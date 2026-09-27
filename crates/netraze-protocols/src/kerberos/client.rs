//! Kerberos Authentication Service exchange (RFC 4120 section 3.1).

use std::time::Duration;

use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6,
    ExplicitContextTag7, ExplicitContextTag8, GeneralizedTimeAsn1, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_krb::constants::error_codes::KDC_ERR_PREAUTH_REQUIRED;
use picky_krb::constants::key_usages::AS_REP_ENC;
use picky_krb::constants::types::{
    AS_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2_TYPE,
    PA_PAC_REQUEST_TYPE,
};
use picky_krb::data_types::{
    EncryptedData, EtypeInfo2, KerbPaPacRequest, KerberosStringAsn1, PaData, PaEncTsEnc,
    PrincipalName, Ticket,
};
use picky_krb::messages::{AsRep, AsReq, EncAsRepPart, KdcReq, KdcReqBody, KrbError};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, RngCore};
use time::OffsetDateTime;

use super::crypto::{KerberosEncryptionType, decrypt, derive_password_key, encrypt};
use super::transport::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_SIZE, DEFAULT_OPERATION_TIMEOUT,
};
use super::{KdcTransport, KdcTransportConfig, KerberosError};

const KERBEROS_VERSION: u8 = 5;
const AS_REP_TAG: u8 = 0x6b;
const KRB_ERROR_TAG: u8 = 0x7e;
const TEN_HOURS: time::Duration = time::Duration::hours(10);
const SEVEN_DAYS: time::Duration = time::Duration::days(7);

/// Configuration for a Kerberos KDC client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosClientConfig {
    pub endpoint: String,
    pub realm: String,
    pub connect_timeout: Duration,
    pub operation_timeout: Duration,
    pub max_response_size: usize,
}

impl KerberosClientConfig {
    #[must_use]
    pub fn new(endpoint: impl Into<String>, realm: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            realm: realm.into().trim().to_ascii_uppercase(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }
}

/// A long-term Kerberos credential. Debug output is deliberately redacted.
#[derive(Clone, PartialEq, Eq)]
pub enum KerberosCredential {
    Password(String),
    NtHash([u8; 16]),
    Aes128Key([u8; 16]),
    Aes256Key([u8; 32]),
}

impl core::fmt::Debug for KerberosCredential {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Password(_) => "KerberosCredential::Password([REDACTED])",
            Self::NtHash(_) => "KerberosCredential::NtHash([REDACTED])",
            Self::Aes128Key(_) => "KerberosCredential::Aes128Key([REDACTED])",
            Self::Aes256Key(_) => "KerberosCredential::Aes256Key([REDACTED])",
        })
    }
}

impl KerberosCredential {
    pub fn from_nt_hash_hex(value: &str) -> Result<Self, KerberosError> {
        Ok(Self::NtHash(parse_hex_key::<16>(value, "NT hash")?))
    }

    pub fn from_aes128_hex(value: &str) -> Result<Self, KerberosError> {
        Ok(Self::Aes128Key(parse_hex_key::<16>(value, "AES-128 key")?))
    }

    pub fn from_aes256_hex(value: &str) -> Result<Self, KerberosError> {
        Ok(Self::Aes256Key(parse_hex_key::<32>(value, "AES-256 key")?))
    }

    fn supported_etypes(&self) -> &'static [KerberosEncryptionType] {
        match self {
            Self::Password(_) => &[
                KerberosEncryptionType::Aes256CtsHmacSha196,
                KerberosEncryptionType::Aes128CtsHmacSha196,
                KerberosEncryptionType::Rc4Hmac,
            ],
            Self::NtHash(_) => &[KerberosEncryptionType::Rc4Hmac],
            Self::Aes128Key(_) => &[KerberosEncryptionType::Aes128CtsHmacSha196],
            Self::Aes256Key(_) => &[KerberosEncryptionType::Aes256CtsHmacSha196],
        }
    }

    fn key_for(
        &self,
        encryption_type: KerberosEncryptionType,
        salt: &[u8],
    ) -> Result<Vec<u8>, KerberosError> {
        match (self, encryption_type) {
            (Self::Password(password), _) => derive_password_key(encryption_type, password, salt),
            (Self::NtHash(key), KerberosEncryptionType::Rc4Hmac)
            | (Self::Aes128Key(key), KerberosEncryptionType::Aes128CtsHmacSha196) => {
                Ok(key.to_vec())
            }
            (Self::Aes256Key(key), KerberosEncryptionType::Aes256CtsHmacSha196) => Ok(key.to_vec()),
            _ => Err(KerberosError::Crypto(format!(
                "credential cannot be used with {encryption_type}"
            ))),
        }
    }
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

/// An acquired TGT and its session key. Secret fields remain private and this
/// type deliberately does not implement serialization.
#[derive(Clone)]
pub struct TicketGrantingTicket {
    pub(crate) ticket: Ticket,
    pub(crate) session_key: Vec<u8>,
    pub(crate) session_encryption_type: KerberosEncryptionType,
    pub(crate) client_principal: String,
    pub(crate) realm: String,
    pub(crate) valid_from_unix: i64,
    pub(crate) valid_until_unix: i64,
    pub(crate) renewable_until_unix: Option<i64>,
}

impl core::fmt::Debug for TicketGrantingTicket {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TicketGrantingTicket")
            .field("client_principal", &self.client_principal)
            .field("realm", &self.realm)
            .field("session_encryption_type", &self.session_encryption_type)
            .field("valid_from_unix", &self.valid_from_unix)
            .field("valid_until_unix", &self.valid_until_unix)
            .field("renewable_until_unix", &self.renewable_until_unix)
            .finish_non_exhaustive()
    }
}

impl TicketGrantingTicket {
    #[must_use]
    pub fn client_principal(&self) -> &str {
        &self.client_principal
    }

    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    #[must_use]
    pub const fn session_encryption_type(&self) -> KerberosEncryptionType {
        self.session_encryption_type
    }

    #[must_use]
    pub const fn valid_from_unix(&self) -> i64 {
        self.valid_from_unix
    }

    #[must_use]
    pub const fn valid_until_unix(&self) -> i64 {
        self.valid_until_unix
    }

    #[must_use]
    pub const fn renewable_until_unix(&self) -> Option<i64> {
        self.renewable_until_unix
    }
}

/// Kerberos client bound to one KDC endpoint and realm.
#[derive(Debug, Clone)]
pub struct KerberosClient {
    pub(crate) config: KerberosClientConfig,
    pub(crate) transport: KdcTransport,
}

impl KerberosClient {
    pub fn connect(config: KerberosClientConfig) -> Result<Self, KerberosError> {
        validate_realm(&config.realm)?;
        let mut transport_config = KdcTransportConfig::new(config.endpoint.clone());
        transport_config.connect_timeout = config.connect_timeout;
        transport_config.operation_timeout = config.operation_timeout;
        transport_config.max_response_size = config.max_response_size;
        let transport = KdcTransport::new(transport_config)?;
        Ok(Self { config, transport })
    }

    #[must_use]
    pub fn config(&self) -> &KerberosClientConfig {
        &self.config
    }

    /// Acquire a TGT with password, NT-hash, or AES-key pre-authentication.
    pub async fn request_tgt(
        &self,
        username: &str,
        credential: &KerberosCredential,
    ) -> Result<TicketGrantingTicket, KerberosError> {
        let mut rng = OsRng;
        self.request_tgt_at(username, credential, OffsetDateTime::now_utc(), &mut rng)
            .await
    }

    async fn request_tgt_at<R: RngCore + CryptoRng>(
        &self,
        username: &str,
        credential: &KerberosCredential,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<TicketGrantingTicket, KerberosError> {
        validate_username(username)?;
        let nonce = rng.r#gen::<u32>() & 0x7fff_ffff;
        let initial = build_as_req(
            &self.config.realm,
            username,
            nonce,
            now,
            credential.supported_etypes(),
            None,
        )?;
        let response = self.transport.exchange(&encode_der(&initial)?).await?;

        let (as_rep, encryption_type, salt) = match decode_kdc_reply(&response)? {
            AsExchangeReply::AsRep(as_rep) => {
                let encryption_type = encrypted_data_type(&as_rep.0.enc_part.0)?;
                let salt = default_salt(&self.config.realm, username);
                (as_rep, encryption_type, salt)
            }
            AsExchangeReply::Error(error) => {
                let code = error.0.error_code.0;
                if code != KDC_ERR_PREAUTH_REQUIRED {
                    return Err(kdc_error(error));
                }
                let (encryption_type, salt) = select_preauth_parameters(
                    &error,
                    credential.supported_etypes(),
                    &self.config.realm,
                    username,
                )?;
                let long_term_key = credential.key_for(encryption_type, salt.as_bytes())?;
                let timestamp =
                    encode_encrypted_timestamp(encryption_type, &long_term_key, now, rng)?;
                let authenticated = build_as_req(
                    &self.config.realm,
                    username,
                    nonce,
                    now,
                    credential.supported_etypes(),
                    Some(timestamp),
                )?;
                let response = self
                    .transport
                    .exchange(&encode_der(&authenticated)?)
                    .await?;
                match decode_kdc_reply(&response)? {
                    AsExchangeReply::AsRep(as_rep) => (as_rep, encryption_type, salt),
                    AsExchangeReply::Error(error) => return Err(kdc_error(error)),
                }
            }
        };

        let long_term_key = credential.key_for(encryption_type, salt.as_bytes())?;
        finish_as_exchange(
            as_rep,
            &long_term_key,
            encryption_type,
            username,
            &self.config.realm,
            nonce,
        )
    }
}

pub(crate) enum AsExchangeReply {
    AsRep(AsRep),
    Error(KrbError),
}

pub(crate) fn decode_kdc_reply(bytes: &[u8]) -> Result<AsExchangeReply, KerberosError> {
    validate_der_envelope(bytes)?;
    match bytes[0] {
        AS_REP_TAG => picky_asn1_der::from_bytes(bytes)
            .map(AsExchangeReply::AsRep)
            .map_err(|error| KerberosError::InvalidMessage(error.to_string())),
        KRB_ERROR_TAG => picky_asn1_der::from_bytes(bytes)
            .map(AsExchangeReply::Error)
            .map_err(|error| KerberosError::InvalidMessage(error.to_string())),
        tag => Err(KerberosError::UnexpectedReply {
            expected: "AS-REP or KRB-ERROR",
            actual: i32::from(tag & 0x1f),
        }),
    }
}

pub(crate) fn validate_der_envelope(bytes: &[u8]) -> Result<(), KerberosError> {
    if bytes.len() < 2 {
        return Err(KerberosError::InvalidMessage(
            "DER reply is truncated".to_owned(),
        ));
    }
    let first = bytes[1];
    let (header_len, content_len) = if first & 0x80 == 0 {
        (2, usize::from(first))
    } else {
        let length_octets = usize::from(first & 0x7f);
        if length_octets == 0
            || length_octets > core::mem::size_of::<usize>()
            || bytes.len() < 2 + length_octets
        {
            return Err(KerberosError::InvalidMessage(
                "invalid DER long-form length".to_owned(),
            ));
        }
        if bytes[2] == 0 {
            return Err(KerberosError::InvalidMessage(
                "non-minimal DER length".to_owned(),
            ));
        }
        let mut value = 0_usize;
        for byte in &bytes[2..2 + length_octets] {
            value = value
                .checked_mul(256)
                .and_then(|current| current.checked_add(usize::from(*byte)))
                .ok_or_else(|| KerberosError::InvalidMessage("DER length overflow".to_owned()))?;
        }
        if value < 128 {
            return Err(KerberosError::InvalidMessage(
                "non-minimal DER long-form length".to_owned(),
            ));
        }
        (2 + length_octets, value)
    };
    if header_len.checked_add(content_len) != Some(bytes.len()) {
        return Err(KerberosError::InvalidMessage(
            "DER reply contains trailing or truncated data".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn build_as_req(
    realm: &str,
    username: &str,
    nonce: u32,
    now: OffsetDateTime,
    encryption_types: &[KerberosEncryptionType],
    encrypted_timestamp: Option<EncryptedData>,
) -> Result<AsReq, KerberosError> {
    let till = now + TEN_HOURS;
    let renew_till = now + SEVEN_DAYS;
    let mut pa_data = Vec::new();
    if let Some(timestamp) = encrypted_timestamp {
        pa_data.push(PaData {
            padata_type: ExplicitContextTag1::from(integer_i32(i32::from(PA_ENC_TIMESTAMP[0]))),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(encode_der(&timestamp)?)),
        });
    }
    pa_data.push(PaData {
        padata_type: ExplicitContextTag1::from(integer_i32(i32::from_be_bytes([
            0,
            0,
            PA_PAC_REQUEST_TYPE[0],
            PA_PAC_REQUEST_TYPE[1],
        ]))),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(encode_der(
            &KerbPaPacRequest {
                include_pac: ExplicitContextTag0::from(true),
            },
        )?)),
    });

    let body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(vec![
            0x40, 0x81, 0x00, 0x10,
        ]))),
        cname: Optional::from(Some(ExplicitContextTag1::from(principal(
            NT_PRINCIPAL,
            &[username],
        )?))),
        realm: ExplicitContextTag2::from(kerberos_string(realm)?),
        sname: Optional::from(Some(ExplicitContextTag3::from(principal(
            NT_SRV_INST,
            &["krbtgt", realm],
        )?))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(till))),
        rtime: Optional::from(Some(ExplicitContextTag6::from(GeneralizedTimeAsn1::from(
            GeneralizedTime::from(renew_till),
        )))),
        nonce: ExplicitContextTag7::from(integer_u32(nonce)),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(
            encryption_types
                .iter()
                .map(|encryption_type| integer_i32(encryption_type.number()))
                .collect::<Vec<_>>(),
        )),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };
    Ok(AsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(integer_i32(i32::from(KERBEROS_VERSION))),
        msg_type: ExplicitContextTag2::from(integer_i32(i32::from(AS_REQ_MSG_TYPE))),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(
            pa_data,
        )))),
        req_body: ExplicitContextTag4::from(body),
    }))
}

fn encode_encrypted_timestamp<R: RngCore + CryptoRng>(
    encryption_type: KerberosEncryptionType,
    key: &[u8],
    now: OffsetDateTime,
    rng: &mut R,
) -> Result<EncryptedData, KerberosError> {
    let timestamp = PaEncTsEnc {
        patimestamp: ExplicitContextTag0::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(
            now,
        ))),
        pausec: Optional::from(Some(ExplicitContextTag1::from(integer_u32(
            now.microsecond().min(999_999),
        )))),
    };
    let encrypted = encrypt(encryption_type, key, 1, &encode_der(&timestamp)?, rng)?;
    Ok(EncryptedData {
        etype: ExplicitContextTag0::from(integer_i32(encryption_type.number())),
        kvno: Optional::from(None),
        cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted)),
    })
}

fn select_preauth_parameters(
    error: &KrbError,
    supported: &[KerberosEncryptionType],
    realm: &str,
    username: &str,
) -> Result<(KerberosEncryptionType, String), KerberosError> {
    let e_data = error.0.e_data.0.as_ref().ok_or_else(|| {
        KerberosError::InvalidMessage("pre-authentication error omitted METHOD-DATA".to_owned())
    })?;
    let method_data: Asn1SequenceOf<PaData> = picky_asn1_der::from_bytes(&e_data.0.0)
        .map_err(|decode| KerberosError::InvalidMessage(decode.to_string()))?;
    let mut offered = Vec::new();
    for pa_data in method_data.0 {
        if integer_as_i32(&pa_data.padata_type.0) == Some(i32::from(PA_ETYPE_INFO2_TYPE[0])) {
            let info: EtypeInfo2 = picky_asn1_der::from_bytes(&pa_data.padata_data.0.0)
                .map_err(|decode| KerberosError::InvalidMessage(decode.to_string()))?;
            for entry in info.0 {
                let Some(number) = integer_as_i32(&entry.etype.0) else {
                    continue;
                };
                let Ok(encryption_type) = KerberosEncryptionType::from_number(number) else {
                    continue;
                };
                let salt = entry.salt.0.as_ref().map_or_else(
                    || default_salt(realm, username),
                    |value| value.0.to_string(),
                );
                offered.push((encryption_type, salt));
            }
        }
    }
    for wanted in supported {
        if let Some((encryption_type, salt)) = offered.iter().find(|(offered, _)| offered == wanted)
        {
            return Ok((*encryption_type, salt.clone()));
        }
    }
    Err(KerberosError::Crypto(
        "KDC offered no encryption type compatible with the supplied credential".to_owned(),
    ))
}

fn finish_as_exchange(
    as_rep: AsRep,
    long_term_key: &[u8],
    encryption_type: KerberosEncryptionType,
    username: &str,
    realm: &str,
    nonce: u32,
) -> Result<TicketGrantingTicket, KerberosError> {
    if integer_as_i32(&as_rep.0.msg_type.0) != Some(11) {
        return Err(KerberosError::UnexpectedReply {
            expected: "AS-REP",
            actual: integer_as_i32(&as_rep.0.msg_type.0).unwrap_or(-1),
        });
    }
    let reply_realm = as_rep.0.crealm.0.to_string();
    if !reply_realm.eq_ignore_ascii_case(realm) {
        return Err(KerberosError::InvalidMessage(format!(
            "AS-REP realm {reply_realm} does not match requested realm {realm}"
        )));
    }
    let reply_principal = principal_name(&as_rep.0.cname.0);
    if !reply_principal.eq_ignore_ascii_case(username) {
        return Err(KerberosError::InvalidMessage(format!(
            "AS-REP principal {reply_principal} does not match requested principal {username}"
        )));
    }
    let reply_encryption_type = encrypted_data_type(&as_rep.0.enc_part.0)?;
    if reply_encryption_type != encryption_type {
        return Err(KerberosError::InvalidMessage(format!(
            "AS-REP uses {reply_encryption_type}, expected {encryption_type}"
        )));
    }
    let plaintext = decrypt(
        encryption_type,
        long_term_key,
        AS_REP_ENC,
        &as_rep.0.enc_part.0.cipher.0.0,
    )?;
    let encrypted_part: EncAsRepPart = picky_asn1_der::from_bytes(&plaintext)
        .map_err(|error| KerberosError::InvalidMessage(error.to_string()))?;
    if integer_as_u32(&encrypted_part.0.nonce.0) != Some(nonce) {
        return Err(KerberosError::InvalidMessage(
            "AS-REP nonce does not match request".to_owned(),
        ));
    }
    let service_realm = encrypted_part.0.srealm.0.to_string();
    if !service_realm.eq_ignore_ascii_case(realm)
        || principal_name(&encrypted_part.0.sname.0) != format!("krbtgt/{realm}")
    {
        return Err(KerberosError::InvalidMessage(
            "AS-REP does not contain the requested krbtgt service".to_owned(),
        ));
    }
    let session_encryption_type = KerberosEncryptionType::from_number(
        integer_as_i32(&encrypted_part.0.key.0.key_type.0).ok_or_else(|| {
            KerberosError::InvalidMessage("invalid session-key enctype".to_owned())
        })?,
    )?;
    let session_key = encrypted_part.0.key.0.key_value.0.0.clone();
    if session_key.len() != session_encryption_type.key_len() {
        return Err(KerberosError::InvalidKeyLength {
            encryption_type: session_encryption_type.name(),
            expected: session_encryption_type.key_len(),
            actual: session_key.len(),
        });
    }
    let valid_from = encrypted_part.0.start_time.0.as_ref().map_or_else(
        || encrypted_part.0.auth_time.0.clone(),
        |value| value.0.clone(),
    );
    let valid_from_unix = date_to_unix(valid_from)?;
    let valid_until_unix = date_to_unix(encrypted_part.0.end_time.0.clone())?;
    if valid_until_unix <= valid_from_unix {
        return Err(KerberosError::InvalidMessage(
            "AS-REP ticket lifetime is invalid".to_owned(),
        ));
    }
    let renewable_until_unix = encrypted_part
        .0
        .renew_till
        .0
        .as_ref()
        .map(|value| date_to_unix(value.0.clone()))
        .transpose()?;
    Ok(TicketGrantingTicket {
        ticket: as_rep.0.ticket.0,
        session_key,
        session_encryption_type,
        client_principal: reply_principal,
        realm: reply_realm,
        valid_from_unix,
        valid_until_unix,
        renewable_until_unix,
    })
}

pub(crate) fn encrypted_data_type(
    data: &EncryptedData,
) -> Result<KerberosEncryptionType, KerberosError> {
    let number = integer_as_i32(&data.etype.0).ok_or_else(|| {
        KerberosError::InvalidMessage("invalid encrypted-data enctype".to_owned())
    })?;
    KerberosEncryptionType::from_number(number)
}

fn date_to_unix(value: GeneralizedTimeAsn1) -> Result<i64, KerberosError> {
    OffsetDateTime::try_from(value.0)
        .map(|value| value.unix_timestamp())
        .map_err(|error| KerberosError::InvalidMessage(error.to_string()))
}

pub(crate) fn kdc_error(error: KrbError) -> KerberosError {
    let message = error
        .0
        .e_text
        .0
        .as_ref()
        .map_or_else(String::new, |text| format!(": {}", text.0.0));
    let data = error.0.e_data.0.map(|value| value.0.0);
    KerberosError::Kdc {
        code: error.0.error_code.0 as i32,
        message,
        data,
    }
}

pub(crate) fn principal(
    name_type: u8,
    components: &[&str],
) -> Result<PrincipalName, KerberosError> {
    let components = components
        .iter()
        .map(|component| kerberos_string(component))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PrincipalName {
        name_type: ExplicitContextTag0::from(integer_i32(i32::from(name_type))),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(components)),
    })
}

pub(crate) fn principal_name(value: &PrincipalName) -> String {
    value
        .name_string
        .0
        .0
        .iter()
        .map(|component| component.0.to_string())
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn kerberos_string(value: &str) -> Result<KerberosStringAsn1, KerberosError> {
    IA5String::from_string(value.to_owned())
        .map(KerberosStringAsn1::from)
        .map_err(|error| KerberosError::InvalidMessage(error.to_string()))
}

fn default_salt(realm: &str, username: &str) -> String {
    format!("{realm}{username}")
}

pub(crate) fn integer_i32(value: i32) -> IntegerAsn1 {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != if value < 0 { 0xff } else { 0 })
        .unwrap_or(bytes.len() - 1);
    let mut output = bytes[first..].to_vec();
    if value >= 0 && output[0] & 0x80 != 0 {
        output.insert(0, 0);
    } else if value < 0 && output[0] & 0x80 == 0 {
        output.insert(0, 0xff);
    }
    IntegerAsn1::from(output)
}

pub(crate) fn integer_u32(value: u32) -> IntegerAsn1 {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut output = bytes[first..].to_vec();
    if output[0] & 0x80 != 0 {
        output.insert(0, 0);
    }
    IntegerAsn1::from(output)
}

pub(crate) fn integer_as_i32(value: &IntegerAsn1) -> Option<i32> {
    if value.0.is_empty() || value.0.len() > 4 {
        return None;
    }
    let fill = if value.0[0] & 0x80 != 0 { 0xff } else { 0 };
    let mut bytes = [fill; 4];
    bytes[4 - value.0.len()..].copy_from_slice(&value.0);
    Some(i32::from_be_bytes(bytes))
}

pub(crate) fn integer_as_u32(value: &IntegerAsn1) -> Option<u32> {
    if value.0.is_empty() || value.0.len() > 5 || value.0[0] & 0x80 != 0 {
        return None;
    }
    let value = if value.0.len() == 5 {
        if value.0[0] != 0 {
            return None;
        }
        &value.0[1..]
    } else {
        &value.0
    };
    let mut bytes = [0_u8; 4];
    bytes[4 - value.len()..].copy_from_slice(value);
    Some(u32::from_be_bytes(bytes))
}

pub(crate) fn encode_der<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, KerberosError> {
    picky_asn1_der::to_vec(value).map_err(|error| KerberosError::InvalidMessage(error.to_string()))
}

fn validate_realm(realm: &str) -> Result<(), KerberosError> {
    if realm.is_empty()
        || realm.len() > 255
        || !realm.is_ascii()
        || realm.contains(['/', '\\', '@'])
    {
        return Err(KerberosError::InvalidMessage(
            "Kerberos realm is invalid".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_username(username: &str) -> Result<(), KerberosError> {
    if username.is_empty()
        || username.len() > 256
        || !username.is_ascii()
        || username.contains(['/', '\\'])
    {
        return Err(KerberosError::InvalidMessage(
            "Kerberos username is invalid".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky_asn1::wrapper::{ExplicitContextTag9, ExplicitContextTag10, ExplicitContextTag12};
    use picky_krb::data_types::{
        EncryptionKey, EtypeInfo2Entry, KerberosFlags, LastReq, TicketInner,
    };
    use picky_krb::messages::{EncKdcRepPart, KdcRep, KrbErrorInner};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn credential_debug_never_displays_secret() {
        let credential = KerberosCredential::Password("do-not-print".to_owned());
        let debug = format!("{credential:?}");
        assert!(!debug.contains("do-not-print"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn parses_key_material_strictly() {
        assert!(KerberosCredential::from_nt_hash_hex("00".repeat(16).as_str()).is_ok());
        assert!(KerberosCredential::from_nt_hash_hex("00").is_err());
        assert!(KerberosCredential::from_aes256_hex("gg".repeat(32).as_str()).is_err());
    }

    #[test]
    fn as_req_contains_expected_principal_realm_nonce_and_etypes() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let request = build_as_req(
            "EXAMPLE.TEST",
            "alice",
            0x1020_3040,
            now,
            &[
                KerberosEncryptionType::Aes256CtsHmacSha196,
                KerberosEncryptionType::Aes128CtsHmacSha196,
                KerberosEncryptionType::Rc4Hmac,
            ],
            None,
        )
        .unwrap();
        let encoded = encode_der(&request).unwrap();
        let decoded: AsReq = picky_asn1_der::from_bytes(&encoded).unwrap();
        assert_eq!(
            principal_name(&decoded.0.req_body.0.cname.0.as_ref().unwrap().0),
            "alice"
        );
        assert_eq!(decoded.0.req_body.0.realm.0.to_string(), "EXAMPLE.TEST");
        assert_eq!(
            integer_as_u32(&decoded.0.req_body.0.nonce.0),
            Some(0x1020_3040)
        );
        let etypes = decoded
            .0
            .req_body
            .0
            .etype
            .0
            .0
            .iter()
            .filter_map(integer_as_i32)
            .collect::<Vec<_>>();
        assert_eq!(etypes, [18, 17, 23]);
    }

    #[test]
    fn der_envelope_rejects_trailing_indefinite_and_non_minimal_lengths() {
        assert!(validate_der_envelope(&[0x6b, 0x00]).is_ok());
        assert!(validate_der_envelope(&[0x6b, 0x00, 0x00]).is_err());
        assert!(validate_der_envelope(&[0x6b, 0x80, 0x00, 0x00]).is_err());
        assert!(validate_der_envelope(&[0x6b, 0x81, 0x01, 0x00]).is_err());
    }

    #[test]
    fn rejects_invalid_names_before_network_use() {
        assert!(KerberosClient::connect(KerberosClientConfig::new("dc", "BAD/REALM")).is_err());
        assert!(validate_username("DOMAIN\\alice").is_err());
    }

    #[tokio::test]
    async fn password_as_exchange_negotiates_preauth_and_returns_opaque_tgt() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let server = tokio::spawn(async move {
            let (mut first_stream, first) = read_request(&listener).await;
            let initial: AsReq = picky_asn1_der::from_bytes(&first).unwrap();
            let nonce = integer_as_u32(&initial.0.req_body.0.nonce.0).unwrap();
            let error = preauth_required("EXAMPLE.TEST", "alice", now);
            write_response(&mut first_stream, &error).await;

            let (mut second_stream, second) = read_request(&listener).await;
            let authenticated: AsReq = picky_asn1_der::from_bytes(&second).unwrap();
            assert_eq!(authenticated.0.padata.0.as_ref().unwrap().0.0.len(), 2);
            let reply = successful_as_rep("EXAMPLE.TEST", "alice", nonce, now);
            write_response(&mut second_stream, &reply).await;
        });

        let client =
            KerberosClient::connect(KerberosClientConfig::new(endpoint, "example.test")).unwrap();
        let mut rng = OsRng;
        let tgt = client
            .request_tgt_at(
                "alice",
                &KerberosCredential::Password("test-only-password".to_owned()),
                now,
                &mut rng,
            )
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(tgt.client_principal(), "alice");
        assert_eq!(tgt.realm(), "EXAMPLE.TEST");
        assert_eq!(
            tgt.session_encryption_type(),
            KerberosEncryptionType::Aes256CtsHmacSha196
        );
        assert_eq!(tgt.valid_from_unix(), now.unix_timestamp());
        assert_eq!(tgt.valid_until_unix(), (now + TEN_HOURS).unix_timestamp());
    }

    async fn read_request(listener: &TcpListener) -> (tokio::net::TcpStream, Vec<u8>) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        let mut request = vec![0; u32::from_be_bytes(header) as usize];
        stream.read_exact(&mut request).await.unwrap();
        (stream, request)
    }

    async fn write_response<T: serde::Serialize>(stream: &mut tokio::net::TcpStream, response: &T) {
        let encoded = encode_der(response).unwrap();
        stream
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&encoded).await.unwrap();
    }

    fn preauth_required(realm: &str, username: &str, now: OffsetDateTime) -> KrbError {
        let salt = format!("{realm}{username}");
        let info = EtypeInfo2::from(vec![EtypeInfo2Entry {
            etype: ExplicitContextTag0::from(integer_i32(18)),
            salt: Optional::from(Some(ExplicitContextTag1::from(
                kerberos_string(&salt).unwrap(),
            ))),
            s2kparams: Optional::from(None),
        }]);
        let methods = Asn1SequenceOf::from(vec![PaData {
            padata_type: ExplicitContextTag1::from(integer_i32(19)),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
                encode_der(&info).unwrap(),
            )),
        }]);
        KrbError::from(KrbErrorInner {
            pvno: ExplicitContextTag0::from(integer_i32(5)),
            msg_type: ExplicitContextTag1::from(integer_i32(30)),
            ctime: Optional::from(None),
            cusec: Optional::from(None),
            stime: ExplicitContextTag4::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(now))),
            susec: ExplicitContextTag5::from(integer_u32(0)),
            error_code: ExplicitContextTag6::from(KDC_ERR_PREAUTH_REQUIRED),
            crealm: Optional::from(None),
            cname: Optional::from(None),
            realm: ExplicitContextTag9::from(kerberos_string(realm).unwrap()),
            sname: ExplicitContextTag10::from(principal(NT_SRV_INST, &["krbtgt", realm]).unwrap()),
            e_text: Optional::from(None),
            e_data: Optional::from(Some(ExplicitContextTag12::from(OctetStringAsn1::from(
                encode_der(&methods).unwrap(),
            )))),
        })
    }

    fn successful_as_rep(realm: &str, username: &str, nonce: u32, now: OffsetDateTime) -> AsRep {
        let session_key = vec![0x42; 32];
        let encrypted_part = EncAsRepPart::from(EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(integer_i32(18)),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(session_key)),
            }),
            last_req: ExplicitContextTag1::from(LastReq::from(Vec::new())),
            nonce: ExplicitContextTag2::from(integer_u32(nonce)),
            key_expiration: Optional::from(None),
            flags: ExplicitContextTag4::from(KerberosFlags::from(BitString::with_bytes(vec![
                0;
                4
            ]))),
            auth_time: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(
                now,
            ))),
            start_time: Optional::from(Some(ExplicitContextTag6::from(GeneralizedTimeAsn1::from(
                GeneralizedTime::from(now),
            )))),
            end_time: ExplicitContextTag7::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(
                now + TEN_HOURS,
            ))),
            renew_till: Optional::from(Some(ExplicitContextTag8::from(GeneralizedTimeAsn1::from(
                GeneralizedTime::from(now + SEVEN_DAYS),
            )))),
            srealm: ExplicitContextTag9::from(kerberos_string(realm).unwrap()),
            sname: ExplicitContextTag10::from(principal(NT_SRV_INST, &["krbtgt", realm]).unwrap()),
            caadr: Optional::from(None),
            encrypted_pa_data: Optional::from(None),
        });
        let long_term_key = derive_password_key(
            KerberosEncryptionType::Aes256CtsHmacSha196,
            "test-only-password",
            format!("{realm}{username}").as_bytes(),
        )
        .unwrap();
        let encrypted = encrypt(
            KerberosEncryptionType::Aes256CtsHmacSha196,
            &long_term_key,
            AS_REP_ENC,
            &encode_der(&encrypted_part).unwrap(),
            &mut OsRng,
        )
        .unwrap();
        AsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(integer_i32(5)),
            msg_type: ExplicitContextTag1::from(integer_i32(11)),
            padata: Optional::from(None),
            crealm: ExplicitContextTag3::from(kerberos_string(realm).unwrap()),
            cname: ExplicitContextTag4::from(principal(NT_PRINCIPAL, &[username]).unwrap()),
            ticket: ExplicitContextTag5::from(Ticket::from(TicketInner {
                tkt_vno: ExplicitContextTag0::from(integer_i32(5)),
                realm: ExplicitContextTag1::from(kerberos_string(realm).unwrap()),
                sname: ExplicitContextTag2::from(
                    principal(NT_SRV_INST, &["krbtgt", realm]).unwrap(),
                ),
                enc_part: ExplicitContextTag3::from(EncryptedData {
                    etype: ExplicitContextTag0::from(integer_i32(18)),
                    kvno: Optional::from(None),
                    cipher: ExplicitContextTag2::from(OctetStringAsn1::from(vec![1, 2, 3])),
                }),
            })),
            enc_part: ExplicitContextTag6::from(EncryptedData {
                etype: ExplicitContextTag0::from(integer_i32(18)),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted)),
            }),
        })
    }
}
