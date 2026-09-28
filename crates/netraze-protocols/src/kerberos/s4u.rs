//! Service-for-User exchanges from MS-SFU.
//!
//! These APIs exercise delegation already authorized by the KDC. They never
//! modify directory objects or delegation ACLs: S4U2Self produces a bounded
//! evidence ticket, and S4U2Proxy submits that exact ticket to the KDC for an
//! explicitly named target service.

use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag7,
    ExplicitContextTag8, ExplicitContextTag11, GeneralizedTimeAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::key_usages::{
    TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR_CKSUM,
};
use picky_krb::constants::types::{
    AP_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST, PA_TGS_REQ_TYPE, TGS_REQ_MSG_TYPE,
};
use picky_krb::data_types::{
    ApOptions, Authenticator, AuthenticatorInner, Checksum, EncryptedData, KerberosFlags,
    KerberosStringAsn1, PaData, PaPacOptions, PrincipalName, Ticket,
};
use picky_krb::messages::{ApReq, ApReqInner, KdcReq, KdcReqBody, TgsReq};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::assessment::{
    ServiceTicket, decode_tgs_reply, finish_service_tgs_exchange, validate_spn,
};
use super::client::{
    encode_der, integer_i32, integer_u32, kerberos_string, principal, validate_realm,
    validate_username,
};
use super::crypto::keyed_checksum;
use super::{KerberosClient, KerberosError, TicketGrantingTicket, encrypt};

const KERBEROS_VERSION: i32 = 5;
const PA_FOR_USER_TYPE: i32 = 129;
const PA_PAC_OPTIONS_TYPE: i32 = 167;
const PA_FOR_USER_KEY_USAGE: i32 = 17;
const FORWARDABLE_TICKET_FLAG: u32 = 0x4000_0000;
const TEN_HOURS: time::Duration = time::Duration::hours(10);

/// Delegation policy requested from the KDC during S4U2Proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S4uDelegationMode {
    /// Classic constrained delegation. The evidence ticket must carry the
    /// forwardable flag or the exchange is rejected locally.
    Constrained,
    /// Resource-based constrained delegation. PA-PAC-OPTIONS advertises the
    /// RBCD path; the target KDC remains the authorization authority.
    ResourceBased,
}

/// S4U2Self output accepted by [`KerberosClient::request_s4u2proxy`].
///
/// The embedded ticket and its session key remain opaque and are omitted from
/// debug output. Safe identity and lifetime metadata are exposed explicitly.
#[derive(Clone)]
pub struct S4uEvidenceTicket {
    ticket: ServiceTicket,
    requesting_service: String,
    impersonated_principal: String,
    impersonated_realm: String,
}

impl core::fmt::Debug for S4uEvidenceTicket {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("S4uEvidenceTicket")
            .field("requesting_service", &self.requesting_service)
            .field("impersonated_principal", &self.impersonated_principal)
            .field("impersonated_realm", &self.impersonated_realm)
            .field("forwardable", &self.is_forwardable())
            .field("valid_until_unix", &self.ticket.valid_until_unix())
            .finish_non_exhaustive()
    }
}

impl S4uEvidenceTicket {
    #[must_use]
    pub fn requesting_service(&self) -> &str {
        &self.requesting_service
    }

    #[must_use]
    pub fn impersonated_principal(&self) -> &str {
        &self.impersonated_principal
    }

    #[must_use]
    pub fn impersonated_realm(&self) -> &str {
        &self.impersonated_realm
    }

    #[must_use]
    pub const fn is_forwardable(&self) -> bool {
        self.ticket.ticket_flags() & FORWARDABLE_TICKET_FLAG != 0
    }

    #[must_use]
    pub const fn service_ticket(&self) -> &ServiceTicket {
        &self.ticket
    }

    #[must_use]
    pub fn into_service_ticket(self) -> ServiceTicket {
        self.ticket
    }
}

#[derive(Serialize, Deserialize)]
struct PaForUser {
    user_name: ExplicitContextTag0<PrincipalName>,
    user_realm: ExplicitContextTag1<KerberosStringAsn1>,
    cksum: ExplicitContextTag2<Checksum>,
    auth_package: ExplicitContextTag3<KerberosStringAsn1>,
}

impl KerberosClient {
    /// Request a ticket to the caller's own service identity on behalf of
    /// another principal. The own-service name must exactly match the TGT
    /// client principal; no alternate account is inferred.
    pub async fn request_s4u2self(
        &self,
        tgt: &TicketGrantingTicket,
        own_service_principal: &str,
        impersonated_principal: &str,
    ) -> Result<S4uEvidenceTicket, KerberosError> {
        validate_s4u_tgt(self, tgt)?;
        validate_username(own_service_principal)?;
        validate_username(impersonated_principal)?;
        if !own_service_principal.eq_ignore_ascii_case(tgt.client_principal()) {
            return Err(KerberosError::InvalidMessage(
                "S4U2Self service identity does not match the TGT client".to_owned(),
            ));
        }
        let now = OffsetDateTime::now_utc();
        validate_ticket_lifetime(tgt.valid_from_unix(), tgt.valid_until_unix(), now)?;
        let nonce = OsRng.r#gen::<u32>() & 0x7fff_ffff;
        let for_user = pa_for_user(tgt, impersonated_principal, tgt.realm())?;
        let request = build_s4u_tgs_req(
            tgt,
            principal(NT_PRINCIPAL, &[own_service_principal])?,
            tgt.kdc_realm(),
            nonce,
            now,
            [0x40, 0x01, 0, 0],
            vec![for_user, pa_pac_options_rbcd()?],
            Vec::new(),
            &mut OsRng,
        )?;
        let response = self.transport.exchange(&encode_der(&request)?).await?;
        let reply = decode_tgs_reply(&response)?;
        let ticket = finish_service_tgs_exchange(
            reply,
            tgt,
            own_service_principal,
            tgt.kdc_realm(),
            impersonated_principal,
            tgt.realm(),
            nonce,
        )?;
        Ok(S4uEvidenceTicket {
            ticket,
            requesting_service: own_service_principal.to_owned(),
            impersonated_principal: impersonated_principal.to_owned(),
            impersonated_realm: tgt.realm().to_owned(),
        })
    }

    /// Exchange a validated S4U2Self evidence ticket for one explicitly named
    /// service ticket. KDC authorization failures are returned unchanged and
    /// are never worked around by modifying directory state.
    pub async fn request_s4u2proxy(
        &self,
        tgt: &TicketGrantingTicket,
        evidence: &S4uEvidenceTicket,
        target_service_principal: &str,
        mode: S4uDelegationMode,
    ) -> Result<ServiceTicket, KerberosError> {
        validate_s4u_tgt(self, tgt)?;
        validate_spn(target_service_principal)?;
        let now = OffsetDateTime::now_utc();
        validate_ticket_lifetime(tgt.valid_from_unix(), tgt.valid_until_unix(), now)?;
        validate_ticket_lifetime(
            evidence.ticket.valid_from_unix(),
            evidence.ticket.valid_until_unix(),
            now,
        )?;
        if !evidence
            .requesting_service
            .eq_ignore_ascii_case(tgt.client_principal())
            || !evidence
                .ticket
                .service_principal_name()
                .eq_ignore_ascii_case(tgt.client_principal())
            || !evidence
                .impersonated_realm
                .eq_ignore_ascii_case(tgt.realm())
        {
            return Err(KerberosError::InvalidMessage(
                "S4U evidence ticket does not belong to the supplied TGT".to_owned(),
            ));
        }
        validate_delegation_mode(evidence, mode)?;

        let nonce = OsRng.r#gen::<u32>() & 0x7fff_ffff;
        let mut extra_padata = Vec::new();
        if mode == S4uDelegationMode::ResourceBased {
            extra_padata.push(pa_pac_options_rbcd()?);
        }
        let service_components = target_service_principal.split('/').collect::<Vec<_>>();
        let request = build_s4u_tgs_req(
            tgt,
            principal(NT_SRV_INST, &service_components)?,
            tgt.kdc_realm(),
            nonce,
            now,
            [0x40, 0x03, 0, 0],
            extra_padata,
            vec![evidence.ticket.ticket.clone()],
            &mut OsRng,
        )?;
        let response = self.transport.exchange(&encode_der(&request)?).await?;
        let reply = decode_tgs_reply(&response)?;
        let ticket = finish_service_tgs_exchange(
            reply,
            tgt,
            target_service_principal,
            tgt.kdc_realm(),
            &evidence.impersonated_principal,
            &evidence.impersonated_realm,
            nonce,
        )?;
        Ok(ticket)
    }

    /// Perform the complete, read-only S4U2Self → S4U2Proxy exchange.
    pub async fn request_delegated_service_ticket(
        &self,
        tgt: &TicketGrantingTicket,
        own_service_principal: &str,
        impersonated_principal: &str,
        target_service_principal: &str,
        mode: S4uDelegationMode,
    ) -> Result<ServiceTicket, KerberosError> {
        let evidence = self
            .request_s4u2self(tgt, own_service_principal, impersonated_principal)
            .await?;
        self.request_s4u2proxy(tgt, &evidence, target_service_principal, mode)
            .await
    }
}

#[allow(clippy::too_many_arguments)]
fn build_s4u_tgs_req<R: RngCore + CryptoRng>(
    tgt: &TicketGrantingTicket,
    service_name: PrincipalName,
    request_realm: &str,
    nonce: u32,
    now: OffsetDateTime,
    options: [u8; 4],
    mut extra_padata: Vec<PaData>,
    additional_tickets: Vec<Ticket>,
    rng: &mut R,
) -> Result<TgsReq, KerberosError> {
    validate_realm(request_realm)?;
    let request_body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
            options.to_vec(),
        ))),
        cname: Optional::from(None),
        realm: ExplicitContextTag2::from(kerberos_string(request_realm)?),
        sname: Optional::from(Some(ExplicitContextTag3::from(service_name))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(
            now + TEN_HOURS,
        ))),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(integer_u32(nonce)),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
            integer_i32(18),
            integer_i32(17),
            integer_i32(23),
        ])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: if additional_tickets.is_empty() {
            Optional::from(None)
        } else {
            Optional::from(Some(ExplicitContextTag11::from(Asn1SequenceOf::from(
                additional_tickets,
            ))))
        },
    };
    let mut padata = Vec::with_capacity(1 + extra_padata.len());
    padata.push(tgs_authentication_padata(tgt, &request_body, now, rng)?);
    padata.append(&mut extra_padata);
    Ok(TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(integer_i32(KERBEROS_VERSION)),
        msg_type: ExplicitContextTag2::from(integer_i32(i32::from(TGS_REQ_MSG_TYPE))),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(
            padata,
        )))),
        req_body: ExplicitContextTag4::from(request_body),
    }))
}

fn tgs_authentication_padata<R: RngCore + CryptoRng>(
    tgt: &TicketGrantingTicket,
    request_body: &KdcReqBody,
    now: OffsetDateTime,
    rng: &mut R,
) -> Result<PaData, KerberosError> {
    let (checksum_type, checksum) = keyed_checksum(
        tgt.session_encryption_type,
        &tgt.session_key,
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR_CKSUM,
        &encode_der(request_body)?,
    )?;
    let client_components = tgt.client_principal().split('/').collect::<Vec<_>>();
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(integer_i32(KERBEROS_VERSION)),
        crealm: ExplicitContextTag1::from(kerberos_string(tgt.realm())?),
        cname: ExplicitContextTag2::from(principal(NT_PRINCIPAL, &client_components)?),
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
        pvno: ExplicitContextTag0::from(integer_i32(KERBEROS_VERSION)),
        msg_type: ExplicitContextTag1::from(integer_i32(i32::from(AP_REQ_MSG_TYPE))),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(vec![0; 4]))),
        ticket: ExplicitContextTag3::from(tgt.ticket.clone()),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(integer_i32(tgt.session_encryption_type.number())),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    });
    Ok(PaData {
        padata_type: ExplicitContextTag1::from(integer_i32(i32::from(PA_TGS_REQ_TYPE[0]))),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(encode_der(&ap_req)?)),
    })
}

fn pa_for_user(
    tgt: &TicketGrantingTicket,
    impersonated_principal: &str,
    realm: &str,
) -> Result<PaData, KerberosError> {
    validate_username(impersonated_principal)?;
    validate_realm(realm)?;
    let mut checksum_input =
        Vec::with_capacity(4 + impersonated_principal.len() + realm.len() + "Kerberos".len());
    checksum_input.extend_from_slice(&i32::from(NT_PRINCIPAL).to_le_bytes());
    checksum_input.extend_from_slice(impersonated_principal.as_bytes());
    checksum_input.extend_from_slice(realm.as_bytes());
    checksum_input.extend_from_slice(b"Kerberos");
    let (checksum_type, checksum) = keyed_checksum(
        tgt.session_encryption_type,
        &tgt.session_key,
        PA_FOR_USER_KEY_USAGE,
        &checksum_input,
    )?;
    let value = PaForUser {
        user_name: ExplicitContextTag0::from(principal(NT_PRINCIPAL, &[impersonated_principal])?),
        user_realm: ExplicitContextTag1::from(kerberos_string(realm)?),
        cksum: ExplicitContextTag2::from(Checksum {
            cksumtype: ExplicitContextTag0::from(integer_i32(checksum_type)),
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum)),
        }),
        auth_package: ExplicitContextTag3::from(kerberos_string("Kerberos")?),
    };
    Ok(PaData {
        padata_type: ExplicitContextTag1::from(integer_i32(PA_FOR_USER_TYPE)),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(encode_der(&value)?)),
    })
}

fn pa_pac_options_rbcd() -> Result<PaData, KerberosError> {
    let value = PaPacOptions {
        flags: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(vec![
            0x10, 0, 0, 0,
        ]))),
    };
    Ok(PaData {
        padata_type: ExplicitContextTag1::from(integer_i32(PA_PAC_OPTIONS_TYPE)),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(encode_der(&value)?)),
    })
}

fn validate_s4u_tgt(
    client: &KerberosClient,
    tgt: &TicketGrantingTicket,
) -> Result<(), KerberosError> {
    if !tgt.kdc_realm().eq_ignore_ascii_case(&client.config.realm) {
        return Err(KerberosError::InvalidMessage(format!(
            "TGT is for KDC realm {}, but the client is connected to {}",
            tgt.kdc_realm(),
            client.config.realm
        )));
    }
    Ok(())
}

fn validate_ticket_lifetime(
    valid_from_unix: i64,
    valid_until_unix: i64,
    now: OffsetDateTime,
) -> Result<(), KerberosError> {
    let now = now.unix_timestamp();
    if now < valid_from_unix || now >= valid_until_unix {
        return Err(KerberosError::InvalidMessage(
            "S4U exchange requires a currently valid ticket".to_owned(),
        ));
    }
    Ok(())
}

fn validate_delegation_mode(
    evidence: &S4uEvidenceTicket,
    mode: S4uDelegationMode,
) -> Result<(), KerberosError> {
    if mode == S4uDelegationMode::Constrained && !evidence.is_forwardable() {
        return Err(KerberosError::InvalidMessage(
            "classic constrained delegation requires a forwardable S4U2Self ticket".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky_krb::data_types::TicketInner;

    fn test_tgt(
        encryption_type: super::super::KerberosEncryptionType,
        key: Vec<u8>,
    ) -> TicketGrantingTicket {
        let now = 1_700_000_000;
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
                    cipher: ExplicitContextTag2::from(OctetStringAsn1::from(vec![0x77; 32])),
                }),
            }),
            session_key: key,
            session_encryption_type: encryption_type,
            client_principal: "service$".to_owned(),
            realm: "EXAMPLE.TEST".to_owned(),
            kdc_realm: "EXAMPLE.TEST".to_owned(),
            issued_at_unix: now,
            valid_from_unix: now,
            valid_until_unix: now + 36_000,
            renewable_until_unix: None,
            ticket_flags: FORWARDABLE_TICKET_FLAG,
        }
    }

    fn checksum_bytes(padata: &PaData) -> Vec<u8> {
        let value: PaForUser = picky_asn1_der::from_bytes(&padata.padata_data.0.0).unwrap();
        value.cksum.0.checksum.0.0
    }

    #[test]
    fn pa_for_user_checksums_match_impacket_vectors() {
        let aes256 = test_tgt(
            super::super::KerberosEncryptionType::Aes256CtsHmacSha196,
            (0_u8..32).collect(),
        );
        assert_eq!(
            checksum_bytes(&pa_for_user(&aes256, "Administrator", "EXAMPLE.TEST").unwrap()),
            hex("171af2ef19acc5245542d322")
        );
        let aes128 = test_tgt(
            super::super::KerberosEncryptionType::Aes128CtsHmacSha196,
            (0_u8..16).collect(),
        );
        assert_eq!(
            checksum_bytes(&pa_for_user(&aes128, "Administrator", "EXAMPLE.TEST").unwrap()),
            hex("7da07ac2e9f8338cad92f344")
        );
        let rc4 = test_tgt(
            super::super::KerberosEncryptionType::Rc4Hmac,
            (0_u8..16).collect(),
        );
        assert_eq!(
            checksum_bytes(&pa_for_user(&rc4, "Administrator", "EXAMPLE.TEST").unwrap()),
            hex("934b7821aa533668a2e5f16b997ab409")
        );
    }

    #[test]
    fn s4u_request_encodes_required_options_and_additional_ticket() {
        let tgt = test_tgt(
            super::super::KerberosEncryptionType::Aes128CtsHmacSha196,
            vec![0x22; 16],
        );
        let evidence = tgt.ticket.clone();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap();
        let request = build_s4u_tgs_req(
            &tgt,
            principal(NT_SRV_INST, &["cifs", "dc.example.test"]).unwrap(),
            "EXAMPLE.TEST",
            7,
            now,
            [0x40, 0x03, 0, 0],
            vec![pa_pac_options_rbcd().unwrap()],
            vec![evidence.clone()],
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(
            request.0.req_body.0.kdc_options.0.0.as_bytes(),
            &[0, 0x40, 0x03, 0, 0]
        );
        assert_eq!(
            request
                .0
                .req_body
                .0
                .additional_tickets
                .0
                .as_ref()
                .unwrap()
                .0
                .0,
            vec![evidence]
        );
        assert_eq!(request.0.padata.0.as_ref().unwrap().0.0.len(), 2);
    }

    #[test]
    fn classic_delegation_rejects_non_forwardable_evidence() {
        let service_ticket = ServiceTicket {
            ticket: test_tgt(
                super::super::KerberosEncryptionType::Aes128CtsHmacSha196,
                vec![0x22; 16],
            )
            .ticket,
            session_key: vec![0x44; 16],
            session_encryption_type: super::super::KerberosEncryptionType::Aes128CtsHmacSha196,
            client_principal: "Administrator".to_owned(),
            client_realm: "EXAMPLE.TEST".to_owned(),
            service_principal_name: "service$".to_owned(),
            realm: "EXAMPLE.TEST".to_owned(),
            issued_at_unix: 1_700_000_000,
            valid_from_unix: 1_700_000_000,
            valid_until_unix: 1_700_036_000,
            renewable_until_unix: None,
            ticket_flags: 0,
        };
        let evidence = S4uEvidenceTicket {
            ticket: service_ticket,
            requesting_service: "service$".to_owned(),
            impersonated_principal: "Administrator".to_owned(),
            impersonated_realm: "EXAMPLE.TEST".to_owned(),
        };
        assert!(validate_delegation_mode(&evidence, S4uDelegationMode::Constrained).is_err());
        assert!(validate_delegation_mode(&evidence, S4uDelegationMode::ResourceBased).is_ok());
    }

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}
