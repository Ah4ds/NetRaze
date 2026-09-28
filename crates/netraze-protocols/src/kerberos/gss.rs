//! Kerberos GSS-API initiation and RFC 4121 per-message protection.
//!
//! SMB and LDAP both negotiate Kerberos through SPNEGO, but consume the
//! established context differently: SMB derives its session signing key while
//! LDAP uses GSS wrap tokens for confidentiality and integrity. Keeping the
//! AP exchange and sequence state here prevents either transport from growing
//! a subtly different Kerberos implementation.

use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7,
    GeneralizedTimeAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::key_usages::{
    ACCEPTOR_SEAL, AP_REP_ENC, AP_REQ_AUTHENTICATOR, INITIATOR_SEAL,
};
use picky_krb::constants::types::{AP_REQ_MSG_TYPE, NT_PRINCIPAL};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    ApOptions, Authenticator, AuthenticatorInner, Checksum, EncApRepPart, EncryptedData,
    EncryptionKey,
};
use picky_krb::messages::{ApRep, ApReq, ApReqInner};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use time::OffsetDateTime;

use super::client::{
    encode_der, integer_as_i32, integer_as_u32, integer_i32, integer_u32, kerberos_string,
    principal,
};
use super::{KerberosEncryptionType, KerberosError, ServiceTicket, decrypt, encrypt};

const KERBEROS_VERSION: i32 = 5;
const AP_REP_MESSAGE_TYPE: i32 = 15;
const GSS_CHECKSUM_TYPE: i32 = 0x8003;
const GSS_CONTEXT_FLAGS: u32 = 0x3e;
const AES_GSS_CHECKSUM_LEN: usize = 12;
const GSS_WRAP_HEADER_LEN: usize = 16;
const GSS_WRAP_RRC: usize = GSS_WRAP_HEADER_LEN + AES_GSS_CHECKSUM_LEN;
const MAX_GSS_TOKEN: usize = 16 * 1024 * 1024;

const SPNEGO_OID_DER: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const KERBEROS_OID_DER: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];
const AP_REQ_TOKEN_ID: [u8; 2] = [0x01, 0x00];
const AP_REP_TOKEN_ID: [u8; 2] = [0x02, 0x00];

/// In-progress initiator state between the SPNEGO request and AP-REP.
pub struct KerberosGssInitiator {
    ticket_encryption_type: KerberosEncryptionType,
    ticket_session_key: Vec<u8>,
    initiator_subkey: Vec<u8>,
    authenticator_time: i64,
    authenticator_microseconds: u32,
    initiator_sequence: u64,
}

impl core::fmt::Debug for KerberosGssInitiator {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KerberosGssInitiator")
            .field("ticket_encryption_type", &self.ticket_encryption_type)
            .field("initiator_sequence", &self.initiator_sequence)
            .finish_non_exhaustive()
    }
}

impl KerberosGssInitiator {
    /// Build an AP-REQ inside a SPNEGO NegTokenInit. Mutual authentication,
    /// replay detection, sequencing, integrity, and confidentiality are all
    /// requested. An AES-128 initiator subkey gives modern RFC 4121 wrapping
    /// even when the service ticket itself was issued with RC4-HMAC.
    pub fn start(ticket: &ServiceTicket) -> Result<(Self, Vec<u8>), KerberosError> {
        let mut rng = OsRng;
        Self::start_at(ticket, OffsetDateTime::now_utc(), &mut rng)
    }

    fn start_at<R: RngCore + CryptoRng>(
        ticket: &ServiceTicket,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>), KerberosError> {
        let now_unix = now.unix_timestamp();
        if now_unix < ticket.valid_from_unix || now_unix >= ticket.valid_until_unix {
            return Err(KerberosError::InvalidMessage(
                "service ticket is not valid at the current time".to_owned(),
            ));
        }
        let mut initiator_subkey =
            vec![0_u8; KerberosEncryptionType::Aes128CtsHmacSha196.key_len()];
        rng.fill_bytes(&mut initiator_subkey);
        let initiator_sequence = u64::from(rng.next_u32());
        let authenticator_microseconds = now.microsecond().min(999_999);

        let mut gss_checksum = Vec::with_capacity(24);
        gss_checksum.extend_from_slice(&16_u32.to_le_bytes());
        gss_checksum.extend_from_slice(&[0_u8; 16]);
        gss_checksum.extend_from_slice(&GSS_CONTEXT_FLAGS.to_le_bytes());

        let client_components = ticket.client_principal.split('/').collect::<Vec<_>>();
        let authenticator = Authenticator::from(AuthenticatorInner {
            authenticator_vno: ExplicitContextTag0::from(integer_i32(KERBEROS_VERSION)),
            crealm: ExplicitContextTag1::from(kerberos_string(&ticket.client_realm)?),
            cname: ExplicitContextTag2::from(principal(NT_PRINCIPAL, &client_components)?),
            cksum: Optional::from(Some(ExplicitContextTag3::from(Checksum {
                cksumtype: ExplicitContextTag0::from(integer_i32(GSS_CHECKSUM_TYPE)),
                checksum: ExplicitContextTag1::from(OctetStringAsn1::from(gss_checksum)),
            }))),
            cusec: ExplicitContextTag4::from(integer_u32(authenticator_microseconds)),
            ctime: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(now))),
            subkey: Optional::from(Some(ExplicitContextTag6::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(integer_i32(
                    KerberosEncryptionType::AES128_NUMBER,
                )),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(
                    initiator_subkey.clone(),
                )),
            }))),
            seq_number: Optional::from(Some(ExplicitContextTag7::from(integer_u32(
                initiator_sequence as u32,
            )))),
            authorization_data: Optional::from(None),
        });
        let encrypted_authenticator = encrypt(
            ticket.session_encryption_type,
            &ticket.session_key,
            AP_REQ_AUTHENTICATOR,
            &encode_der(&authenticator)?,
            rng,
        )?;
        let ap_req = ApReq::from(ApReqInner {
            pvno: ExplicitContextTag0::from(integer_i32(KERBEROS_VERSION)),
            msg_type: ExplicitContextTag1::from(integer_i32(i32::from(AP_REQ_MSG_TYPE))),
            // RFC 4120 numbers APOptions from the most significant bit. Bit 2
            // (0x20) requests mutual authentication.
            ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(vec![
                0x20, 0, 0, 0,
            ]))),
            ticket: ExplicitContextTag3::from(ticket.ticket.clone()),
            authenticator: ExplicitContextTag4::from(EncryptedData {
                etype: ExplicitContextTag0::from(integer_i32(
                    ticket.session_encryption_type.number(),
                )),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
            }),
        });
        let ap_req_der = encode_der(&ap_req)?;
        let raw_token = encode_initial_context_token(&AP_REQ_TOKEN_ID, &ap_req_der)?;
        let spnego = encode_neg_token_init(&raw_token)?;
        Ok((
            Self {
                ticket_encryption_type: ticket.session_encryption_type,
                ticket_session_key: ticket.session_key.clone(),
                initiator_subkey,
                authenticator_time: now.unix_timestamp(),
                authenticator_microseconds,
                initiator_sequence,
            },
            spnego,
        ))
    }

    /// Validate the acceptor's SPNEGO response and AP-REP before releasing a
    /// usable security context. A missing AP-REP is rejected because the
    /// initiator requested mutual authentication.
    pub fn finish(self, response: &[u8]) -> Result<KerberosSecurityContext, KerberosError> {
        let response_token = decode_neg_token_response(response)?
            .ok_or_else(|| invalid_gss("SPNEGO response did not contain an AP-REP"))?;
        let ap_rep_der = decode_kerberos_mech_token(&response_token, AP_REP_TOKEN_ID)?;
        let ap_rep: ApRep = picky_asn1_der::from_bytes(ap_rep_der)
            .map_err(|error| invalid_gss(format!("invalid AP-REP: {error}")))?;
        if integer_as_i32(&ap_rep.0.pvno.0) != Some(KERBEROS_VERSION)
            || integer_as_i32(&ap_rep.0.msg_type.0) != Some(AP_REP_MESSAGE_TYPE)
        {
            return Err(invalid_gss("AP-REP has an invalid version or message type"));
        }
        let reply_encryption_type = KerberosEncryptionType::from_number(
            integer_as_i32(&ap_rep.0.enc_part.0.etype.0)
                .ok_or_else(|| invalid_gss("AP-REP has an invalid encryption type"))?,
        )?;
        if reply_encryption_type != self.ticket_encryption_type {
            return Err(invalid_gss(
                "AP-REP encrypted part does not use the service-ticket session enctype",
            ));
        }
        let plaintext = decrypt(
            reply_encryption_type,
            &self.ticket_session_key,
            AP_REP_ENC,
            &ap_rep.0.enc_part.0.cipher.0.0,
        )?;
        let encrypted_reply: EncApRepPart = picky_asn1_der::from_bytes(&plaintext)
            .map_err(|error| invalid_gss(format!("invalid encrypted AP-REP part: {error}")))?;
        let reply_time = OffsetDateTime::try_from(encrypted_reply.0.ctime.0.0.clone())
            .map_err(|error| invalid_gss(error.to_string()))?;
        let reply_microseconds = integer_as_u32(&encrypted_reply.0.cusec.0)
            .ok_or_else(|| invalid_gss("AP-REP has an invalid microsecond value"))?;
        if reply_time.unix_timestamp() != self.authenticator_time
            || reply_microseconds != self.authenticator_microseconds
        {
            return Err(invalid_gss(
                "AP-REP does not match the AP-REQ authenticator",
            ));
        }

        let (key_encryption_type, key, acceptor_subkey) = encrypted_reply.0.subkey.0.map_or_else(
            || {
                Ok::<_, KerberosError>((
                    KerberosEncryptionType::Aes128CtsHmacSha196,
                    self.initiator_subkey,
                    false,
                ))
            },
            |subkey| {
                let encryption_type = KerberosEncryptionType::from_number(
                    integer_as_i32(&subkey.0.key_type.0)
                        .ok_or_else(|| invalid_gss("AP-REP subkey has an invalid enctype"))?,
                )?;
                let key = subkey.0.key_value.0.0;
                validate_gss_key(encryption_type, &key)?;
                Ok((encryption_type, key, true))
            },
        )?;
        validate_gss_key(key_encryption_type, &key)?;
        let receive_sequence =
            encrypted_reply
                .0
                .seq_number
                .0
                .as_ref()
                .map_or(Ok(0_u64), |value| {
                    integer_as_u32(&value.0)
                        .map(u64::from)
                        .ok_or_else(|| invalid_gss("AP-REP has an invalid sequence number"))
                })?;

        Ok(KerberosSecurityContext {
            encryption_type: key_encryption_type,
            key,
            send_sequence: self.initiator_sequence,
            receive_sequence,
            acceptor_subkey,
            sent_by_acceptor: false,
        })
    }
}

/// Established Kerberos context with independent send and receive sequences.
pub struct KerberosSecurityContext {
    encryption_type: KerberosEncryptionType,
    key: Vec<u8>,
    send_sequence: u64,
    receive_sequence: u64,
    acceptor_subkey: bool,
    sent_by_acceptor: bool,
}

impl core::fmt::Debug for KerberosSecurityContext {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KerberosSecurityContext")
            .field("encryption_type", &self.encryption_type)
            .field("send_sequence", &self.send_sequence)
            .field("receive_sequence", &self.receive_sequence)
            .field("acceptor_subkey", &self.acceptor_subkey)
            .finish_non_exhaustive()
    }
}

impl KerberosSecurityContext {
    /// GSS context key consumed by SMB session-key derivation. The returned
    /// bytes remain owned by the security context and must not be persisted.
    #[must_use]
    pub fn session_key(&self) -> &[u8] {
        &self.key
    }

    #[must_use]
    pub const fn encryption_type(&self) -> KerberosEncryptionType {
        self.encryption_type
    }

    /// Seal one message as an RFC 4121 Wrap token.
    pub fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, KerberosError> {
        if plaintext.len() > MAX_GSS_TOKEN {
            return Err(invalid_gss("GSS plaintext exceeds the 16 MiB limit"));
        }
        let flags = self.outgoing_flags();
        let mut embedded_header = wrap_header(flags, 0, 0, self.send_sequence);
        let mut payload = Vec::with_capacity(plaintext.len() + GSS_WRAP_HEADER_LEN);
        payload.extend_from_slice(plaintext);
        payload.extend_from_slice(&embedded_header);
        let cipher = cipher_for_gss(self.encryption_type)?;
        let usage = if self.sent_by_acceptor {
            ACCEPTOR_SEAL
        } else {
            INITIATOR_SEAL
        };
        let encrypted = cipher
            .encrypt_no_checksum(&self.key, usage, &payload)
            .map_err(|error| KerberosError::Crypto(error.to_string()))?;
        let mut checksum_input =
            Vec::with_capacity(encrypted.confounder.len() + plaintext.len() + GSS_WRAP_HEADER_LEN);
        checksum_input.extend_from_slice(&encrypted.confounder);
        checksum_input.extend_from_slice(plaintext);
        checksum_input.extend_from_slice(&embedded_header);
        let checksum = cipher
            .encryption_checksum(&self.key, usage, &checksum_input)
            .map_err(|error| KerberosError::Crypto(error.to_string()))?;
        let mut body = encrypted.encrypted;
        body.extend_from_slice(&checksum);
        let body_len = body.len();
        body.rotate_right(GSS_WRAP_RRC % body_len);
        embedded_header[6..8].copy_from_slice(&(GSS_WRAP_RRC as u16).to_be_bytes());
        let mut output = Vec::with_capacity(GSS_WRAP_HEADER_LEN + body.len());
        output.extend_from_slice(&embedded_header);
        output.extend_from_slice(&body);
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or_else(|| invalid_gss("GSS send sequence exhausted"))?;
        Ok(output)
    }

    /// Authenticate and unseal one peer RFC 4121 Wrap token.
    pub fn unwrap(&mut self, token: &[u8]) -> Result<Vec<u8>, KerberosError> {
        if token.len() < GSS_WRAP_HEADER_LEN + AES_GSS_CHECKSUM_LEN + 16
            || token.len() > MAX_GSS_TOKEN + 128
        {
            return Err(invalid_gss("GSS Wrap token length is invalid"));
        }
        let header: [u8; GSS_WRAP_HEADER_LEN] = token[..GSS_WRAP_HEADER_LEN]
            .try_into()
            .map_err(|_| invalid_gss("GSS Wrap header is truncated"))?;
        if header[..2] != [0x05, 0x04] || header[3] != 0xff {
            return Err(invalid_gss("GSS Wrap header is malformed"));
        }
        let expected_flags = self.incoming_flags();
        if header[2] != expected_flags {
            return Err(invalid_gss(format!(
                "GSS Wrap flags are {:#04x}; expected {expected_flags:#04x}",
                header[2]
            )));
        }
        let extra_count = usize::from(u16::from_be_bytes([header[4], header[5]]));
        let rotation = usize::from(u16::from_be_bytes([header[6], header[7]]));
        let sequence = u64::from_be_bytes(
            header[8..16]
                .try_into()
                .map_err(|_| invalid_gss("GSS Wrap sequence is truncated"))?,
        );
        if sequence != self.receive_sequence {
            return Err(KerberosError::GssSequence {
                expected: self.receive_sequence,
                actual: sequence,
            });
        }
        let mut body = token[GSS_WRAP_HEADER_LEN..].to_vec();
        if rotation > body.len() || extra_count > body.len() {
            return Err(invalid_gss("GSS Wrap rotation or extra count is invalid"));
        }
        let body_len = body.len();
        body.rotate_left((rotation + extra_count) % body_len);
        let cipher = cipher_for_gss(self.encryption_type)?;
        let usage = if self.sent_by_acceptor {
            INITIATOR_SEAL
        } else {
            ACCEPTOR_SEAL
        };
        let decrypted = cipher
            .decrypt_no_checksum(&self.key, usage, &body)
            .map_err(|_| KerberosError::Integrity)?;
        if decrypted.plaintext.len() < GSS_WRAP_HEADER_LEN + extra_count {
            return Err(invalid_gss("GSS Wrap plaintext is truncated"));
        }
        let message_len = decrypted.plaintext.len() - GSS_WRAP_HEADER_LEN - extra_count;
        let message = &decrypted.plaintext[..message_len];
        let embedded = &decrypted.plaintext[message_len + extra_count..];
        let mut expected_embedded = header;
        expected_embedded[4..8].fill(0);
        if embedded != expected_embedded {
            return Err(KerberosError::Integrity);
        }
        let mut checksum_input = Vec::with_capacity(
            decrypted.confounder.len() + message.len() + extra_count + GSS_WRAP_HEADER_LEN,
        );
        checksum_input.extend_from_slice(&decrypted.confounder);
        checksum_input.extend_from_slice(message);
        checksum_input.extend_from_slice(&decrypted.plaintext[message_len..]);
        let expected_checksum = cipher
            .encryption_checksum(&self.key, usage, &checksum_input)
            .map_err(|error| KerberosError::Crypto(error.to_string()))?;
        if !constant_time_eq(&decrypted.checksum, &expected_checksum) {
            return Err(KerberosError::Integrity);
        }
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or_else(|| invalid_gss("GSS receive sequence exhausted"))?;
        Ok(message.to_vec())
    }

    const fn outgoing_flags(&self) -> u8 {
        let direction = if self.sent_by_acceptor { 0x01 } else { 0 };
        direction | 0x02 | if self.acceptor_subkey { 0x04 } else { 0 }
    }

    const fn incoming_flags(&self) -> u8 {
        let direction = if self.sent_by_acceptor { 0 } else { 0x01 };
        direction | 0x02 | if self.acceptor_subkey { 0x04 } else { 0 }
    }

    #[cfg(test)]
    fn test_peer(&self) -> Self {
        Self {
            encryption_type: self.encryption_type,
            key: self.key.clone(),
            send_sequence: self.receive_sequence,
            receive_sequence: self.send_sequence,
            acceptor_subkey: self.acceptor_subkey,
            sent_by_acceptor: !self.sent_by_acceptor,
        }
    }
}

fn cipher_for_gss(
    encryption_type: KerberosEncryptionType,
) -> Result<Box<dyn picky_krb::crypto::Cipher>, KerberosError> {
    match encryption_type {
        KerberosEncryptionType::Aes128CtsHmacSha196 => {
            Ok(CipherSuite::Aes128CtsHmacSha196.cipher())
        }
        KerberosEncryptionType::Aes256CtsHmacSha196 => {
            Ok(CipherSuite::Aes256CtsHmacSha196.cipher())
        }
        KerberosEncryptionType::Rc4Hmac => Err(KerberosError::Crypto(
            "RC4 service tickets use an AES initiator subkey for RFC 4121 GSS protection"
                .to_owned(),
        )),
    }
}

fn validate_gss_key(
    encryption_type: KerberosEncryptionType,
    key: &[u8],
) -> Result<(), KerberosError> {
    if matches!(encryption_type, KerberosEncryptionType::Rc4Hmac) {
        return Err(invalid_gss(
            "acceptor selected an RC4 subkey, which cannot protect RFC 4121 messages",
        ));
    }
    if key.len() != encryption_type.key_len() {
        return Err(KerberosError::InvalidKeyLength {
            encryption_type: encryption_type.name(),
            expected: encryption_type.key_len(),
            actual: key.len(),
        });
    }
    Ok(())
}

fn wrap_header(flags: u8, extra_count: u16, rotation: u16, sequence: u64) -> [u8; 16] {
    let mut header = [0_u8; 16];
    header[..2].copy_from_slice(&[0x05, 0x04]);
    header[2] = flags;
    header[3] = 0xff;
    header[4..6].copy_from_slice(&extra_count.to_be_bytes());
    header[6..8].copy_from_slice(&rotation.to_be_bytes());
    header[8..16].copy_from_slice(&sequence.to_be_bytes());
    header
}

fn encode_initial_context_token(
    token_id: &[u8; 2],
    kerberos_der: &[u8],
) -> Result<Vec<u8>, KerberosError> {
    let mut body = Vec::with_capacity(KERBEROS_OID_DER.len() + token_id.len() + kerberos_der.len());
    body.extend_from_slice(KERBEROS_OID_DER);
    body.extend_from_slice(token_id);
    body.extend_from_slice(kerberos_der);
    der_wrap(0x60, &body)
}

fn encode_neg_token_init(mechanism_token: &[u8]) -> Result<Vec<u8>, KerberosError> {
    let mechanism_list = der_wrap(0x30, KERBEROS_OID_DER)?;
    let mechanism_list = der_wrap(0xa0, &mechanism_list)?;
    let mechanism_token = der_wrap(0x04, mechanism_token)?;
    let mechanism_token = der_wrap(0xa2, &mechanism_token)?;
    let mut sequence = Vec::with_capacity(mechanism_list.len() + mechanism_token.len());
    sequence.extend_from_slice(&mechanism_list);
    sequence.extend_from_slice(&mechanism_token);
    let sequence = der_wrap(0x30, &sequence)?;
    let negotiation = der_wrap(0xa0, &sequence)?;
    let mut body = Vec::with_capacity(SPNEGO_OID_DER.len() + negotiation.len());
    body.extend_from_slice(SPNEGO_OID_DER);
    body.extend_from_slice(&negotiation);
    der_wrap(0x60, &body)
}

fn decode_neg_token_response(input: &[u8]) -> Result<Option<Vec<u8>>, KerberosError> {
    if input.is_empty() {
        return Ok(None);
    }
    let (_, outer, rest) = der_tlv(input)?;
    if !rest.is_empty() {
        return Err(invalid_gss("trailing bytes after SPNEGO response"));
    }
    let sequence = if input[0] == 0xa1 {
        expect_single_tlv(0x30, outer)?
    } else if input[0] == 0x30 {
        outer
    } else {
        return Err(invalid_gss("SPNEGO response is not NegTokenResp"));
    };
    let mut remaining = sequence;
    let mut response = None;
    while !remaining.is_empty() {
        let (tag, value, tail) = der_tlv(remaining)?;
        remaining = tail;
        match tag {
            0xa0 => {
                let enumerated = expect_single_tlv(0x0a, value)?;
                if enumerated.len() != 1 || enumerated[0] > 1 {
                    return Err(invalid_gss("SPNEGO negotiation was rejected"));
                }
            }
            0xa1 => {
                let oid = expect_single_tlv(0x06, value)?;
                if oid != &KERBEROS_OID_DER[2..] {
                    return Err(invalid_gss("SPNEGO selected a non-Kerberos mechanism"));
                }
            }
            0xa2 => {
                if response.is_some() {
                    return Err(invalid_gss("SPNEGO response contains duplicate tokens"));
                }
                response = Some(expect_single_tlv(0x04, value)?.to_vec());
            }
            0xa3 => {
                // A mechanism-list MIC is optional when exactly one mechanism
                // was offered. It is structurally validated but not needed to
                // disambiguate the selected mechanism.
                let _ = expect_single_tlv(0x04, value)?;
            }
            _ => return Err(invalid_gss("SPNEGO response contains an unknown field")),
        }
    }
    Ok(response)
}

fn decode_kerberos_mech_token(
    input: &[u8],
    expected_token_id: [u8; 2],
) -> Result<&[u8], KerberosError> {
    if input.first() == Some(&0x6f) {
        // Some GSS acceptors return the bare AP-REP application value.
        return Ok(input);
    }
    let (tag, value, rest) = der_tlv(input)?;
    if tag != 0x60 || !rest.is_empty() {
        return Err(invalid_gss("Kerberos mechanism token is malformed"));
    }
    if !value.starts_with(KERBEROS_OID_DER) {
        return Err(invalid_gss(
            "Kerberos mechanism token has an unexpected OID",
        ));
    }
    let value = &value[KERBEROS_OID_DER.len()..];
    if value.len() < 2 || value[..2] != expected_token_id {
        return Err(invalid_gss(
            "Kerberos mechanism token has an unexpected token ID",
        ));
    }
    Ok(&value[2..])
}

fn der_wrap(tag: u8, value: &[u8]) -> Result<Vec<u8>, KerberosError> {
    if value.len() > MAX_GSS_TOKEN {
        return Err(invalid_gss("DER value exceeds the GSS token limit"));
    }
    let mut output = Vec::with_capacity(value.len() + 6);
    output.push(tag);
    encode_der_length(value.len(), &mut output);
    output.extend_from_slice(value);
    Ok(output)
}

fn encode_der_length(length: usize, output: &mut Vec<u8>) {
    if length < 128 {
        output.push(length as u8);
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    output.push(0x80 | significant.len() as u8);
    output.extend_from_slice(significant);
}

fn der_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), KerberosError> {
    if input.len() < 2 {
        return Err(invalid_gss("truncated DER header"));
    }
    let tag = input[0];
    let first = input[1];
    let (length, header_len) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > core::mem::size_of::<usize>() || input.len() < 2 + count {
            return Err(invalid_gss("invalid DER long-form length"));
        }
        if input[2] == 0 {
            return Err(invalid_gss("non-minimal DER length"));
        }
        let mut length = 0_usize;
        for byte in &input[2..2 + count] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| invalid_gss("DER length overflow"))?;
        }
        if length < 128 {
            return Err(invalid_gss("non-minimal DER long-form length"));
        }
        (length, 2 + count)
    };
    if length > MAX_GSS_TOKEN || input.len() < header_len + length {
        return Err(invalid_gss("truncated or oversized DER value"));
    }
    Ok((
        tag,
        &input[header_len..header_len + length],
        &input[header_len + length..],
    ))
}

fn expect_single_tlv(expected_tag: u8, input: &[u8]) -> Result<&[u8], KerberosError> {
    let (tag, value, rest) = der_tlv(input)?;
    if tag != expected_tag || !rest.is_empty() {
        return Err(invalid_gss(format!(
            "expected one DER tag {expected_tag:#04x}"
        )));
    }
    Ok(value)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn invalid_gss(message: impl Into<String>) -> KerberosError {
    KerberosError::InvalidGssToken(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky_krb::data_types::EncApRepPartInner;
    use picky_krb::messages::ApRepInner;

    fn test_initiator() -> KerberosGssInitiator {
        KerberosGssInitiator {
            ticket_encryption_type: KerberosEncryptionType::Aes128CtsHmacSha196,
            ticket_session_key: vec![0x31; 16],
            initiator_subkey: vec![0x42; 16],
            authenticator_time: 1_700_000_000,
            authenticator_microseconds: 123_456,
            initiator_sequence: 11,
        }
    }

    fn ap_rep_response(initiator: &KerberosGssInitiator, timestamp: i64) -> Vec<u8> {
        let reply_part = EncApRepPart::from(EncApRepPartInner {
            ctime: ExplicitContextTag0::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(
                OffsetDateTime::from_unix_timestamp(timestamp).unwrap(),
            ))),
            cusec: ExplicitContextTag1::from(integer_u32(initiator.authenticator_microseconds)),
            subkey: Optional::from(Some(ExplicitContextTag2::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(integer_i32(
                    KerberosEncryptionType::AES128_NUMBER,
                )),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(vec![0x55; 16])),
            }))),
            seq_number: Optional::from(Some(ExplicitContextTag3::from(integer_u32(29)))),
        });
        let ciphertext = encrypt(
            initiator.ticket_encryption_type,
            &initiator.ticket_session_key,
            AP_REP_ENC,
            &encode_der(&reply_part).unwrap(),
            &mut OsRng,
        )
        .unwrap();
        let ap_rep = ApRep::from(ApRepInner {
            pvno: ExplicitContextTag0::from(integer_i32(KERBEROS_VERSION)),
            msg_type: ExplicitContextTag1::from(integer_i32(AP_REP_MESSAGE_TYPE)),
            enc_part: ExplicitContextTag2::from(EncryptedData {
                etype: ExplicitContextTag0::from(integer_i32(
                    initiator.ticket_encryption_type.number(),
                )),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(ciphertext)),
            }),
        });
        let raw =
            encode_initial_context_token(&AP_REP_TOKEN_ID, &encode_der(&ap_rep).unwrap()).unwrap();
        let response = der_wrap(0x04, &raw).unwrap();
        let response = der_wrap(0xa2, &response).unwrap();
        let result = der_wrap(0x0a, &[0]).unwrap();
        let result = der_wrap(0xa0, &result).unwrap();
        let mut sequence = result;
        sequence.extend_from_slice(&response);
        let sequence = der_wrap(0x30, &sequence).unwrap();
        der_wrap(0xa1, &sequence).unwrap()
    }

    #[test]
    fn ap_rep_must_match_the_authenticator() {
        let initiator = test_initiator();
        let response = ap_rep_response(&initiator, initiator.authenticator_time);
        let context = initiator.finish(&response).unwrap();
        assert_eq!(context.session_key(), &[0x55; 16]);

        let initiator = test_initiator();
        let response = ap_rep_response(&initiator, initiator.authenticator_time + 1);
        assert!(matches!(
            initiator.finish(&response),
            Err(KerberosError::InvalidGssToken(_))
        ));
    }

    #[test]
    fn wrap_context_round_trips_in_both_directions() {
        let mut initiator = KerberosSecurityContext {
            encryption_type: KerberosEncryptionType::Aes128CtsHmacSha196,
            key: vec![0x41; 16],
            send_sequence: 17,
            receive_sequence: 23,
            acceptor_subkey: true,
            sent_by_acceptor: false,
        };
        let mut acceptor = initiator.test_peer();

        let request = initiator.wrap(b"ldap request").unwrap();
        assert_eq!(acceptor.unwrap(&request).unwrap(), b"ldap request");
        let response = acceptor.wrap(b"ldap response").unwrap();
        assert_eq!(initiator.unwrap(&response).unwrap(), b"ldap response");
    }

    #[test]
    fn wrap_context_rejects_replay_and_tampering() {
        let mut initiator = KerberosSecurityContext {
            encryption_type: KerberosEncryptionType::Aes256CtsHmacSha196,
            key: vec![0x24; 32],
            send_sequence: 4,
            receive_sequence: 8,
            acceptor_subkey: false,
            sent_by_acceptor: false,
        };
        let mut acceptor = initiator.test_peer();
        let token = initiator.wrap(b"protected").unwrap();
        assert_eq!(acceptor.unwrap(&token).unwrap(), b"protected");
        assert!(matches!(
            acceptor.unwrap(&token),
            Err(KerberosError::GssSequence { .. })
        ));

        let mut acceptor = initiator.test_peer();
        let mut tampered = initiator.wrap(b"another").unwrap();
        *tampered.last_mut().unwrap() ^= 0x80;
        assert!(matches!(
            acceptor.unwrap(&tampered),
            Err(KerberosError::Integrity)
        ));
    }

    #[test]
    fn strict_spnego_response_parser_extracts_ap_rep() {
        let raw = encode_initial_context_token(&AP_REP_TOKEN_ID, &[0x6f, 0x00]).unwrap();
        let response = der_wrap(0x04, &raw).unwrap();
        let response = der_wrap(0xa2, &response).unwrap();
        let result = der_wrap(0x0a, &[0]).unwrap();
        let result = der_wrap(0xa0, &result).unwrap();
        let mut sequence = result;
        sequence.extend_from_slice(&response);
        let sequence = der_wrap(0x30, &sequence).unwrap();
        let token = der_wrap(0xa1, &sequence).unwrap();

        let extracted = decode_neg_token_response(&token).unwrap().unwrap();
        assert_eq!(
            decode_kerberos_mech_token(&extracted, AP_REP_TOKEN_ID).unwrap(),
            &[0x6f, 0x00]
        );
    }

    #[test]
    fn strict_spnego_parser_rejects_trailing_bytes() {
        let mut token = der_wrap(0xa1, &der_wrap(0x30, &[]).unwrap()).unwrap();
        token.push(0);
        assert!(decode_neg_token_response(&token).is_err());
    }
}
