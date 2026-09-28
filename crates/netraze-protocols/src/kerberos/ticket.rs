//! Interoperable Kerberos ticket containers.
//!
//! The protocol client keeps ticket/session-key pairs in memory. This module is
//! the only place where that material crosses a file boundary: MIT ccache v4
//! and the cleartext-`EncKrbCredPart` KRB-CRED convention used by `.kirbi`
//! files. Container metadata is checked against the embedded RFC 4120 ticket
//! before a credential can be selected for authentication.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ccache_io::{Ccache, Credential, KeyBlock, Principal};
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6,
    ExplicitContextTag7, ExplicitContextTag8, ExplicitContextTag9, ExplicitContextTag10,
    GeneralizedTimeAsn1, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::data_types::{
    EncryptedData, EncryptionKey, HostAddresses, KerberosFlags, KerberosStringAsn1, PrincipalName,
    Ticket,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::assessment::ServiceTicket;
use super::client::{
    TicketGrantingTicket, integer_as_i32, integer_i32, kerberos_string, principal_name,
};
use super::{KerberosEncryptionType, KerberosError};

const MAX_TICKET_FILE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_TICKETS: usize = 4_096;
const MAX_PRINCIPAL_COMPONENTS: usize = 32;
const MAX_PRINCIPAL_LENGTH: usize = 4_096;
const KERBEROS_VERSION: i32 = 5;
const KRB_CRED_MESSAGE_TYPE: i32 = 22;
const KRB_CRED_APPLICATION_TAG: u8 = 22;
const ENC_KRB_CRED_PART_APPLICATION_TAG: u8 = 29;

/// The two file formats accepted by NetRaze for ticket import and export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketFileFormat {
    CcacheV4,
    Kirbi,
}

/// Whether a cached ticket is a ticket-granting ticket or an application
/// service ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KerberosTicketKind {
    TicketGranting,
    Service,
}

/// Non-secret information suitable for UI display and workspace persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketMetadata {
    pub kind: KerberosTicketKind,
    pub client_principal: String,
    pub client_realm: String,
    pub realm: String,
    pub service_principal: String,
    pub encryption_type: KerberosEncryptionType,
    pub issued_at_unix: i64,
    pub valid_from_unix: i64,
    pub valid_until_unix: i64,
    pub renewable_until_unix: Option<i64>,
    pub ticket_flags: u32,
}

/// One RFC 4120 ticket paired with the session key required to use it.
///
/// Secret fields are private, deliberately not serializable, and omitted from
/// `Debug` output.
#[derive(Clone)]
pub struct KerberosTicket {
    pub(crate) ticket: Ticket,
    pub(crate) session_key: Vec<u8>,
    metadata: TicketMetadata,
}

impl core::fmt::Debug for KerberosTicket {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KerberosTicket")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl KerberosTicket {
    #[must_use]
    pub const fn metadata(&self) -> &TicketMetadata {
        &self.metadata
    }

    #[must_use]
    pub fn is_valid_at(&self, unix_time: i64) -> bool {
        self.metadata.valid_from_unix <= unix_time && unix_time < self.metadata.valid_until_unix
    }

    #[must_use]
    pub fn from_tgt(ticket: &TicketGrantingTicket) -> Self {
        Self {
            ticket: ticket.ticket.clone(),
            session_key: ticket.session_key.clone(),
            metadata: TicketMetadata {
                kind: KerberosTicketKind::TicketGranting,
                client_principal: ticket.client_principal.clone(),
                client_realm: ticket.realm.clone(),
                realm: ticket.kdc_realm.clone(),
                service_principal: principal_name(&ticket.ticket.0.sname.0),
                encryption_type: ticket.session_encryption_type,
                issued_at_unix: ticket.issued_at_unix,
                valid_from_unix: ticket.valid_from_unix,
                valid_until_unix: ticket.valid_until_unix,
                renewable_until_unix: ticket.renewable_until_unix,
                ticket_flags: ticket.ticket_flags,
            },
        }
    }

    #[must_use]
    pub fn from_service(ticket: &ServiceTicket) -> Self {
        Self {
            ticket: ticket.ticket.clone(),
            session_key: ticket.session_key.clone(),
            metadata: TicketMetadata {
                kind: KerberosTicketKind::Service,
                client_principal: ticket.client_principal.clone(),
                client_realm: ticket.client_realm.clone(),
                realm: ticket.realm.clone(),
                service_principal: ticket.service_principal_name.clone(),
                encryption_type: ticket.session_encryption_type,
                issued_at_unix: ticket.issued_at_unix,
                valid_from_unix: ticket.valid_from_unix,
                valid_until_unix: ticket.valid_until_unix,
                renewable_until_unix: ticket.renewable_until_unix,
                ticket_flags: ticket.ticket_flags,
            },
        }
    }

    pub fn to_tgt(&self) -> Result<TicketGrantingTicket, KerberosError> {
        if self.metadata.kind != KerberosTicketKind::TicketGranting {
            return Err(KerberosError::InvalidTicketContainer(
                "selected ticket is not a ticket-granting ticket".to_owned(),
            ));
        }
        Ok(TicketGrantingTicket {
            ticket: self.ticket.clone(),
            session_key: self.session_key.clone(),
            session_encryption_type: self.metadata.encryption_type,
            client_principal: self.metadata.client_principal.clone(),
            realm: self.metadata.client_realm.clone(),
            kdc_realm: self.metadata.realm.clone(),
            issued_at_unix: self.metadata.issued_at_unix,
            valid_from_unix: self.metadata.valid_from_unix,
            valid_until_unix: self.metadata.valid_until_unix,
            renewable_until_unix: self.metadata.renewable_until_unix,
            ticket_flags: self.metadata.ticket_flags,
        })
    }

    pub fn to_service_ticket(&self) -> Result<ServiceTicket, KerberosError> {
        if self.metadata.kind != KerberosTicketKind::Service {
            return Err(KerberosError::InvalidTicketContainer(
                "selected ticket is not a service ticket".to_owned(),
            ));
        }
        Ok(ServiceTicket {
            ticket: self.ticket.clone(),
            session_key: self.session_key.clone(),
            session_encryption_type: self.metadata.encryption_type,
            client_principal: self.metadata.client_principal.clone(),
            client_realm: self.metadata.client_realm.clone(),
            service_principal_name: self.metadata.service_principal.clone(),
            realm: self.metadata.realm.clone(),
            issued_at_unix: self.metadata.issued_at_unix,
            valid_from_unix: self.metadata.valid_from_unix,
            valid_until_unix: self.metadata.valid_until_unix,
            renewable_until_unix: self.metadata.renewable_until_unix,
            ticket_flags: self.metadata.ticket_flags,
        })
    }
}

/// Exact ticket-selection constraints. An absent service principal selects a
/// TGT; a present service principal selects only an exact service ticket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TicketSelector {
    pub client_principal: Option<String>,
    pub realm: Option<String>,
    pub service_principal: Option<String>,
    /// Override used by deterministic tests. Production callers leave this
    /// unset and selection uses the current UTC time.
    pub valid_at_unix: Option<i64>,
}

/// An in-memory cache. It never implements serde because every entry contains
/// a reusable session key.
#[derive(Clone)]
pub struct TicketCache {
    primary_principal: String,
    primary_realm: String,
    tickets: Vec<KerberosTicket>,
}

impl core::fmt::Debug for TicketCache {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TicketCache")
            .field("primary_principal", &self.primary_principal)
            .field("primary_realm", &self.primary_realm)
            .field("ticket_count", &self.tickets.len())
            .finish_non_exhaustive()
    }
}

impl TicketCache {
    pub fn new(ticket: KerberosTicket) -> Self {
        Self {
            primary_principal: ticket.metadata.client_principal.clone(),
            primary_realm: ticket.metadata.client_realm.clone(),
            tickets: vec![ticket],
        }
    }

    pub fn from_tgt(ticket: &TicketGrantingTicket) -> Self {
        Self::new(KerberosTicket::from_tgt(ticket))
    }

    pub fn push(&mut self, ticket: KerberosTicket) -> Result<(), KerberosError> {
        if self.tickets.len() >= MAX_TICKETS {
            return Err(KerberosError::InvalidTicketContainer(format!(
                "ticket cache exceeds the {MAX_TICKETS}-entry limit"
            )));
        }
        self.tickets.push(ticket);
        Ok(())
    }

    #[must_use]
    pub fn primary_principal(&self) -> &str {
        &self.primary_principal
    }

    #[must_use]
    pub fn primary_realm(&self) -> &str {
        &self.primary_realm
    }

    pub fn metadata(&self) -> impl ExactSizeIterator<Item = &TicketMetadata> {
        self.tickets.iter().map(KerberosTicket::metadata)
    }

    pub fn select(&self, selector: &TicketSelector) -> Result<&KerberosTicket, KerberosError> {
        let now = selector
            .valid_at_unix
            .unwrap_or_else(|| OffsetDateTime::now_utc().unix_timestamp());
        let realm = selector.realm.as_deref().unwrap_or(&self.primary_realm);
        let requested_kind = if selector.service_principal.is_some() {
            KerberosTicketKind::Service
        } else {
            KerberosTicketKind::TicketGranting
        };
        let mut matches =
            self.tickets
                .iter()
                .filter(|ticket| {
                    let metadata = ticket.metadata();
                    metadata.kind == requested_kind
                        && ticket.is_valid_at(now)
                        && metadata.realm.eq_ignore_ascii_case(realm)
                        && selector.client_principal.as_ref().is_none_or(|client| {
                            metadata.client_principal.eq_ignore_ascii_case(client)
                        })
                        && selector.service_principal.as_ref().is_none_or(|service| {
                            metadata.service_principal.eq_ignore_ascii_case(service)
                        })
                })
                .collect::<Vec<_>>();
        if matches.is_empty() {
            return Err(KerberosError::TicketNotFound);
        }
        matches.sort_by_key(|ticket| {
            (
                ticket.metadata.issued_at_unix,
                ticket.metadata.valid_until_unix,
            )
        });
        let selected = matches.pop().expect("non-empty ticket matches");
        if matches.last().is_some_and(|other| {
            other.metadata.issued_at_unix == selected.metadata.issued_at_unix
                && other.metadata.valid_until_unix == selected.metadata.valid_until_unix
        }) {
            return Err(KerberosError::AmbiguousTicket);
        }
        Ok(selected)
    }
}

/// Load and validate a ccache v4 or `.kirbi` file. Format is detected from the
/// ccache magic; every other input is parsed as DER KRB-CRED.
pub fn import_ticket_file(path: impl AsRef<Path>) -> Result<TicketCache, KerberosError> {
    let path = path.as_ref();
    let metadata = fs::metadata(path)
        .map_err(|source| KerberosError::io(&path.display().to_string(), source))?;
    if metadata.len() > MAX_TICKET_FILE_SIZE {
        return Err(KerberosError::TicketFileTooLarge {
            path: path.display().to_string(),
            limit: MAX_TICKET_FILE_SIZE as usize,
        });
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|source| KerberosError::io(&path.display().to_string(), source))?;
    if bytes.starts_with(&[0x05, 0x04]) {
        decode_ccache(&bytes)
    } else {
        decode_kirbi(&bytes)
    }
}

/// Export a cache to an explicitly selected format. The destination is
/// written through a same-directory temporary file and owner-only mode is set
/// before secret bytes are written on Unix.
pub fn export_ticket_file(
    path: impl AsRef<Path>,
    cache: &TicketCache,
    format: TicketFileFormat,
    overwrite: bool,
) -> Result<(), KerberosError> {
    let path = path.as_ref();
    if !overwrite && path.exists() {
        return Err(KerberosError::TicketFileExists(path.display().to_string()));
    }
    let bytes = match format {
        TicketFileFormat::CcacheV4 => encode_ccache(cache)?,
        TicketFileFormat::Kirbi => encode_kirbi(cache)?,
    };
    if bytes.len() > MAX_TICKET_FILE_SIZE as usize {
        return Err(KerberosError::TicketFileTooLarge {
            path: path.display().to_string(),
            limit: MAX_TICKET_FILE_SIZE as usize,
        });
    }
    let temporary = temporary_path(path);
    let result = write_protected(&temporary, &bytes).and_then(|()| {
        if overwrite && path.exists() {
            fs::remove_file(path)
                .map_err(|source| KerberosError::io(&path.display().to_string(), source))?;
        }
        fs::rename(&temporary, path)
            .map_err(|source| KerberosError::io(&path.display().to_string(), source))
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    let suffix = rand::thread_rng().next_u64();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ticket");
    path.with_file_name(format!(".{name}.netraze-{suffix:016x}.tmp"))
}

fn write_protected(path: &Path, bytes: &[u8]) -> Result<(), KerberosError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| KerberosError::io(&path.display().to_string(), source))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| KerberosError::io(&path.display().to_string(), source))
}

fn decode_ccache(bytes: &[u8]) -> Result<TicketCache, KerberosError> {
    let ccache = Ccache::parse(bytes)
        .map_err(|error| KerberosError::InvalidTicketContainer(error.to_string()))?;
    if ccache.credentials.is_empty() || ccache.credentials.len() > MAX_TICKETS {
        return Err(KerberosError::InvalidTicketContainer(format!(
            "ccache must contain between 1 and {MAX_TICKETS} credentials"
        )));
    }
    validate_principal(&ccache.primary)?;
    let mut tickets = Vec::with_capacity(ccache.credentials.len());
    for credential in &ccache.credentials {
        tickets.push(ticket_from_ccache(credential)?);
    }
    Ok(TicketCache {
        primary_principal: ccache.primary.components.join("/"),
        primary_realm: ccache.primary.realm,
        tickets,
    })
}

fn ticket_from_ccache(credential: &Credential) -> Result<KerberosTicket, KerberosError> {
    validate_principal(&credential.client)?;
    validate_principal(&credential.server)?;
    if credential.ticket.is_empty() || credential.ticket.len() > MAX_TICKET_FILE_SIZE as usize {
        return Err(KerberosError::InvalidTicketContainer(
            "ccache credential has an empty or oversized ticket".to_owned(),
        ));
    }
    let ticket: Ticket = picky_asn1_der::from_bytes(&credential.ticket)
        .map_err(|error| KerberosError::InvalidTicketContainer(error.to_string()))?;
    let ticket_realm = ticket.0.realm.0.0.to_string();
    let ticket_service = principal_name(&ticket.0.sname.0);
    let cache_service = credential.server.components.join("/");
    if !ticket_realm.eq_ignore_ascii_case(&credential.server.realm)
        || !ticket_service.eq_ignore_ascii_case(&cache_service)
    {
        return Err(KerberosError::InvalidTicketContainer(
            "ccache server metadata does not match the embedded ticket".to_owned(),
        ));
    }
    make_ticket(ImportedTicket {
        ticket,
        encryption_type: credential.key.keytype.into(),
        session_key: credential.key.key.clone(),
        client_principal: credential.client.components.join("/"),
        client_realm: credential.client.realm.clone(),
        service_principal: cache_service,
        issued_at_unix: i64::from(credential.authtime),
        valid_from_unix: i64::from(credential.starttime),
        valid_until_unix: i64::from(credential.endtime),
        renewable_until_unix: (credential.renew_till != 0)
            .then_some(i64::from(credential.renew_till)),
        ticket_flags: credential.tktflags,
    })
}

fn encode_ccache(cache: &TicketCache) -> Result<Vec<u8>, KerberosError> {
    validate_cache(cache)?;
    let primary = Principal {
        realm: cache.primary_realm.clone(),
        name_type: 1,
        components: split_principal(&cache.primary_principal)?,
    };
    let mut ccache = Ccache::new(primary);
    for ticket in &cache.tickets {
        let metadata = ticket.metadata();
        ccache.credentials.push(Credential {
            client: Principal {
                realm: metadata.client_realm.clone(),
                name_type: 1,
                components: split_principal(&metadata.client_principal)?,
            },
            server: Principal {
                realm: ticket.ticket.0.realm.0.0.to_string(),
                name_type: 2,
                components: split_principal(&metadata.service_principal)?,
            },
            key: KeyBlock {
                keytype: u16::try_from(metadata.encryption_type.number()).map_err(|_| {
                    KerberosError::InvalidTicketContainer("negative ticket enctype".to_owned())
                })?,
                key: ticket.session_key.clone(),
            },
            authtime: unix_as_u32(metadata.issued_at_unix)?,
            starttime: unix_as_u32(metadata.valid_from_unix)?,
            endtime: unix_as_u32(metadata.valid_until_unix)?,
            renew_till: metadata
                .renewable_until_unix
                .map(unix_as_u32)
                .transpose()?
                .unwrap_or(0),
            is_skey: false,
            tktflags: metadata.ticket_flags,
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: picky_asn1_der::to_vec(&ticket.ticket)
                .map_err(|error| KerberosError::InvalidTicketContainer(error.to_string()))?,
            second_ticket: Vec::new(),
        });
    }
    Ok(ccache.to_bytes())
}

fn validate_principal(principal: &Principal) -> Result<(), KerberosError> {
    validate_principal_parts(&principal.realm, &principal.components)
}

fn validate_principal_parts(realm: &str, components: &[String]) -> Result<(), KerberosError> {
    if realm.is_empty()
        || realm.len() > MAX_PRINCIPAL_LENGTH
        || components.is_empty()
        || components.len() > MAX_PRINCIPAL_COMPONENTS
        || components
            .iter()
            .any(|component| component.is_empty() || component.len() > MAX_PRINCIPAL_LENGTH)
    {
        return Err(KerberosError::InvalidTicketContainer(
            "ticket contains an invalid or oversized principal".to_owned(),
        ));
    }
    Ok(())
}

fn split_principal(principal: &str) -> Result<Vec<String>, KerberosError> {
    let components = principal.split('/').map(str::to_owned).collect::<Vec<_>>();
    validate_principal_parts("placeholder", &components)?;
    Ok(components)
}

fn unix_as_u32(value: i64) -> Result<u32, KerberosError> {
    u32::try_from(value).map_err(|_| {
        KerberosError::InvalidTicketContainer(format!(
            "timestamp {value} cannot be represented by ccache v4"
        ))
    })
}

struct ImportedTicket {
    ticket: Ticket,
    encryption_type: i32,
    session_key: Vec<u8>,
    client_principal: String,
    client_realm: String,
    service_principal: String,
    issued_at_unix: i64,
    valid_from_unix: i64,
    valid_until_unix: i64,
    renewable_until_unix: Option<i64>,
    ticket_flags: u32,
}

fn make_ticket(imported: ImportedTicket) -> Result<KerberosTicket, KerberosError> {
    let ImportedTicket {
        ticket,
        encryption_type,
        session_key,
        client_principal,
        client_realm,
        service_principal,
        issued_at_unix,
        valid_from_unix,
        valid_until_unix,
        renewable_until_unix,
        ticket_flags,
    } = imported;
    validate_principal_parts(&client_realm, &split_principal(&client_principal)?)?;
    let encryption_type = KerberosEncryptionType::from_number(encryption_type)?;
    if session_key.len() != encryption_type.key_len() {
        return Err(KerberosError::InvalidKeyLength {
            encryption_type: encryption_type.name(),
            expected: encryption_type.key_len(),
            actual: session_key.len(),
        });
    }
    if valid_until_unix <= valid_from_unix
        || issued_at_unix > valid_until_unix
        || renewable_until_unix.is_some_and(|renew| renew < valid_until_unix)
    {
        return Err(KerberosError::InvalidTicketContainer(
            "ticket lifetime metadata is inconsistent".to_owned(),
        ));
    }
    let embedded_realm = ticket.0.realm.0.0.to_string();
    let embedded_service = principal_name(&ticket.0.sname.0);
    if !embedded_service.eq_ignore_ascii_case(&service_principal) {
        return Err(KerberosError::InvalidTicketContainer(
            "ticket service metadata does not match the embedded ticket".to_owned(),
        ));
    }
    let kind = if service_principal
        .split('/')
        .next()
        .is_some_and(|component| component.eq_ignore_ascii_case("krbtgt"))
    {
        KerberosTicketKind::TicketGranting
    } else {
        KerberosTicketKind::Service
    };
    Ok(KerberosTicket {
        ticket,
        session_key,
        metadata: TicketMetadata {
            kind,
            client_principal,
            client_realm: client_realm.clone(),
            realm: if kind == KerberosTicketKind::TicketGranting {
                service_principal
                    .split('/')
                    .nth(1)
                    .unwrap_or(&client_realm)
                    .to_ascii_uppercase()
            } else {
                embedded_realm
            },
            service_principal,
            encryption_type,
            issued_at_unix,
            valid_from_unix,
            valid_until_unix,
            renewable_until_unix,
            ticket_flags,
        },
    })
}

fn validate_cache(cache: &TicketCache) -> Result<(), KerberosError> {
    if cache.tickets.is_empty() || cache.tickets.len() > MAX_TICKETS {
        return Err(KerberosError::InvalidTicketContainer(format!(
            "ticket cache must contain between 1 and {MAX_TICKETS} entries"
        )));
    }
    validate_principal_parts(
        &cache.primary_realm,
        &split_principal(&cache.primary_principal)?,
    )
}

// RFC 4120 section 5.8.1. `picky-krb` 0.11 does not expose KRB-CRED, so the
// narrow standard types live here and continue to use the same DER engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KrbCredInner {
    pvno: ExplicitContextTag0<IntegerAsn1>,
    msg_type: ExplicitContextTag1<IntegerAsn1>,
    tickets: ExplicitContextTag2<Asn1SequenceOf<Ticket>>,
    enc_part: ExplicitContextTag3<EncryptedData>,
}

type KrbCred = ApplicationTag<KrbCredInner, KRB_CRED_APPLICATION_TAG>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EncKrbCredPartInner {
    ticket_info: ExplicitContextTag0<Asn1SequenceOf<KrbCredInfo>>,
    #[serde(default)]
    nonce: Optional<Option<ExplicitContextTag1<IntegerAsn1>>>,
    #[serde(default)]
    timestamp: Optional<Option<ExplicitContextTag2<GeneralizedTimeAsn1>>>,
    #[serde(default)]
    usec: Optional<Option<ExplicitContextTag3<IntegerAsn1>>>,
    #[serde(default)]
    sender_address: Optional<Option<ExplicitContextTag4<picky_krb::data_types::HostAddress>>>,
    #[serde(default)]
    receiver_address: Optional<Option<ExplicitContextTag5<picky_krb::data_types::HostAddress>>>,
}

type EncKrbCredPart = ApplicationTag<EncKrbCredPartInner, ENC_KRB_CRED_PART_APPLICATION_TAG>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KrbCredInfo {
    key: ExplicitContextTag0<EncryptionKey>,
    #[serde(default)]
    prealm: Optional<Option<ExplicitContextTag1<KerberosStringAsn1>>>,
    #[serde(default)]
    pname: Optional<Option<ExplicitContextTag2<PrincipalName>>>,
    #[serde(default)]
    flags: Optional<Option<ExplicitContextTag3<KerberosFlags>>>,
    #[serde(default)]
    auth_time: Optional<Option<ExplicitContextTag4<GeneralizedTimeAsn1>>>,
    #[serde(default)]
    start_time: Optional<Option<ExplicitContextTag5<GeneralizedTimeAsn1>>>,
    #[serde(default)]
    end_time: Optional<Option<ExplicitContextTag6<GeneralizedTimeAsn1>>>,
    #[serde(default)]
    renew_till: Optional<Option<ExplicitContextTag7<GeneralizedTimeAsn1>>>,
    #[serde(default)]
    srealm: Optional<Option<ExplicitContextTag8<KerberosStringAsn1>>>,
    #[serde(default)]
    sname: Optional<Option<ExplicitContextTag9<PrincipalName>>>,
    #[serde(default)]
    caddr: Optional<Option<ExplicitContextTag10<HostAddresses>>>,
}

fn decode_kirbi(bytes: &[u8]) -> Result<TicketCache, KerberosError> {
    let krb_cred: KrbCred = picky_asn1_der::from_bytes(bytes)
        .map_err(|error| KerberosError::InvalidTicketContainer(error.to_string()))?;
    if integer_as_i32(&krb_cred.0.pvno.0) != Some(KERBEROS_VERSION)
        || integer_as_i32(&krb_cred.0.msg_type.0) != Some(KRB_CRED_MESSAGE_TYPE)
    {
        return Err(KerberosError::InvalidTicketContainer(
            "KRB-CRED version or message type is invalid".to_owned(),
        ));
    }
    if integer_as_i32(&krb_cred.0.enc_part.0.etype.0) != Some(0) {
        return Err(KerberosError::InvalidTicketContainer(
            "encrypted KRB-CRED enc-parts are not supported".to_owned(),
        ));
    }
    let enc_part: EncKrbCredPart = picky_asn1_der::from_bytes(&krb_cred.0.enc_part.0.cipher.0.0)
        .map_err(|error| KerberosError::InvalidTicketContainer(error.to_string()))?;
    let tickets = &krb_cred.0.tickets.0.0;
    let infos = &enc_part.0.ticket_info.0.0;
    if tickets.is_empty() || tickets.len() != infos.len() || tickets.len() > MAX_TICKETS {
        return Err(KerberosError::InvalidTicketContainer(
            "KRB-CRED ticket and ticket-info counts are invalid".to_owned(),
        ));
    }
    let mut parsed = Vec::with_capacity(tickets.len());
    for (ticket, info) in tickets.iter().zip(infos) {
        parsed.push(ticket_from_krb_cred(ticket.clone(), info)?);
    }
    let first = parsed.first().expect("non-empty KRB-CRED");
    Ok(TicketCache {
        primary_principal: first.metadata.client_principal.clone(),
        primary_realm: first.metadata.realm.clone(),
        tickets: parsed,
    })
}

fn ticket_from_krb_cred(
    ticket: Ticket,
    info: &KrbCredInfo,
) -> Result<KerberosTicket, KerberosError> {
    let client_realm = required_optional(&info.prealm, "prealm")?.0.to_string();
    let client_principal = principal_name(required_optional(&info.pname, "pname")?);
    let service_realm = required_optional(&info.srealm, "srealm")?.0.to_string();
    let service_principal = principal_name(required_optional(&info.sname, "sname")?);
    if !ticket
        .0
        .realm
        .0
        .0
        .to_string()
        .eq_ignore_ascii_case(&service_realm)
        || !principal_name(&ticket.0.sname.0).eq_ignore_ascii_case(&service_principal)
    {
        return Err(KerberosError::InvalidTicketContainer(
            "KRB-CRED service metadata does not match the embedded ticket".to_owned(),
        ));
    }
    let key = &info.key.0;
    let encryption_type = integer_as_i32(&key.key_type.0).ok_or_else(|| {
        KerberosError::InvalidTicketContainer("invalid KRB-CRED key type".to_owned())
    })?;
    let issued_at_unix = time_as_unix(required_optional(&info.auth_time, "authtime")?)?;
    let valid_from_unix = info
        .start_time
        .0
        .as_ref()
        .map(|value| time_as_unix(&value.0))
        .transpose()?
        .unwrap_or(issued_at_unix);
    let valid_until_unix = time_as_unix(required_optional(&info.end_time, "endtime")?)?;
    let renewable_until_unix = info
        .renew_till
        .0
        .as_ref()
        .map(|value| time_as_unix(&value.0))
        .transpose()?;
    let ticket_flags = info
        .flags
        .0
        .as_ref()
        .map(|flags| flags_as_u32(&flags.0))
        .transpose()?
        .unwrap_or(0);
    make_ticket(ImportedTicket {
        ticket,
        encryption_type,
        session_key: key.key_value.0.0.clone(),
        client_principal,
        client_realm,
        service_principal,
        issued_at_unix,
        valid_from_unix,
        valid_until_unix,
        renewable_until_unix,
        ticket_flags,
    })
}

fn required_optional<'a, T>(
    value: &'a Optional<Option<T>>,
    field: &str,
) -> Result<&'a T, KerberosError> {
    value.0.as_ref().ok_or_else(|| {
        KerberosError::InvalidTicketContainer(format!("KRB-CRED is missing {field}"))
    })
}

fn time_as_unix(value: &GeneralizedTimeAsn1) -> Result<i64, KerberosError> {
    OffsetDateTime::try_from(value.0.clone())
        .map(|date| date.unix_timestamp())
        .map_err(|error| KerberosError::InvalidTicketContainer(error.to_string()))
}

fn flags_as_u32(flags: &KerberosFlags) -> Result<u32, KerberosError> {
    let bytes = flags.0.as_bytes();
    if bytes.len() != 5 || bytes[0] != 0 {
        return Err(KerberosError::InvalidTicketContainer(
            "KRB-CRED flags are not a 32-bit bit string".to_owned(),
        ));
    }
    Ok(u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]))
}

fn encode_kirbi(cache: &TicketCache) -> Result<Vec<u8>, KerberosError> {
    validate_cache(cache)?;
    let tickets = cache
        .tickets
        .iter()
        .map(|ticket| ticket.ticket.clone())
        .collect::<Vec<_>>();
    let infos = cache
        .tickets
        .iter()
        .map(ticket_to_krb_cred_info)
        .collect::<Result<Vec<_>, _>>()?;
    let enc_part = EncKrbCredPart::from(EncKrbCredPartInner {
        ticket_info: ExplicitContextTag0::from(Asn1SequenceOf::from(infos)),
        nonce: Optional::from(None),
        timestamp: Optional::from(None),
        usec: Optional::from(None),
        sender_address: Optional::from(None),
        receiver_address: Optional::from(None),
    });
    let encoded_part = picky_asn1_der::to_vec(&enc_part)
        .map_err(|error| KerberosError::InvalidTicketContainer(error.to_string()))?;
    let krb_cred = KrbCred::from(KrbCredInner {
        pvno: ExplicitContextTag0::from(integer_i32(KERBEROS_VERSION)),
        msg_type: ExplicitContextTag1::from(integer_i32(KRB_CRED_MESSAGE_TYPE)),
        tickets: ExplicitContextTag2::from(Asn1SequenceOf::from(tickets)),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(integer_i32(0)),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encoded_part)),
        }),
    });
    picky_asn1_der::to_vec(&krb_cred)
        .map_err(|error| KerberosError::InvalidTicketContainer(error.to_string()))
}

fn ticket_to_krb_cred_info(ticket: &KerberosTicket) -> Result<KrbCredInfo, KerberosError> {
    let metadata = ticket.metadata();
    Ok(KrbCredInfo {
        key: ExplicitContextTag0::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(integer_i32(metadata.encryption_type.number())),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(ticket.session_key.clone())),
        }),
        prealm: Optional::from(Some(ExplicitContextTag1::from(kerberos_string(
            &metadata.client_realm,
        )?))),
        pname: Optional::from(Some(ExplicitContextTag2::from(principal_from_string(
            &metadata.client_principal,
            1,
        )?))),
        flags: Optional::from(Some(ExplicitContextTag3::from(BitStringAsn1::from(
            BitString::with_bytes(metadata.ticket_flags.to_be_bytes().to_vec()),
        )))),
        auth_time: Optional::from(Some(ExplicitContextTag4::from(unix_as_time(
            metadata.issued_at_unix,
        )?))),
        start_time: Optional::from(Some(ExplicitContextTag5::from(unix_as_time(
            metadata.valid_from_unix,
        )?))),
        end_time: Optional::from(Some(ExplicitContextTag6::from(unix_as_time(
            metadata.valid_until_unix,
        )?))),
        renew_till: Optional::from(
            metadata
                .renewable_until_unix
                .map(unix_as_time)
                .transpose()?
                .map(ExplicitContextTag7::from),
        ),
        srealm: Optional::from(Some(ExplicitContextTag8::from(kerberos_string(
            &ticket.ticket.0.realm.0.0.to_string(),
        )?))),
        sname: Optional::from(Some(ExplicitContextTag9::from(
            ticket.ticket.0.sname.0.clone(),
        ))),
        caddr: Optional::from(None),
    })
}

fn principal_from_string(value: &str, name_type: i32) -> Result<PrincipalName, KerberosError> {
    let components = split_principal(value)?
        .into_iter()
        .map(|component| kerberos_string(&component))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PrincipalName {
        name_type: ExplicitContextTag0::from(integer_i32(name_type)),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(components)),
    })
}

fn unix_as_time(value: i64) -> Result<GeneralizedTimeAsn1, KerberosError> {
    OffsetDateTime::from_unix_timestamp(value)
        .map(GeneralizedTime::from)
        .map(GeneralizedTimeAsn1::from)
        .map_err(|error| KerberosError::InvalidTicketContainer(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky_asn1::wrapper::ExplicitContextTag1;
    use picky_krb::data_types::TicketInner;

    fn sample_ticket(service: &str, issued: i64) -> KerberosTicket {
        let realm = "EXAMPLE.TEST";
        let service_components = service.split('/').collect::<Vec<_>>();
        let ticket = Ticket::from(TicketInner {
            tkt_vno: ExplicitContextTag0::from(integer_i32(5)),
            realm: ExplicitContextTag1::from(kerberos_string(realm).unwrap()),
            sname: ExplicitContextTag2::from(PrincipalName {
                name_type: ExplicitContextTag0::from(integer_i32(2)),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
                    service_components
                        .iter()
                        .map(|part| kerberos_string(part).unwrap())
                        .collect::<Vec<_>>(),
                )),
            }),
            enc_part: ExplicitContextTag3::from(EncryptedData {
                etype: ExplicitContextTag0::from(integer_i32(18)),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(vec![0x41; 48])),
            }),
        });
        make_ticket(ImportedTicket {
            ticket,
            encryption_type: 18,
            session_key: vec![0x22; 32],
            client_principal: "alice".to_owned(),
            client_realm: realm.to_owned(),
            service_principal: service.to_owned(),
            issued_at_unix: issued,
            valid_from_unix: issued,
            valid_until_unix: issued + 3_600,
            renewable_until_unix: Some(issued + 7_200),
            ticket_flags: 0x40e1_0000,
        })
        .unwrap()
    }

    #[test]
    fn ccache_and_kirbi_round_trip_without_exposing_keys() {
        let mut cache = TicketCache::new(sample_ticket("krbtgt/EXAMPLE.TEST", 1_700_000_000));
        cache
            .push(sample_ticket("ldap/dc01.example.test", 1_700_000_001))
            .unwrap();
        for (format, encoded) in [
            (TicketFileFormat::CcacheV4, encode_ccache(&cache).unwrap()),
            (TicketFileFormat::Kirbi, encode_kirbi(&cache).unwrap()),
        ] {
            let decoded = match format {
                TicketFileFormat::CcacheV4 => decode_ccache(&encoded).unwrap(),
                TicketFileFormat::Kirbi => decode_kirbi(&encoded).unwrap(),
            };
            assert_eq!(decoded.metadata().count(), 2);
            assert!(!format!("{decoded:?}").contains("22222222"));
            let selected = decoded
                .select(&TicketSelector {
                    realm: Some("example.test".to_owned()),
                    valid_at_unix: Some(1_700_000_100),
                    ..TicketSelector::default()
                })
                .unwrap();
            assert_eq!(selected.metadata().service_principal, "krbtgt/EXAMPLE.TEST");
        }
    }

    #[test]
    fn exact_service_selection_prefers_the_newest_ticket() {
        let mut cache = TicketCache::new(sample_ticket("ldap/dc01.example.test", 1_700_000_000));
        cache
            .push(sample_ticket("ldap/dc01.example.test", 1_700_000_100))
            .unwrap();
        let selected = cache
            .select(&TicketSelector {
                realm: Some("EXAMPLE.TEST".to_owned()),
                service_principal: Some("LDAP/DC01.EXAMPLE.TEST".to_owned()),
                valid_at_unix: Some(1_700_000_200),
                ..TicketSelector::default()
            })
            .unwrap();
        assert_eq!(selected.metadata().issued_at_unix, 1_700_000_100);
    }

    #[test]
    fn selection_rejects_expired_and_approximate_matches() {
        let cache = TicketCache::new(sample_ticket("ldap/dc01.example.test", 1_700_000_000));
        assert!(matches!(
            cache.select(&TicketSelector {
                service_principal: Some("ldap/dc01".to_owned()),
                valid_at_unix: Some(1_700_000_100),
                ..TicketSelector::default()
            }),
            Err(KerberosError::TicketNotFound)
        ));
        assert!(matches!(
            cache.select(&TicketSelector {
                service_principal: Some("ldap/dc01.example.test".to_owned()),
                valid_at_unix: Some(1_700_004_000),
                ..TicketSelector::default()
            }),
            Err(KerberosError::TicketNotFound)
        ));
    }
}
