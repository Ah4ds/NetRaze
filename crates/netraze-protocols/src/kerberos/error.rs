use std::io;

/// Errors surfaced by the Kerberos transport, codecs, and exchanges.
#[derive(Debug, thiserror::Error)]
pub enum KerberosError {
    #[error("invalid Kerberos endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("Kerberos connection to {endpoint} timed out")]
    ConnectTimeout { endpoint: String },
    #[error("Kerberos operation against {endpoint} timed out")]
    OperationTimeout { endpoint: String },
    #[error("Kerberos I/O against {endpoint} failed: {source}")]
    Io {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("Kerberos ticket file {path} exceeds the {limit}-byte limit")]
    TicketFileTooLarge { path: String, limit: usize },
    #[error("Kerberos ticket file already exists: {0}")]
    TicketFileExists(String),
    #[error("invalid Kerberos ticket container: {0}")]
    InvalidTicketContainer(String),
    #[error("no Kerberos ticket matched the requested selector")]
    TicketNotFound,
    #[error("multiple Kerberos tickets matched the requested selector")]
    AmbiguousTicket,
    #[error("Kerberos referral to realm {realm} is not allowlisted")]
    ReferralDenied { realm: String },
    #[error("Kerberos referral realm {realm} has no configured KDC endpoint")]
    MissingReferralEndpoint { realm: String },
    #[error("Kerberos referral loop detected at realm {realm}")]
    ReferralLoop { realm: String },
    #[error("Kerberos referral chain exceeded the {limit}-hop limit")]
    ReferralLimit { limit: usize },
    #[error("Kerberos TCP frame announced an empty payload")]
    EmptyFrame,
    #[error("Kerberos TCP response is {announced} bytes; limit is {limit} bytes")]
    ResponseTooLarge { announced: usize, limit: usize },
    #[error("invalid Kerberos DER message: {0}")]
    InvalidMessage(String),
    #[error("Kerberos cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("Kerberos key for {encryption_type} is {actual} bytes; expected {expected}")]
    InvalidKeyLength {
        encryption_type: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("Kerberos ciphertext for {encryption_type} is too short: {actual} bytes")]
    CiphertextTooShort {
        encryption_type: &'static str,
        actual: usize,
    },
    #[error("Kerberos ciphertext integrity check failed")]
    Integrity,
    #[error("invalid Kerberos GSS token: {0}")]
    InvalidGssToken(String),
    #[error("Kerberos GSS sequence mismatch: expected {expected}, received {actual}")]
    GssSequence { expected: u64, actual: u64 },
    #[error("KDC returned error {code}{message}")]
    Kdc {
        code: i32,
        message: String,
        data: Option<Vec<u8>>,
    },
    #[error("unexpected Kerberos reply: expected {expected}, received message type {actual}")]
    UnexpectedReply { expected: &'static str, actual: i32 },
}

impl KerberosError {
    pub(crate) fn io(endpoint: &str, source: io::Error) -> Self {
        Self::Io {
            endpoint: endpoint.to_owned(),
            source,
        }
    }
}
