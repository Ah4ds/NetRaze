//! Pure-Rust Kerberos v5 client foundations.
//!
//! KDC requests use the TCP record marking defined by RFC 4120 section 7.2.2:
//! a four-byte network-order length followed by one DER-encoded Kerberos
//! message. Higher-level AS and TGS exchanges live above this bounded transport
//! and never expose `picky-krb` representations to callers.

mod crypto;
mod error;
mod transport;

pub use crypto::{KerberosEncryptionType, decrypt, derive_password_key, encrypt};
pub use error::KerberosError;
pub use transport::{KdcTransport, KdcTransportConfig};

use netraze_core::Capability;

use crate::StaticProtocolFactory;

#[must_use]
pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "kerberos",
        "Kerberos",
        88,
        vec![
            Capability::Authentication,
            Capability::Enumeration,
            Capability::ModuleHooks,
        ],
    )
}
