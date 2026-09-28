//! Pure-Rust Kerberos v5 client foundations.
//!
//! KDC requests use the TCP record marking defined by RFC 4120 section 7.2.2:
//! a four-byte network-order length followed by one DER-encoded Kerberos
//! message. Higher-level AS and TGS exchanges live above this bounded transport
//! and never expose `picky-krb` representations to callers.

mod assessment;
mod client;
mod crypto;
mod error;
mod ticket;
mod transport;

pub use crypto::{KerberosEncryptionType, decrypt, derive_password_key, encrypt};
pub use error::KerberosError;
pub use ticket::{
    KerberosTicket, KerberosTicketKind, TicketCache, TicketFileFormat, TicketMetadata,
    TicketSelector, export_ticket_file, import_ticket_file,
};
pub use transport::{KdcTransport, KdcTransportConfig, KdcTransportPolicy};

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
pub use assessment::{
    KerberosAssessmentOutcome, KerberosAssessmentTargets, RoastArtifact, ServicePrincipalTarget,
    ServiceTicket, export_roast_artifacts, targets_from_inventory,
};
pub use client::{
    KerberosClient, KerberosClientConfig, KerberosCredential, ReferralPolicy, TicketGrantingTicket,
};
