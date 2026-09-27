//! Protocol-neutral Kerberos assessment results.
//!
//! These records intentionally exclude ticket ciphertext and Hashcat material
//! so they can be shown and persisted by frontends without silently storing
//! credential-equivalent artifacts.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KerberosFindingKind {
    AsRepRoast,
    Kerberoast,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KerberosFinding {
    pub kind: KerberosFindingKind,
    pub principal: String,
    pub service_principal_name: Option<String>,
    pub encryption_type: i32,
    pub hashcat_mode: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KerberosTargetError {
    pub target: String,
    pub message: String,
}
