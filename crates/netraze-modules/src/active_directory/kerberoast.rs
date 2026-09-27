use crate::StaticModuleFactory;
use netraze_core::ModuleCategory;

pub fn factory() -> StaticModuleFactory {
    StaticModuleFactory::new(
        "kerberoast",
        "Request service tickets for LDAP-discovered or explicit SPNs and export compatible ticket material on request.",
        &["ldap", "kerberos"],
        ModuleCategory::CredentialAccess,
    )
}
