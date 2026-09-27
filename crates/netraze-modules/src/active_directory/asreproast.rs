use crate::StaticModuleFactory;
use netraze_core::ModuleCategory;

pub fn factory() -> StaticModuleFactory {
    StaticModuleFactory::new(
        "asreproast",
        "Find AD users without Kerberos pre-authentication and export compatible AS-REP material on request.",
        &["ldap", "kerberos"],
        ModuleCategory::CredentialAccess,
    )
}
