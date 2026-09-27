mod support;

use netraze_protocols::{
    kerberos::{
        KerberosClient, KerberosClientConfig, KerberosCredential, KerberosEncryptionType,
        targets_from_inventory,
    },
    ldap::{self, LdapClientConfig},
    ntlm::{NtlmCredential, nt_hash_from_password},
};
use picky_krb::constants::error_codes::KDC_ERR_ETYPE_NOSUPP;

const KDC_ENDPOINT: &str = "127.0.0.1:1088";
const LDAP_ENDPOINT: &str = "127.0.0.1:1389";
const TEST_REALM: &str = "NETRAZE.TEST";
const TEST_DOMAIN: &str = "NETRAZE";
const TEST_USER: &str = "alice";

fn test_password() -> String {
    support::required_env("NETRAZE_SAMBA_AD_PASSWORD")
}

fn client() -> KerberosClient {
    KerberosClient::connect(KerberosClientConfig::new(KDC_ENDPOINT, TEST_REALM))
        .expect("fixed local Samba AD KDC configuration is invalid")
}

#[tokio::test]
#[ignore = "requires the local tests/samba-ad Docker harness"]
async fn password_preauth_acquires_and_validates_an_aes_tgt() {
    let tgt = client()
        .request_tgt(TEST_USER, &KerberosCredential::Password(test_password()))
        .await
        .expect("password AS exchange against the local Samba AD KDC failed");
    assert_eq!(tgt.client_principal(), TEST_USER);
    assert_eq!(tgt.realm(), TEST_REALM);
    assert!(matches!(
        tgt.session_encryption_type(),
        KerberosEncryptionType::Aes128CtsHmacSha196 | KerberosEncryptionType::Aes256CtsHmacSha196
    ));
    assert!(tgt.valid_until_unix() > tgt.valid_from_unix());
}

#[tokio::test]
#[ignore = "requires the local tests/samba-ad Docker harness"]
async fn nt_hash_preauth_reports_the_fixture_kdc_rc4_policy() {
    let credential = KerberosCredential::NtHash(nt_hash_from_password(&test_password()));
    let error = client()
        .request_tgt(TEST_USER, &credential)
        .await
        .expect_err("the pinned MIT-backed Samba KDC unexpectedly accepted RC4");
    assert!(
        matches!(
            error,
            netraze_protocols::kerberos::KerberosError::Kdc { code, .. }
                if code == KDC_ERR_ETYPE_NOSUPP as i32
        ),
        "unexpected NT-hash policy result: {error}"
    );
}

#[tokio::test]
#[ignore = "requires the local tests/samba-ad Docker harness"]
async fn ldap_candidates_produce_as_rep_and_service_ticket_findings() {
    let password = test_password();
    let inventory = ldap::inventory(
        LdapClientConfig::new(LDAP_ENDPOINT),
        TEST_USER,
        TEST_DOMAIN,
        NtlmCredential::Password(password.clone()),
    )
    .await
    .expect("LDAP discovery against the local Samba AD fixture failed");
    let targets = targets_from_inventory(&inventory);
    assert!(
        targets
            .as_rep_principals
            .iter()
            .any(|principal| principal.eq_ignore_ascii_case("asrep")),
        "pre-auth-disabled fixture account was not discovered"
    );
    let service_target = targets
        .service_principals
        .iter()
        .find(|target| {
            target
                .service_principal_name
                .eq_ignore_ascii_case("HTTP/web.netraze.test")
        })
        .cloned()
        .expect("service-account SPN fixture was not discovered");

    let client = client();
    let as_rep = client
        .assess_as_rep(&["asrep".to_owned()])
        .await
        .expect("AS-REP assessment failed");
    assert_eq!(as_rep.findings.len(), 1);
    assert_eq!(as_rep.artifacts.len(), 1);
    assert!(
        as_rep.artifacts[0]
            .hashcat_line()
            .starts_with("$krb5asrep$")
    );

    let tgt = client
        .request_tgt(TEST_USER, &KerberosCredential::Password(password))
        .await
        .expect("TGT acquisition for service-ticket assessment failed");
    let service = client
        .assess_spns(&tgt, &[service_target])
        .await
        .expect("service-ticket assessment failed");
    assert_eq!(
        service.findings.len(),
        1,
        "service-ticket target errors: {:?}",
        service.errors
    );
    assert_eq!(service.artifacts.len(), 1);
    assert!(service.artifacts[0].hashcat_line().starts_with("$krb5tgs$"));
}

#[tokio::test]
#[ignore = "requires the local tests/samba-ad Docker harness"]
async fn wrong_password_does_not_produce_a_tgt() {
    let wrong = format!("{}-invalid", test_password());
    assert!(
        client()
            .request_tgt(TEST_USER, &KerberosCredential::Password(wrong))
            .await
            .is_err()
    );
}
