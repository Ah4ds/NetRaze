mod support;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use netraze_protocols::{
    kerberos::{
        KdcTransportPolicy, KerberosClient, KerberosClientConfig, KerberosCredential,
        KerberosEncryptionType, KerberosTicket, TicketCache, TicketFileFormat, TicketSelector,
        export_ticket_file, import_ticket_file, targets_from_inventory,
    },
    ldap::{self, LdapClient, LdapClientConfig},
    ntlm::{NtlmCredential, nt_hash_from_password},
    smb::SmbClient,
};
use picky_krb::constants::error_codes::KDC_ERR_ETYPE_NOSUPP;

const KDC_ENDPOINT: &str = "127.0.0.1:1088";
const LDAP_ENDPOINT: &str = "127.0.0.1:1389";
const TEST_REALM: &str = "NETRAZE.TEST";
const TEST_DOMAIN: &str = "NETRAZE";
const TEST_USER: &str = "alice";
const SERVICE_HOST: &str = "dc1.netraze.test";
const SMB_ENDPOINT: &str = "127.0.0.1:2445";

fn test_password() -> String {
    support::required_env("NETRAZE_SAMBA_AD_PASSWORD")
}

fn client() -> KerberosClient {
    KerberosClient::connect(KerberosClientConfig::new(KDC_ENDPOINT, TEST_REALM))
        .expect("fixed local Samba AD KDC configuration is invalid")
}

struct TicketFiles(Vec<PathBuf>);

impl TicketFiles {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn path(&mut self, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "netraze-samba-ad-ticket-{}-{nonce}.{extension}",
            std::process::id()
        ));
        self.0.push(path.clone());
        path
    }
}

impl Drop for TicketFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
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
async fn udp_only_transport_acquires_and_validates_a_tgt() {
    let mut config = KerberosClientConfig::new(KDC_ENDPOINT, TEST_REALM);
    config.transport_policy = KdcTransportPolicy::UdpOnly;
    let udp_client = KerberosClient::connect(config).expect("UDP KDC configuration is invalid");
    let tgt = udp_client
        .request_tgt(TEST_USER, &KerberosCredential::Password(test_password()))
        .await
        .expect("UDP AS exchange against the local Samba AD KDC failed");
    assert_eq!(tgt.client_principal(), TEST_USER);
    assert_eq!(tgt.realm(), TEST_REALM);
}

#[tokio::test]
#[ignore = "requires the local tests/samba-ad Docker harness"]
async fn imported_ccache_and_kirbi_authenticate_ldap_and_smb_sessions() {
    let client = client();
    let tgt = client
        .request_tgt(TEST_USER, &KerberosCredential::Password(test_password()))
        .await
        .expect("TGT acquisition for ticket-session test failed");
    let ldap_spn = format!("ldap/{SERVICE_HOST}");
    let cifs_spn = format!("cifs/{SERVICE_HOST}");
    let ldap_ticket = client
        .request_service_ticket(&tgt, &ldap_spn)
        .await
        .expect("LDAP service-ticket acquisition failed");
    let cifs_ticket = client
        .request_service_ticket(&tgt, &cifs_spn)
        .await
        .expect("SMB service-ticket acquisition failed");

    let mut cache = TicketCache::from_tgt(&tgt);
    cache
        .push(KerberosTicket::from_service(&ldap_ticket))
        .expect("LDAP ticket could not be cached");
    cache
        .push(KerberosTicket::from_service(&cifs_ticket))
        .expect("SMB ticket could not be cached");

    let mut files = TicketFiles::new();
    let ccache_path = files.path("ccache");
    let kirbi_path = files.path("kirbi");
    export_ticket_file(&ccache_path, &cache, TicketFileFormat::CcacheV4, false)
        .expect("ccache export failed");
    export_ticket_file(&kirbi_path, &cache, TicketFileFormat::Kirbi, false)
        .expect("kirbi export failed");

    let imported_ccache = import_ticket_file(&ccache_path).expect("ccache import failed");
    let imported_ldap = imported_ccache
        .select(&TicketSelector {
            service_principal: Some(ldap_spn),
            ..TicketSelector::default()
        })
        .and_then(KerberosTicket::to_service_ticket)
        .expect("exact LDAP service-ticket selection failed");
    let mut ldap_client = LdapClient::connect(LdapClientConfig::new(LDAP_ENDPOINT))
        .await
        .expect("LDAP connection failed");
    ldap_client
        .bind_kerberos(SERVICE_HOST, &imported_ldap)
        .await
        .expect("imported ccache did not authenticate LDAP");
    let root_dse = ldap_client
        .root_dse()
        .await
        .expect("Kerberos-authenticated RootDSE search failed");
    assert_eq!(
        root_dse.first_utf8("defaultNamingContext"),
        Some("DC=netraze,DC=test")
    );
    ldap_client.unbind().await.expect("LDAP unbind failed");

    let imported_kirbi = import_ticket_file(&kirbi_path).expect("kirbi import failed");
    let imported_cifs = imported_kirbi
        .select(&TicketSelector {
            service_principal: Some(cifs_spn),
            ..TicketSelector::default()
        })
        .and_then(KerberosTicket::to_service_ticket)
        .expect("exact CIFS service-ticket selection failed");
    let mut smb_client = SmbClient::new(SMB_ENDPOINT).with_kerberos(SERVICE_HOST, imported_cifs);
    smb_client
        .connect()
        .await
        .expect("imported kirbi did not authenticate SMB");
    let server = smb_client
        .server_info()
        .await
        .expect("Kerberos-authenticated SRVSVC query failed");
    assert_eq!(server.name.to_ascii_uppercase(), "DC1");
    smb_client.disconnect().await;
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
