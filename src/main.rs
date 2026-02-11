use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::process::Command;

const KEYCHAIN_SERVICE: &str = "com.tunnel-cli.cloudflare";

// ─── CLI Definition ──────────────────────────────────────────

#[derive(Parser)]
#[command(name = "talpa", about = "Cloudflare Tunnel route manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initial setup — store credentials in macOS Keychain
    Setup,
    /// Dig a new tunnel route + CNAME record
    Dig {
        /// Hostname (e.g. app.example.com)
        hostname: String,
        /// Local service (e.g. http://localhost:8080)
        service: String,
    },
    /// Plug (remove) a tunnel route + CNAME record
    Plug {
        /// Hostname to remove
        hostname: String,
    },
    /// List all active routes
    List,
}

// ─── macOS Keychain ──────────────────────────────────────────

fn keychain_set(account: &str, password: &str) -> Result<()> {
    let _ = Command::new("security")
        .args(["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account])
        .output();

    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-s", KEYCHAIN_SERVICE,
            "-a", account,
            "-w", password,
            "-U",
        ])
        .output()
        .context("Failed to run `security` command")?;

    if !output.status.success() {
        bail!(
            "Keychain write failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn keychain_get(account: &str) -> Result<String> {
    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-s", KEYCHAIN_SERVICE,
            "-a", account,
            "-w",
        ])
        .output()
        .context("Failed to run `security` command")?;

    if !output.status.success() {
        bail!(
            "Keychain read failed for '{}'. Run `tunnel setup` first.",
            account
        );
    }

    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn read_input(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn read_secret(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    let output = Command::new("stty").arg("-echo").output();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if output.is_ok() {
        let _ = Command::new("stty").arg("echo").output();
        eprintln!();
    }
    Ok(input.trim().to_string())
}

// ─── Credentials ─────────────────────────────────────────────

struct Credentials {
    account_id: String,
    zone_id: String,
    tunnel_id: String,
    api_token: String,
}

impl Credentials {
    fn from_keychain() -> Result<Self> {
        Ok(Self {
            account_id: keychain_get("account_id")
                .context("Run `tunnel setup` to configure credentials")?,
            zone_id: keychain_get("zone_id")
                .context("Run `tunnel setup` to configure credentials")?,
            tunnel_id: keychain_get("tunnel_id")
                .context("Run `tunnel setup` to configure credentials")?,
            api_token: keychain_get("api_token")
                .context("Run `tunnel setup` to configure credentials")?,
        })
    }
}

// ─── Cloudflare API Types ────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CfResponse<T> {
    success: bool,
    errors: Vec<CfError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CfError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IngressRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    service: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "originRequest")]
    origin_request: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct TunnelConfigResult {
    config: TunnelConfigInner,
}

#[derive(Debug, Serialize, Deserialize)]
struct TunnelConfigInner {
    ingress: Vec<IngressRule>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct TunnelConfigUpdate {
    config: TunnelConfigInner,
}

// ─── Cloudflare API Client ───────────────────────────────────

struct CfClient {
    client: reqwest::blocking::Client,
    account_id: String,
    zone_id: String,
    tunnel_id: String,
    api_token: String,
}

impl CfClient {
    fn new(creds: &Credentials) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            account_id: creds.account_id.clone(),
            zone_id: creds.zone_id.clone(),
            tunnel_id: creds.tunnel_id.clone(),
            api_token: creds.api_token.clone(),
        }
    }

    fn dns_url(&self) -> String {
        format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        )
    }

    fn tunnel_config_url(&self) -> String {
        format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/cfd_tunnel/{}/configurations",
            self.account_id, self.tunnel_id
        )
    }

    fn verify_connection(&self) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}",
            self.zone_id
        );
        let resp: CfResponse<serde_json::Value> = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()?
            .json()?;

        if !resp.success {
            let msgs: Vec<_> = resp.errors.iter().map(|e| e.message.as_str()).collect();
            bail!("{}", msgs.join(", "));
        }
        Ok(())
    }

    fn get_tunnel_config(&self) -> Result<TunnelConfigInner> {
        let resp: CfResponse<TunnelConfigResult> = self
            .client
            .get(&self.tunnel_config_url())
            .bearer_auth(&self.api_token)
            .send()?
            .json()?;

        if !resp.success {
            let msgs: Vec<_> = resp.errors.iter().map(|e| e.message.as_str()).collect();
            bail!("Failed to get tunnel config: {}", msgs.join(", "));
        }

        Ok(resp.result.context("No config returned")?.config)
    }

    fn put_tunnel_config(&self, config: TunnelConfigInner) -> Result<()> {
        let resp: CfResponse<serde_json::Value> = self
            .client
            .put(&self.tunnel_config_url())
            .bearer_auth(&self.api_token)
            .json(&TunnelConfigUpdate { config })
            .send()?
            .json()?;

        if !resp.success {
            let msgs: Vec<_> = resp.errors.iter().map(|e| e.message.as_str()).collect();
            bail!("Failed to update tunnel config: {}", msgs.join(", "));
        }
        Ok(())
    }

    fn create_cname(&self, hostname: &str) -> Result<()> {
        let resp: CfResponse<serde_json::Value> = self
            .client
            .post(&self.dns_url())
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({
                "type": "CNAME",
                "name": hostname,
                "content": format!("{}.cfargotunnel.com", self.tunnel_id),
                "proxied": true
            }))
            .send()?
            .json()?;

        if !resp.success {
            let msgs: Vec<_> = resp.errors.iter().map(|e| e.message.as_str()).collect();
            bail!("CNAME creation failed: {}", msgs.join(", "));
        }
        Ok(())
    }

    fn find_record_id(&self, hostname: &str) -> Result<Option<String>> {
        let url = format!("{}?type=CNAME&name={}", self.dns_url(), hostname);
        let resp: CfResponse<Vec<DnsRecord>> = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()?
            .json()?;

        Ok(resp
            .result
            .as_ref()
            .and_then(|v| v.first())
            .map(|r| r.id.clone()))
    }

    fn delete_record(&self, record_id: &str) -> Result<()> {
        let url = format!("{}/{}", self.dns_url(), record_id);
        self.client
            .delete(&url)
            .bearer_auth(&self.api_token)
            .send()?;
        Ok(())
    }
}

// ─── Commands ────────────────────────────────────────────────

fn cmd_setup() -> Result<()> {
    println!();
    println!("{}", " 🔧 Tunnel CLI Setup ".bold().on_blue().white());
    println!();
    println!("Credentials will be stored in your macOS Keychain");
    println!("under the service: {}", KEYCHAIN_SERVICE.dimmed());
    println!();

    let account_id = read_input(&format!("  {} Account ID: ", "→".dimmed()))?;
    if account_id.is_empty() {
        bail!("Account ID cannot be empty");
    }

    let zone_id = read_input(&format!("  {} Zone ID: ", "→".dimmed()))?;
    if zone_id.is_empty() {
        bail!("Zone ID cannot be empty");
    }

    let tunnel_id = read_input(&format!("  {} Tunnel ID: ", "→".dimmed()))?;
    if tunnel_id.is_empty() {
        bail!("Tunnel ID cannot be empty");
    }

    let api_token = read_secret(&format!("  {} API Token (hidden): ", "→".dimmed()))?;
    if api_token.is_empty() {
        bail!("API Token cannot be empty");
    }

    print!("  {} Saving to Keychain...", "→".dimmed());
    keychain_set("account_id", &account_id)?;
    keychain_set("zone_id", &zone_id)?;
    keychain_set("tunnel_id", &tunnel_id)?;
    keychain_set("api_token", &api_token)?;
    println!(" {}", "ok".green());

    print!("  {} Verifying...", "→".dimmed());
    let creds = Credentials::from_keychain()?;
    let cf = CfClient::new(&creds);
    match cf.verify_connection() {
        Ok(()) => println!(" {}", "ok".green()),
        Err(e) => {
            println!(" {}", "failed".red());
            println!("    {e}");
            println!("    Check your credentials and try again");
            return Ok(());
        }
    }

    println!();
    println!("{} Setup complete!", "✅".green());
    println!();
    println!("  You can now use:");
    println!(
        "    {} talpa dig app.example.com http://localhost:8080",
        "$".dimmed()
    );
    println!("    {} talpa list", "$".dimmed());
    println!("    {} talpa plug app.example.com", "$".dimmed());
    println!();

    Ok(())
}

fn cmd_add(hostname: &str, service: &str) -> Result<()> {
    let creds = Credentials::from_keychain()?;
    let cf = CfClient::new(&creds);

    print!("  {} Fetching tunnel config...", "→".dimmed());
    let mut config = cf.get_tunnel_config()?;
    println!(" {}", "ok".green());

    if config
        .ingress
        .iter()
        .any(|r| r.hostname.as_deref() == Some(hostname))
    {
        bail!("{hostname} already exists in tunnel config");
    }

    let catch_all = config.ingress.pop().context("No catch-all rule found")?;
    config.ingress.push(IngressRule {
        hostname: Some(hostname.to_string()),
        service: service.to_string(),
        origin_request: None,
    });
    config.ingress.push(catch_all);

    print!("  {} Updating tunnel config...", "→".dimmed());
    cf.put_tunnel_config(config)?;
    println!(" {}", "ok".green());

    print!("  {} Creating CNAME...", "→".dimmed());
    match cf.create_cname(hostname) {
        Ok(()) => println!(" {}", "ok".green()),
        Err(e) => println!(" {} {e}", "⚠".yellow()),
    }

    println!("\n{} {} → {}", "✅".green(), hostname.bold(), service);
    Ok(())
}

fn cmd_remove(hostname: &str) -> Result<()> {
    let creds = Credentials::from_keychain()?;
    let cf = CfClient::new(&creds);

    print!("  {} Fetching tunnel config...", "→".dimmed());
    let mut config = cf.get_tunnel_config()?;
    println!(" {}", "ok".green());

    let before = config.ingress.len();
    config
        .ingress
        .retain(|r| r.hostname.as_deref() != Some(hostname));

    if config.ingress.len() == before {
        bail!("{hostname} not found in tunnel config");
    }

    print!("  {} Updating tunnel config...", "→".dimmed());
    cf.put_tunnel_config(config)?;
    println!(" {}", "ok".green());

    print!("  {} Removing CNAME...", "→".dimmed());
    match cf.find_record_id(hostname)? {
        Some(id) => {
            cf.delete_record(&id)?;
            println!(" {}", "ok".green());
        }
        None => println!(" {} not found (skipped)", "⚠".yellow()),
    }

    println!("\n{} Removed: {}", "🗑️".normal(), hostname.bold());
    Ok(())
}

fn cmd_list() -> Result<()> {
    let creds = Credentials::from_keychain()?;
    let cf = CfClient::new(&creds);

    let config = cf.get_tunnel_config()?;

    println!();
    println!("{}", " 📋 Tunnel Routes ".bold().on_blue().white());
    println!("  Tunnel: {}", creds.tunnel_id.dimmed());
    println!();

    let mut count = 0;
    for rule in &config.ingress {
        match &rule.hostname {
            Some(host) => {
                println!("  {:<40} → {}", host.cyan(), rule.service.green());
                count += 1;
            }
            None => {
                println!(
                    "  {:<40} → {}",
                    "* (catch-all)".dimmed(),
                    rule.service.dimmed()
                );
            }
        }
    }

    println!();
    println!("  Total: {} route(s)", count.to_string().bold());
    println!();
    Ok(())
}

// ─── Main ────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup => cmd_setup(),
        Commands::Dig { hostname, service } => cmd_add(&hostname, &service),
        Commands::Plug { hostname } => cmd_remove(&hostname),
        Commands::List => cmd_list(),
    }
}
