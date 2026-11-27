mod cgroup;
mod collector;
mod uplink;

use anyhow::{bail, Context, Result};
use rprobe_common::secret::{read_secret_file, valid_token};
use std::path::PathBuf;
use std::time::Duration;
use uplink::{run, AgentConfig};

fn main() {
    if let Err(error) = run_cli() {
        eprintln!("rprobe-agent: {error:#}");
        std::process::exit(1);
    }
}

fn run_cli() -> Result<()> {
    let config = parse_args()?;
    collector::require_procfs()?;
    cgroup::validate_scope()?;
    run(config)
}

fn parse_args() -> Result<AgentConfig> {
    let mut server = None;
    let mut id: Option<String> = None;
    let mut token_file = None;
    let mut group = None;
    let mut interval = 5_u64;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" {
            println!("Usage: rprobe-agent --server <https://host> --id <agent-id> --token-file <0600-file> [--group <name>] [--interval <1-60 seconds>]");
            std::process::exit(0);
        }
        if flag == "--token" {
            bail!("--token is disabled because process arguments expose secrets; use --token-file");
        }
        let value = args
            .next()
            .with_context(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--server" => server = Some(value),
            "--id" => id = Some(value),
            "--token-file" => token_file = Some(PathBuf::from(value)),
            "--group" => group = Some(value),
            "--interval" => interval = value.parse().context("--interval must be an integer")?,
            _ => bail!("unknown argument"),
        }
    }
    if !(1..=60).contains(&interval) {
        bail!("--interval must be between 1 and 60 seconds");
    }
    let server = validate_server_url(&server.context("--server is required")?)?;
    let token = read_secret_file(&token_file.context("--token-file is required")?, 1024)
        .context("read agent credential")?
        .trim()
        .to_owned();
    if !valid_token(&token) {
        bail!("token must contain 16-256 visible ASCII characters");
    }
    let agent_id = id.context("--id is required")?;
    if agent_id.is_empty()
        || agent_id.len() > 100
        || !agent_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("--id must be 1-100 ASCII letters, digits, '.', '_' or '-'");
    }
    if group
        .as_ref()
        .is_some_and(|name| name.len() > 64 || name.chars().any(char::is_control))
    {
        bail!("--group must be at most 64 bytes without control characters");
    }
    Ok(AgentConfig {
        server,
        agent_id,
        token,
        group,
        interval: Duration::from_secs(interval),
    })
}

fn validate_server_url(server: &str) -> Result<String> {
    let url = url::Url::parse(server).context("invalid server URL")?;
    if url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("server URL requires a host and must not contain credentials, a query or a fragment");
    }
    let loopback = match url.host() {
        Some(url::Host::Domain(name)) => name == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        bail!("server must use HTTPS; HTTP is allowed only for loopback development");
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

#[cfg(test)]
mod tests {
    use super::validate_server_url;
    #[test]
    fn permits_https_and_loopback_http_only() {
        for url in [
            "https://monitor.example:443",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(validate_server_url(url).is_ok());
        }
        for url in [
            "http://monitor.example",
            "http://localhost:80@evil.example",
            "http://[::1]@evil.example",
            "https://user:secret@monitor.example",
            "https://monitor.example?token=secret",
            "https://monitor.example/#fragment",
        ] {
            assert!(validate_server_url(url).is_err());
        }
    }
}
