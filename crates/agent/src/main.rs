mod cgroup;
mod collector;
mod uplink;

use anyhow::{bail, Context, Result};
use collector::require_procfs;
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
    require_procfs()?;
    run(config)
}

fn parse_args() -> Result<AgentConfig> {
    let mut server = None;
    let mut id = None;
    let mut token = None;
    let mut group = None;
    let mut interval = 5_u64;
    let mut args = std::env::args().skip(1);

    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" {
            println!("Usage: rprobe-agent --server <https://host> --id <agent-id> --token <token> [--group <name>] [--interval <seconds>]");
            std::process::exit(0);
        }
        let value = args
            .next()
            .with_context(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--server" => server = Some(value),
            "--id" => id = Some(value),
            "--token" => token = Some(value),
            "--group" => group = Some(value),
            "--interval" => interval = value.parse().context("--interval must be an integer")?,
            _ => bail!("unknown argument: {flag}"),
        }
    }

    if interval < 1 {
        bail!("--interval must be at least 1 second");
    }
    let server = server.context("--server is required")?;
    validate_server_url(&server)?;

    Ok(AgentConfig {
        server: server.trim_end_matches('/').to_owned(),
        agent_id: id.context("--id is required")?,
        token: token.context("--token is required")?,
        group,
        interval: Duration::from_secs(interval),
    })
}

fn validate_server_url(server: &str) -> Result<()> {
    if server
        .strip_prefix("https://")
        .is_some_and(|authority| !authority.split('/').next().unwrap_or_default().is_empty())
    {
        return Ok(());
    }
    if let Some(authority) = server.strip_prefix("http://") {
        let authority = authority.split('/').next().unwrap_or_default();
        let hostname = if authority.starts_with('[') {
            authority.split(']').next().map(|host| format!("{host}]"))
        } else {
            authority.split(':').next().map(str::to_owned)
        }
        .unwrap_or_default();
        if matches!(hostname.as_str(), "localhost" | "127.0.0.1" | "[::1]") {
            return Ok(());
        }
    }
    bail!("server must use HTTPS; plain HTTP is allowed only for localhost development")
}

#[cfg(test)]
mod tests {
    use super::validate_server_url;

    #[test]
    fn permits_https_and_local_http_only() {
        assert!(validate_server_url("https://monitor.example:443").is_ok());
        assert!(validate_server_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_server_url("http://[::1]:8080").is_ok());
        assert!(validate_server_url("http://monitor.example").is_err());
    }
}
