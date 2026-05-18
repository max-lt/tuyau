use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use tuyau_client::{ClientConfig, IngressRule, TunnelClient};
use tuyau_server::{ServerConfig, TunnelServer};

const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

#[derive(Parser, Debug)]
#[command(name = "tuyau", version, about = "Tuyau QUIC tunnel CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the tunnel server.
    Server {
        /// Path to server.toml.
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the tunnel client.
    Client(ClientArgs),
}

/// Client config sources. Either `--config <path>` (TOML, for users who want
/// a single declarative file) OR the individual flags/env vars below (designed
/// for Docker/Compose/k8s).
#[derive(clap::Args, Debug)]
struct ClientArgs {
    /// Path to client.toml. Mutually exclusive with the per-field flags.
    #[arg(long, conflicts_with_all = ["server", "fingerprint", "token_file", "name", "ingress"])]
    config: Option<PathBuf>,

    /// host:port of the tuyau-server. Env: TUYAU_SERVER.
    #[arg(long)]
    server: Option<String>,

    /// Pinned SHA-256 fingerprint of the server's self-signed cert, 64 hex
    /// chars. Env: TUYAU_FINGERPRINT.
    #[arg(long)]
    fingerprint: Option<String>,

    /// Path to a file containing the 64-hex-char token. Env:
    /// TUYAU_TOKEN_FILE; or pass the hex directly in TUYAU_TOKEN.
    #[arg(long)]
    token_file: Option<PathBuf>,

    /// Informational client name shown in server logs. Defaults to the
    /// machine hostname. Env: TUYAU_NAME.
    #[arg(long)]
    name: Option<String>,

    /// Ingress rule `host=local_addr`, repeatable. Maps a public hostname to
    /// the local `host:port` to forward to. No env equivalent — use TOML
    /// `[[ingress]]` for long lists.
    #[arg(long = "ingress", value_name = "HOST=LOCAL_ADDR")]
    ingress: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Server { config } => run_server(&config).await,
        Cmd::Client(args) => run_client(args).await,
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn run_server(config_path: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading server config at {}", config_path.display()))?;
    let mut cfg = ServerConfig::from_toml_str(&raw).context("parsing server config")?;

    // Default tunnel_cert_dir to the directory of the --config file so the
    // bootstrap loop (run once to print the fingerprint) is predictable.
    if cfg.tunnel_cert_dir.is_none()
        && let Some(parent) = config_path.parent()
    {
        cfg.tunnel_cert_dir = Some(parent.to_path_buf());
    }

    let server = TunnelServer::start(cfg).await.context("starting server")?;
    tracing::info!(addr = %server.local_addr()?, "server listening");

    wait_for_shutdown_signal().await;
    tracing::info!("shutting down");

    let _ = tokio::time::timeout(SHUTDOWN_GRACE, server.shutdown()).await;
    Ok(())
}

async fn run_client(args: ClientArgs) -> Result<()> {
    let cfg = build_client_config(args)?;

    let client = TunnelClient::connect(cfg)
        .await
        .context("connecting to server")?;
    tracing::info!("client connected, serving ingress");

    tokio::select! {
        _ = wait_for_shutdown_signal() => {
            tracing::info!("shutting down");
            let _ = tokio::time::timeout(SHUTDOWN_GRACE, client.shutdown()).await;
        }
        res = client.serve() => {
            match res {
                Ok(()) => tracing::info!("tunnel closed"),
                Err(e) => tracing::warn!(error = %e, "serve loop ended with error"),
            }
        }
    }

    Ok(())
}

/// Env-var snapshot, kept separate from the args so unit tests can drive the
/// builder with synthetic values without touching the process environment.
#[derive(Debug, Default)]
struct EnvVars {
    server: Option<String>,
    fingerprint: Option<String>,
    token: Option<String>,
    token_file: Option<String>,
    name: Option<String>,
}

impl EnvVars {
    fn from_process() -> Self {
        Self {
            server: std::env::var("TUYAU_SERVER").ok(),
            fingerprint: std::env::var("TUYAU_FINGERPRINT").ok(),
            token: std::env::var("TUYAU_TOKEN").ok(),
            token_file: std::env::var("TUYAU_TOKEN_FILE").ok(),
            name: std::env::var("TUYAU_NAME").ok(),
        }
    }
}

fn build_client_config(args: ClientArgs) -> Result<ClientConfig> {
    build_client_config_inner(args, EnvVars::from_process(), default_client_name)
}

fn build_client_config_inner(
    args: ClientArgs,
    env: EnvVars,
    default_name: fn() -> String,
) -> Result<ClientConfig> {
    if let Some(path) = args.config.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading client config at {}", path.display()))?;
        return ClientConfig::from_toml_str(&raw).context("parsing client config");
    }

    let server_addr = args
        .server
        .or(env.server)
        .ok_or_else(|| anyhow!("missing required: --server or TUYAU_SERVER"))?;

    let fingerprint_hex = args
        .fingerprint
        .or(env.fingerprint)
        .ok_or_else(|| anyhow!("missing required: --fingerprint or TUYAU_FINGERPRINT"))?;
    let fingerprint =
        parse_hex_32(&fingerprint_hex).context("--fingerprint / TUYAU_FINGERPRINT")?;

    let token = resolve_token(args.token_file, env.token_file, env.token)?;

    let client_name = args.name.or(env.name).unwrap_or_else(default_name);

    let ingress = parse_ingress(&args.ingress)?;

    Ok(ClientConfig {
        server_addr,
        server_cert_fingerprint_sha256: fingerprint,
        token,
        client_name,
        ingress,
    })
}

fn parse_ingress(entries: &[String]) -> Result<Vec<IngressRule>> {
    entries
        .iter()
        .map(|e| {
            let (host, local_addr) = e
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid --ingress '{e}': expected HOST=LOCAL_ADDR"))?;
            if host.is_empty() || local_addr.is_empty() {
                return Err(anyhow!(
                    "invalid --ingress '{e}': HOST and LOCAL_ADDR must both be non-empty"
                ));
            }
            Ok(IngressRule {
                host: host.to_string(),
                local_addr: local_addr.to_string(),
            })
        })
        .collect()
}

fn resolve_token(
    flag_path: Option<PathBuf>,
    env_path: Option<String>,
    env_hex: Option<String>,
) -> Result<[u8; 32]> {
    let token_file = flag_path.or_else(|| env_path.map(PathBuf::from));

    if let Some(path) = token_file {
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading token file at {}", path.display()))?;
        return parse_hex_32(raw.trim()).context("token file");
    }

    if let Some(hex_str) = env_hex {
        return parse_hex_32(hex_str.trim()).context("TUYAU_TOKEN");
    }

    Err(anyhow!(
        "missing required token: --token-file <PATH>, TUYAU_TOKEN_FILE=<path>, or TUYAU_TOKEN=<hex>"
    ))
}

fn parse_hex_32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("invalid hex")?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        anyhow!(
            "expected 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        )
    })
}

fn default_client_name() -> String {
    hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => tracing::debug!("received SIGINT"),
        _ = sigterm.recv() => tracing::debug!("received SIGTERM"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const HEX_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HEX_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn empty_args() -> ClientArgs {
        ClientArgs {
            config: None,
            server: None,
            fingerprint: None,
            token_file: None,
            name: None,
            ingress: vec![],
        }
    }

    fn stub_default_name() -> String {
        "stub-host".into()
    }

    #[test]
    fn clap_rejects_config_combined_with_per_field_flag() {
        let result = Cli::try_parse_from([
            "tuyau",
            "client",
            "--config",
            "/x.toml",
            "--server",
            "host:4433",
        ]);
        assert!(
            result.is_err(),
            "expected clap to reject --config + --server"
        );
    }

    #[test]
    fn clap_accepts_config_alone() {
        let result = Cli::try_parse_from(["tuyau", "client", "--config", "/x.toml"]);
        assert!(result.is_ok());
    }

    #[test]
    fn clap_accepts_flags_only() {
        let result = Cli::try_parse_from([
            "tuyau",
            "client",
            "--server",
            "host:4433",
            "--fingerprint",
            HEX_A,
            "--token-file",
            "/tok",
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn builds_from_flags_only() {
        let mut tok = NamedTempFile::new().unwrap();
        writeln!(tok, "{}", HEX_B).unwrap();

        let args = ClientArgs {
            config: None,
            server: Some("host:4433".into()),
            fingerprint: Some(HEX_A.into()),
            token_file: Some(tok.path().to_path_buf()),
            name: Some("explicit".into()),
            ingress: vec![],
        };
        let cfg = build_client_config_inner(args, EnvVars::default(), stub_default_name).unwrap();

        assert_eq!(cfg.server_addr, "host:4433");
        assert_eq!(cfg.server_cert_fingerprint_sha256[0], 0xaa);
        assert_eq!(cfg.token[0], 0xbb);
        assert_eq!(cfg.client_name, "explicit");
    }

    #[test]
    fn builds_from_env_only() {
        let mut tok = NamedTempFile::new().unwrap();
        writeln!(tok, "{}", HEX_B).unwrap();

        let env = EnvVars {
            server: Some("envhost:4433".into()),
            fingerprint: Some(HEX_A.into()),
            token: None,
            token_file: Some(tok.path().to_string_lossy().into()),
            name: Some("envname".into()),
        };
        let cfg = build_client_config_inner(empty_args(), env, stub_default_name).unwrap();

        assert_eq!(cfg.server_addr, "envhost:4433");
        assert_eq!(cfg.server_cert_fingerprint_sha256[0], 0xaa);
        assert_eq!(cfg.token[0], 0xbb);
        assert_eq!(cfg.client_name, "envname");
    }

    #[test]
    fn flag_overrides_env() {
        let args = ClientArgs {
            config: None,
            server: Some("flag:4433".into()),
            fingerprint: Some(HEX_A.into()),
            token_file: None,
            name: Some("flag-name".into()),
            ingress: vec![],
        };
        let env = EnvVars {
            server: Some("env:9999".into()),
            fingerprint: Some(HEX_B.into()),
            token: Some(HEX_B.into()),
            token_file: None,
            name: Some("env-name".into()),
        };
        let cfg = build_client_config_inner(args, env, stub_default_name).unwrap();

        assert_eq!(cfg.server_addr, "flag:4433");
        assert_eq!(cfg.server_cert_fingerprint_sha256[0], 0xaa);
        assert_eq!(cfg.client_name, "flag-name");
        // No token flag set, so TUYAU_TOKEN (HEX_B) wins.
        assert_eq!(cfg.token[0], 0xbb);
    }

    #[test]
    fn errors_on_missing_server() {
        let env = EnvVars {
            fingerprint: Some(HEX_A.into()),
            token: Some(HEX_B.into()),
            ..EnvVars::default()
        };
        let err = build_client_config_inner(empty_args(), env, stub_default_name).unwrap_err();
        assert!(err.to_string().contains("server"), "got: {err}");
    }

    #[test]
    fn errors_on_missing_fingerprint() {
        let env = EnvVars {
            server: Some("h:4433".into()),
            token: Some(HEX_B.into()),
            ..EnvVars::default()
        };
        let err = build_client_config_inner(empty_args(), env, stub_default_name).unwrap_err();
        assert!(err.to_string().contains("fingerprint"), "got: {err}");
    }

    #[test]
    fn errors_on_missing_token() {
        let env = EnvVars {
            server: Some("h:4433".into()),
            fingerprint: Some(HEX_A.into()),
            ..EnvVars::default()
        };
        let err = build_client_config_inner(empty_args(), env, stub_default_name).unwrap_err();
        assert!(err.to_string().contains("token"), "got: {err}");
    }

    #[test]
    fn token_file_strips_trailing_whitespace() {
        let mut tok = NamedTempFile::new().unwrap();
        // Trailing newline + extra spaces — common Docker secret artifact.
        writeln!(tok, "{}  ", HEX_B).unwrap();

        let env = EnvVars {
            server: Some("h:4433".into()),
            fingerprint: Some(HEX_A.into()),
            ..EnvVars::default()
        };
        let args = ClientArgs {
            token_file: Some(tok.path().to_path_buf()),
            ..empty_args()
        };
        let cfg = build_client_config_inner(args, env, stub_default_name).unwrap();
        assert_eq!(cfg.token[0], 0xbb);
    }

    #[test]
    fn default_client_name_is_used_when_no_flag_nor_env() {
        let mut tok = NamedTempFile::new().unwrap();
        writeln!(tok, "{}", HEX_B).unwrap();

        let env = EnvVars {
            server: Some("h:4433".into()),
            fingerprint: Some(HEX_A.into()),
            token_file: Some(tok.path().to_string_lossy().into()),
            ..EnvVars::default()
        };
        let cfg = build_client_config_inner(empty_args(), env, stub_default_name).unwrap();
        assert_eq!(cfg.client_name, "stub-host");
    }

    #[test]
    fn parse_hex_32_rejects_wrong_length() {
        assert!(parse_hex_32("deadbeef").is_err());
    }

    #[test]
    fn parse_hex_32_rejects_non_hex() {
        assert!(parse_hex_32(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn parse_ingress_single_and_multiple() {
        let rules = parse_ingress(&[
            "alpha.example.com=127.0.0.1:8080".to_string(),
            "beta.example.com=10.0.0.2:9000".to_string(),
        ])
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].host, "alpha.example.com");
        assert_eq!(rules[0].local_addr, "127.0.0.1:8080");
        assert_eq!(rules[1].host, "beta.example.com");
        assert_eq!(rules[1].local_addr, "10.0.0.2:9000");
    }

    #[test]
    fn parse_ingress_rejects_missing_equals() {
        let err = parse_ingress(&["alpha.example.com".to_string()]).unwrap_err();
        assert!(err.to_string().contains("HOST=LOCAL_ADDR"), "got: {err}");
    }

    #[test]
    fn parse_ingress_rejects_empty_side() {
        assert!(parse_ingress(&["=127.0.0.1:8080".to_string()]).is_err());
        assert!(parse_ingress(&["alpha.example.com=".to_string()]).is_err());
    }

    #[test]
    fn builds_ingress_from_flags() {
        let mut tok = NamedTempFile::new().unwrap();
        writeln!(tok, "{}", HEX_B).unwrap();

        let args = ClientArgs {
            config: None,
            server: Some("host:4433".into()),
            fingerprint: Some(HEX_A.into()),
            token_file: Some(tok.path().to_path_buf()),
            name: None,
            ingress: vec!["alpha.example.com=127.0.0.1:8080".to_string()],
        };
        let cfg = build_client_config_inner(args, EnvVars::default(), stub_default_name).unwrap();
        assert_eq!(cfg.ingress.len(), 1);
        assert_eq!(cfg.ingress[0].host, "alpha.example.com");
        assert_eq!(cfg.ingress[0].local_addr, "127.0.0.1:8080");
    }
}
