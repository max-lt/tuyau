use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use tuyau_client::{ClientConfig, TunnelClient};
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
    Client {
        /// Path to client.toml.
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Server { config } => run_server(&config).await,
        Cmd::Client { config } => run_client(&config).await,
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

async fn run_client(config_path: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading client config at {}", config_path.display()))?;
    let cfg = ClientConfig::from_toml_str(&raw).context("parsing client config")?;

    let client = TunnelClient::connect(cfg)
        .await
        .context("connecting to server")?;
    tracing::info!("client connected, holding connection");

    tokio::select! {
        _ = wait_for_shutdown_signal() => {
            tracing::info!("shutting down");
            let _ = tokio::time::timeout(SHUTDOWN_GRACE, client.shutdown()).await;
        }
        err = client.wait_closed() => {
            tracing::info!(error = %err, "connection closed by remote");
        }
    }

    Ok(())
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
