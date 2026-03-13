use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info};

mod config;
mod network;
mod tunnel;
mod wireguard;

use config::RatConfig;
use tunnel::TunnelManager;
use wireguard::DefaultWireGuard;

#[derive(Parser)]
#[command(
    name = "avocado-rat",
    about = "Avocado Connect Remote Access Tunnel Manager"
)]
struct Cli {
    /// Path to config file
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the tunnel manager daemon
    Run,
    /// Open a new WireGuard tunnel
    Open {
        /// Tunnel ID
        #[arg(long)]
        id: String,
        /// Path to JSON file with interface and peer params
        #[arg(long)]
        params: PathBuf,
        /// TTL in seconds (0 = no expiry)
        #[arg(long, default_value = "3600")]
        ttl: u64,
    },
    /// Close an active tunnel
    Close {
        /// Tunnel ID
        #[arg(long)]
        id: String,
    },
    /// Extend a tunnel's TTL
    Extend {
        /// Tunnel ID
        #[arg(long)]
        id: String,
        /// Additional seconds to add
        #[arg(long)]
        secs: u64,
    },
    /// List all active tunnels
    List,
    /// Get status of a specific tunnel
    Status {
        /// Tunnel ID
        #[arg(long)]
        id: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let config_path = match &cli.config {
        Some(p) => p.clone(),
        None => RatConfig::default_path()?,
    };

    let config = RatConfig::load(&config_path)?;

    match cli.command {
        Commands::Run => run_daemon(config).await,
        Commands::Open { id, params, ttl } => {
            let params_data = std::fs::read_to_string(&params)
                .with_context(|| format!("Failed to read params file: {}", params.display()))?;
            let params_json: serde_json::Value = serde_json::from_str(&params_data)?;
            let request = json!({
                "command": "open",
                "id": id,
                "interface": params_json["interface"],
                "peer": params_json["peer"],
                "ttl_secs": ttl,
            });
            send_command(&config.socket_path, &request).await
        }
        Commands::Close { id } => {
            let request = json!({ "command": "close", "id": id });
            send_command(&config.socket_path, &request).await
        }
        Commands::Extend { id, secs } => {
            let request = json!({ "command": "extend", "id": id, "secs": secs });
            send_command(&config.socket_path, &request).await
        }
        Commands::List => {
            let request = json!({ "command": "list" });
            send_command(&config.socket_path, &request).await
        }
        Commands::Status { id } => {
            let request = json!({ "command": "status", "id": id });
            send_command(&config.socket_path, &request).await
        }
    }
}

async fn run_daemon(config: RatConfig) -> Result<()> {
    info!(socket = %config.socket_path, data_dir = %config.data_dir, "starting avocado-rat");

    // Ensure data and conf directories exist
    let conf_dir = config.conf_dir();
    std::fs::create_dir_all(&conf_dir)
        .with_context(|| format!("Failed to create conf dir: {}", conf_dir.display()))?;

    let wg = DefaultWireGuard::new(conf_dir.clone());
    let mut manager = TunnelManager::new(Box::new(wg), config.timers.clone(), conf_dir);

    // Clean up orphaned tunnels from a previous run
    manager.cleanup_orphans().await;

    // Remove stale socket file
    let socket_path = &config.socket_path;
    if std::path::Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("Failed to bind Unix socket: {socket_path}"))?;

    info!("listening on {socket_path}");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let result = handle_client(stream, &mut manager).await;
                if let Err(e) = result {
                    error!("client handler error: {e:#}");
                }
            }
            Err(e) => {
                error!("accept error: {e}");
            }
        }
    }
}

async fn handle_client(stream: UnixStream, manager: &mut TunnelManager) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let request: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({"ok": false, "error": format!("invalid JSON: {e}")});
                let mut out = serde_json::to_string(&resp)?;
                out.push('\n');
                writer.write_all(out.as_bytes()).await?;
                continue;
            }
        };

        let response = dispatch_command(manager, &request).await;
        let mut out = serde_json::to_string(&response)?;
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
    }

    Ok(())
}

async fn dispatch_command(
    manager: &mut TunnelManager,
    request: &serde_json::Value,
) -> serde_json::Value {
    let command = request["command"].as_str().unwrap_or("");

    match command {
        "open" => {
            let id = match request["id"].as_str() {
                Some(id) => id.to_string(),
                None => return json!({"ok": false, "error": "missing 'id'"}),
            };
            let interface: wireguard::Interface =
                match serde_json::from_value(request["interface"].clone()) {
                    Ok(v) => v,
                    Err(e) => {
                        return json!({"ok": false, "error": format!("invalid interface: {e}")});
                    }
                };
            let peer: wireguard::Peer = match serde_json::from_value(request["peer"].clone()) {
                Ok(v) => v,
                Err(e) => return json!({"ok": false, "error": format!("invalid peer: {e}")}),
            };
            let ttl_secs = request["ttl_secs"].as_u64().unwrap_or(0);

            match manager.open_tunnel(id, interface, peer, ttl_secs).await {
                Ok(info) => json!({"ok": true, "data": info}),
                Err(e) => json!({"ok": false, "error": format!("{e:#}")}),
            }
        }
        "close" => {
            let id = match request["id"].as_str() {
                Some(id) => id,
                None => return json!({"ok": false, "error": "missing 'id'"}),
            };
            match manager.close_tunnel(id).await {
                Ok(()) => json!({"ok": true}),
                Err(e) => json!({"ok": false, "error": format!("{e:#}")}),
            }
        }
        "extend" => {
            let id = match request["id"].as_str() {
                Some(id) => id,
                None => return json!({"ok": false, "error": "missing 'id'"}),
            };
            let secs = match request["secs"].as_u64() {
                Some(s) => s,
                None => return json!({"ok": false, "error": "missing 'secs'"}),
            };
            match manager.extend_tunnel(id, secs).await {
                Ok(()) => json!({"ok": true}),
                Err(e) => json!({"ok": false, "error": format!("{e:#}")}),
            }
        }
        "list" => {
            let tunnels = manager.list_tunnels().await;
            json!({"ok": true, "data": tunnels})
        }
        "status" => {
            let id = match request["id"].as_str() {
                Some(id) => id,
                None => return json!({"ok": false, "error": "missing 'id'"}),
            };
            match manager.get_status(id).await {
                Some(info) => json!({"ok": true, "data": info}),
                None => json!({"ok": false, "error": "tunnel not found"}),
            }
        }
        "find_port" => {
            let lo = request["lo"].as_u64().unwrap_or(49_152) as u16;
            let hi = request["hi"].as_u64().unwrap_or(65_535) as u16;
            match network::find_available_port(lo, hi) {
                Some(port) => json!({"ok": true, "data": {"port": port}}),
                None => json!({"ok": false, "error": "no available UDP port in range"}),
            }
        }
        _ => json!({"ok": false, "error": format!("unknown command: {command}")}),
    }
}

async fn send_command(socket_path: &str, request: &serde_json::Value) -> Result<()> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("Failed to connect to {socket_path}. Is avocado-rat running?"))?;

    let (reader, mut writer) = stream.into_split();

    let mut payload = serde_json::to_string(request)?;
    payload.push('\n');
    writer.write_all(payload.as_bytes()).await?;
    writer.shutdown().await?;

    let mut lines = BufReader::new(reader).lines();
    if let Some(line) = lines.next_line().await? {
        let response: serde_json::Value = serde_json::from_str(&line)?;
        if response["ok"].as_bool() == Some(true) {
            if let Some(data) = response.get("data") {
                println!("{}", serde_json::to_string_pretty(data)?);
            } else {
                println!("OK");
            }
        } else {
            let err = response["error"].as_str().unwrap_or("unknown error");
            eprintln!("Error: {err}");
            std::process::exit(1);
        }
    }

    Ok(())
}
