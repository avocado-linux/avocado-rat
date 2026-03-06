use super::state::{TunnelInfo, TunnelState, TunnelStatus};
use crate::config::TimerConfig;
use crate::wireguard::WireGuard;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, error, info, warn};

/// Commands sent to a per-tunnel task via its mpsc channel.
pub enum TunnelCommand {
    Close,
    Extend { secs: u64 },
    GetState { reply: oneshot::Sender<TunnelInfo> },
}

/// Handle held by the TunnelManager for each active tunnel.
pub struct TunnelHandle {
    pub cmd_tx: mpsc::Sender<TunnelCommand>,
    pub info_rx: watch::Receiver<TunnelInfo>,
    pub join: tokio::task::JoinHandle<()>,
}

/// Run a single tunnel's lifecycle as a tokio task.
///
/// This is the Rust equivalent of a GenServer per-tunnel process:
/// - Writes WireGuard config and brings up the interface
/// - Polls for interface readiness
/// - Runs a status check loop (staleness via RX/TX/handshake)
/// - Handles TTL expiry (auto-close)
/// - Listens for commands (Close, Extend, GetState)
/// - Always tears down the interface on exit
pub async fn run_tunnel(
    wg: Arc<dyn WireGuard>,
    mut state: TunnelState,
    timers: TimerConfig,
    mut cmd_rx: mpsc::Receiver<TunnelCommand>,
    info_tx: watch::Sender<TunnelInfo>,
) {
    let tunnel_id = state.id.clone();
    let iface_name = state.interface.id.clone();

    info!(tunnel = %tunnel_id, iface = %iface_name, "tunnel task starting");

    // Phase 1: Configure + bring up
    if let Err(e) = wg.configure(&tunnel_id, &state.interface, &state.peer) {
        error!(tunnel = %tunnel_id, "failed to write config: {e:#}");
        return;
    }

    if let Err(e) = wg.bring_up(&tunnel_id, &state.interface) {
        error!(tunnel = %tunnel_id, "failed to bring up interface: {e:#}");
        // Clean up config file on failure
        let _ = wg.teardown(&tunnel_id, &state.interface);
        return;
    }

    // Phase 2: Wait for interface to appear
    let up_timeout = tokio::time::Duration::from_secs(timers.interface_up_timeout_secs);
    let poll_interval = tokio::time::Duration::from_millis(500);
    let deadline = tokio::time::Instant::now() + up_timeout;

    loop {
        if wg.interface_exists(&iface_name) {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            error!(tunnel = %tunnel_id, "interface did not appear within timeout");
            let _ = wg.teardown(&tunnel_id, &state.interface);
            return;
        }
        tokio::time::sleep(poll_interval).await;
    }

    state.status = TunnelStatus::Up;
    let _ = info_tx.send(state.to_info());
    info!(tunnel = %tunnel_id, iface = %iface_name, "tunnel is up");

    // Phase 3: Status check loop
    let check_interval = tokio::time::Duration::from_secs(timers.status_check_secs);

    loop {
        tokio::select! {
            // Status check tick
            () = tokio::time::sleep(check_interval) => {
                // Check TTL expiry
                if state.expired() {
                    info!(tunnel = %tunnel_id, "TTL expired, closing tunnel");
                    break;
                }

                // Check staleness
                if state.status == TunnelStatus::Closing {
                    continue;
                }

                let stats = wg.packet_stats(&iface_name);
                let handshake = wg.latest_handshake(&iface_name).unwrap_or(0);

                let (rx, tx) = match stats {
                    Ok(s) => (s.rx_packets, s.tx_packets),
                    Err(e) => {
                        debug!(tunnel = %tunnel_id, "failed to read stats: {e}");
                        (state.last_rx_packets, state.last_tx_packets)
                    }
                };

                let was_stale = state.status == TunnelStatus::Stale;
                let is_stale = state.check_staleness(
                    rx, tx, handshake, timers.stale_threshold_secs,
                );

                if is_stale && !was_stale {
                    warn!(tunnel = %tunnel_id, "tunnel is stale");
                    state.status = TunnelStatus::Stale;
                    let _ = info_tx.send(state.to_info());
                } else if !is_stale && was_stale {
                    info!(tunnel = %tunnel_id, "tunnel recovered from stale");
                    state.status = TunnelStatus::Up;
                    let _ = info_tx.send(state.to_info());
                }
            }

            // Commands from the manager
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(TunnelCommand::Close) => {
                        info!(tunnel = %tunnel_id, "close command received");
                        state.status = TunnelStatus::Closing;
                        let _ = info_tx.send(state.to_info());
                        break;
                    }
                    Some(TunnelCommand::Extend { secs }) => {
                        if let Some(expires) = state.expires_at {
                            state.expires_at =
                                Some(expires + chrono::Duration::seconds(secs as i64));
                            info!(tunnel = %tunnel_id, new_expires = ?state.expires_at, "TTL extended");
                            let _ = info_tx.send(state.to_info());
                        }
                    }
                    Some(TunnelCommand::GetState { reply }) => {
                        let _ = reply.send(state.to_info());
                    }
                    None => {
                        // Manager dropped the sender, shut down
                        info!(tunnel = %tunnel_id, "command channel closed");
                        break;
                    }
                }
            }
        }
    }

    // Phase 4: Cleanup — always teardown
    info!(tunnel = %tunnel_id, "tearing down interface");
    if let Err(e) = wg.teardown(&tunnel_id, &state.interface) {
        error!(tunnel = %tunnel_id, "teardown failed: {e:#}");
    }
}
