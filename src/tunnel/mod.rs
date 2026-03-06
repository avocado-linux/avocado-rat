pub mod state;
pub mod task;

use anyhow::{Result, bail};
use state::{TunnelId, TunnelInfo, TunnelState};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use task::{TunnelCommand, TunnelHandle, run_tunnel};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{info, warn};

use crate::config::TimerConfig;
use crate::wireguard::{Interface, Peer, QuickConfig, WireGuard};

/// Manages all active tunnels.
/// Rust equivalent of DynamicSupervisor + Registry from the Elixir architecture.
pub struct TunnelManager {
    wg: Arc<dyn WireGuard>,
    timers: TimerConfig,
    conf_dir: PathBuf,
    tunnels: HashMap<TunnelId, TunnelHandle>,
}

impl TunnelManager {
    pub fn new(wg: Box<dyn WireGuard>, timers: TimerConfig, conf_dir: PathBuf) -> Self {
        Self {
            wg: Arc::from(wg),
            timers,
            conf_dir,
            tunnels: HashMap::new(),
        }
    }

    /// Open a new tunnel. Returns tunnel info on success.
    pub async fn open_tunnel(
        &mut self,
        id: TunnelId,
        interface: Interface,
        peer: Peer,
        ttl_secs: u64,
    ) -> Result<TunnelInfo> {
        if self.tunnels.contains_key(&id) {
            bail!("tunnel '{id}' already exists");
        }

        let ttl = if ttl_secs == 0 {
            self.timers.default_ttl_secs
        } else {
            ttl_secs
        };

        let state = TunnelState::new(id.clone(), interface, peer, ttl);
        let info = state.to_info();

        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (info_tx, info_rx) = watch::channel(info.clone());

        let wg = self.wg.clone();
        let timers = self.timers.clone();

        let join = tokio::spawn(async move {
            run_tunnel(wg, state, timers, cmd_rx, info_tx).await;
        });

        self.tunnels.insert(
            id,
            TunnelHandle {
                cmd_tx,
                info_rx,
                join,
            },
        );

        Ok(info)
    }

    /// Close a tunnel by ID.
    pub async fn close_tunnel(&mut self, id: &str) -> Result<()> {
        let handle = match self.tunnels.remove(id) {
            Some(h) => h,
            None => bail!("tunnel '{id}' not found"),
        };

        let _ = handle.cmd_tx.send(TunnelCommand::Close).await;
        // Wait for task to finish cleanup
        let _ = handle.join.await;

        Ok(())
    }

    /// Extend a tunnel's TTL.
    pub async fn extend_tunnel(&mut self, id: &str, secs: u64) -> Result<()> {
        let handle = match self.tunnels.get(id) {
            Some(h) => h,
            None => bail!("tunnel '{id}' not found"),
        };

        handle
            .cmd_tx
            .send(TunnelCommand::Extend { secs })
            .await
            .map_err(|_| anyhow::anyhow!("tunnel task has exited"))?;

        Ok(())
    }

    /// List all active tunnels.
    pub async fn list_tunnels(&mut self) -> Vec<TunnelInfo> {
        // Clean up finished tasks first
        self.reap_finished();

        self.tunnels
            .values()
            .map(|h| h.info_rx.borrow().clone())
            .collect()
    }

    /// Get status of a specific tunnel.
    pub async fn get_status(&mut self, id: &str) -> Option<TunnelInfo> {
        self.reap_finished();

        let handle = self.tunnels.get(id)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        if handle
            .cmd_tx
            .send(TunnelCommand::GetState { reply: reply_tx })
            .await
            .is_err()
        {
            // Task exited, return last known state from watch
            return Some(handle.info_rx.borrow().clone());
        }

        reply_rx.await.ok()
    }

    /// Clean up orphaned WireGuard configs and interfaces from a previous run.
    pub async fn cleanup_orphans(&self) {
        let entries = match std::fs::read_dir(&self.conf_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("conf") {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            if let Some((tunnel_id, iface, peer)) = QuickConfig::decode(&content) {
                info!(tunnel = %tunnel_id, iface = %iface.id, "cleaning up orphaned tunnel");
                if let Err(e) = self.wg.teardown(&tunnel_id, &iface) {
                    warn!(tunnel = %tunnel_id, "orphan teardown failed: {e:#}");
                }
                let _ = peer; // consumed by decode but not needed for teardown
            }
        }
    }

    /// Remove handles for tasks that have already finished.
    fn reap_finished(&mut self) {
        let finished: Vec<TunnelId> = self
            .tunnels
            .iter()
            .filter(|(_, h)| h.join.is_finished())
            .map(|(id, _)| id.clone())
            .collect();

        for id in finished {
            info!(tunnel = %id, "reaping finished tunnel task");
            self.tunnels.remove(&id);
        }
    }
}
