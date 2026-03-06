use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::wireguard::{Interface, Peer};

/// Unique identifier for a tunnel (typically a ULID from the API).
pub type TunnelId = String;

/// Tunnel lifecycle status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelStatus {
    Starting,
    Up,
    Stale,
    Closing,
}

impl std::fmt::Display for TunnelStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelStatus::Starting => write!(f, "starting"),
            TunnelStatus::Up => write!(f, "up"),
            TunnelStatus::Stale => write!(f, "stale"),
            TunnelStatus::Closing => write!(f, "closing"),
        }
    }
}

/// Full tunnel state tracked by the per-tunnel task.
#[derive(Debug, Clone)]
pub struct TunnelState {
    pub id: TunnelId,
    pub interface: Interface,
    pub peer: Peer,
    pub status: TunnelStatus,
    pub started_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_rx_packets: u64,
    pub last_tx_packets: u64,
    pub last_handshake: u64,
}

/// Serializable tunnel info returned to IPC clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelInfo {
    pub id: TunnelId,
    pub interface_name: String,
    pub status: TunnelStatus,
    pub started_at: String,
    pub expires_at: Option<String>,
}

impl TunnelState {
    pub fn new(id: TunnelId, interface: Interface, peer: Peer, ttl_secs: u64) -> Self {
        let now = Utc::now();
        let expires_at = if ttl_secs > 0 {
            Some(now + chrono::Duration::seconds(ttl_secs as i64))
        } else {
            None
        };

        Self {
            id,
            interface,
            peer,
            status: TunnelStatus::Starting,
            started_at: now,
            expires_at,
            last_rx_packets: 0,
            last_tx_packets: 0,
            last_handshake: 0,
        }
    }

    pub fn to_info(&self) -> TunnelInfo {
        TunnelInfo {
            id: self.id.clone(),
            interface_name: self.interface.id.clone(),
            status: self.status.clone(),
            started_at: self.started_at.to_rfc3339(),
            expires_at: self.expires_at.map(|t| t.to_rfc3339()),
        }
    }

    pub fn expired(&self) -> bool {
        match self.expires_at {
            Some(expires) => Utc::now() >= expires,
            None => false,
        }
    }

    /// Check if the tunnel is stale based on packet stats and handshake.
    /// A tunnel is stale if RX/TX haven't changed AND no recent handshake.
    pub fn check_staleness(
        &mut self,
        rx_packets: u64,
        tx_packets: u64,
        handshake: u64,
        stale_threshold_secs: u64,
    ) -> bool {
        let packets_changed =
            rx_packets != self.last_rx_packets || tx_packets != self.last_tx_packets;

        self.last_rx_packets = rx_packets;
        self.last_tx_packets = tx_packets;
        self.last_handshake = handshake;

        if packets_changed {
            return false;
        }

        // No packet change — check handshake recency
        if handshake == 0 {
            return true;
        }

        let now = Utc::now().timestamp() as u64;
        now.saturating_sub(handshake) > stale_threshold_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_interface() -> Interface {
        Interface {
            id: "avocado0".to_string(),
            address: "10.0.0.1/24".to_string(),
            listen_port: 0,
            table: "auto".to_string(),
            private_key: "KEY=".to_string(),
            dns: vec![],
        }
    }

    fn test_peer() -> Peer {
        Peer {
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            endpoint: "1.2.3.4".to_string(),
            endpoint_port: 51820,
            public_key: "PUB=".to_string(),
            preshared_key: None,
            persistent_keepalive: 25,
        }
    }

    #[test]
    fn new_tunnel_starts_as_starting() {
        let state = TunnelState::new("t1".into(), test_interface(), test_peer(), 3600);
        assert_eq!(state.status, TunnelStatus::Starting);
        assert!(state.expires_at.is_some());
    }

    #[test]
    fn zero_ttl_means_no_expiry() {
        let state = TunnelState::new("t1".into(), test_interface(), test_peer(), 0);
        assert!(state.expires_at.is_none());
        assert!(!state.expired());
    }

    #[test]
    fn staleness_detected_when_no_activity() {
        let mut state = TunnelState::new("t1".into(), test_interface(), test_peer(), 0);
        // First check: baseline
        let stale = state.check_staleness(0, 0, 0, 120);
        assert!(stale); // no handshake at all

        // Second check with activity
        let stale = state.check_staleness(10, 5, 0, 120);
        assert!(!stale); // packets changed

        // Third check: same packets, no handshake
        let stale = state.check_staleness(10, 5, 0, 120);
        assert!(stale);
    }

    #[test]
    fn not_stale_with_recent_handshake() {
        let mut state = TunnelState::new("t1".into(), test_interface(), test_peer(), 0);
        state.last_rx_packets = 10;
        state.last_tx_packets = 5;

        let recent_handshake = Utc::now().timestamp() as u64 - 30; // 30 seconds ago
        let stale = state.check_staleness(10, 5, recent_handshake, 120);
        assert!(!stale);
    }
}
