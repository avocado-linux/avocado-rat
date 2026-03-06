mod default;
mod quick_config;
mod types;

pub use default::DefaultWireGuard;
pub use quick_config::QuickConfig;
pub use types::{Interface, PacketStats, Peer};

use anyhow::Result;

/// Abstraction over WireGuard system operations.
/// Implemented by DefaultWireGuard (real system commands) or a mock for testing.
pub trait WireGuard: Send + Sync {
    /// Write a wg-quick config file for the given interface and peer.
    fn configure(&self, tunnel_id: &str, iface: &Interface, peer: &Peer) -> Result<()>;

    /// Bring up the WireGuard interface via wg-quick.
    fn bring_up(&self, tunnel_id: &str, iface: &Interface) -> Result<()>;

    /// Tear down the WireGuard interface and remove its config file.
    fn teardown(&self, tunnel_id: &str, iface: &Interface) -> Result<()>;

    /// Check if a network interface exists in sysfs.
    fn interface_exists(&self, iface_name: &str) -> bool;

    /// Read RX/TX packet stats from sysfs.
    fn packet_stats(&self, iface_name: &str) -> Result<PacketStats>;

    /// Read the latest handshake timestamp for a peer on an interface.
    /// Returns seconds since epoch, or 0 if no handshake.
    fn latest_handshake(&self, iface_name: &str) -> Result<u64>;
}
