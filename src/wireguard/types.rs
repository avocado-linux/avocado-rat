use serde::{Deserialize, Serialize};

/// WireGuard interface configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    /// Interface name (e.g. "avocado0")
    pub id: String,
    /// Local IP address with CIDR (e.g. "10.0.0.1/24")
    pub address: String,
    /// Listen port (0 = random)
    #[serde(default)]
    pub listen_port: u16,
    /// Routing table ("auto", "off", or a number)
    #[serde(default = "default_table")]
    pub table: String,
    /// Private key (base64)
    pub private_key: String,
    /// DNS servers (optional)
    #[serde(default)]
    pub dns: Vec<String>,
}

/// WireGuard peer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    /// Allowed IPs (e.g. ["0.0.0.0/0"])
    pub allowed_ips: Vec<String>,
    /// Remote endpoint hostname/IP
    pub endpoint: String,
    /// Remote endpoint port
    pub endpoint_port: u16,
    /// Peer's public key (base64)
    pub public_key: String,
    /// Preshared key (optional, base64)
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// Persistent keepalive interval in seconds (0 = disabled)
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u16,
}

/// Packet statistics from sysfs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
}

fn default_table() -> String {
    "auto".to_string()
}

fn default_keepalive() -> u16 {
    25
}
