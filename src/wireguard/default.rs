use super::WireGuard;
use super::quick_config::QuickConfig;
use super::types::{Interface, PacketStats, Peer};
use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tracing::{debug, warn};

/// WireGuard implementation using system commands (wg-quick, wg) and sysfs.
pub struct DefaultWireGuard {
    conf_dir: PathBuf,
}

impl DefaultWireGuard {
    pub fn new(conf_dir: PathBuf) -> Self {
        Self { conf_dir }
    }

    fn conf_path(&self, iface_name: &str) -> PathBuf {
        self.conf_dir.join(format!("{iface_name}.conf"))
    }
}

impl WireGuard for DefaultWireGuard {
    fn configure(&self, tunnel_id: &str, iface: &Interface, peer: &Peer) -> Result<()> {
        let content = QuickConfig::encode(tunnel_id, iface, peer);
        let path = self.conf_path(&iface.id);
        fs::write(&path, &content)
            .with_context(|| format!("Failed to write config: {}", path.display()))?;
        debug!(path = %path.display(), "wrote wireguard config");
        Ok(())
    }

    fn bring_up(&self, _tunnel_id: &str, iface: &Interface) -> Result<()> {
        let conf_path = self.conf_path(&iface.id);
        let output = Command::new("wg-quick")
            .args(["up", &conf_path.to_string_lossy()])
            .output()
            .context("Failed to execute wg-quick up")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("wg-quick up failed: {stderr}");
        }

        debug!(iface = %iface.id, "interface brought up");
        Ok(())
    }

    fn teardown(&self, _tunnel_id: &str, iface: &Interface) -> Result<()> {
        let conf_path = self.conf_path(&iface.id);

        if conf_path.exists() {
            let output = Command::new("wg-quick")
                .args(["down", &conf_path.to_string_lossy()])
                .output()
                .context("Failed to execute wg-quick down")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(iface = %iface.id, "wg-quick down failed (may already be down): {stderr}");
            }

            fs::remove_file(&conf_path).ok();
            debug!(iface = %iface.id, "interface torn down and config removed");
        }

        Ok(())
    }

    fn interface_exists(&self, iface_name: &str) -> bool {
        let path = format!("/sys/class/net/{iface_name}");
        std::path::Path::new(&path).exists()
    }

    fn packet_stats(&self, iface_name: &str) -> Result<PacketStats> {
        let rx_path = format!("/sys/class/net/{iface_name}/statistics/rx_packets");
        let tx_path = format!("/sys/class/net/{iface_name}/statistics/tx_packets");

        let rx = fs::read_to_string(&rx_path)
            .with_context(|| format!("Failed to read {rx_path}"))?
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        let tx = fs::read_to_string(&tx_path)
            .with_context(|| format!("Failed to read {tx_path}"))?
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        Ok(PacketStats {
            rx_packets: rx,
            tx_packets: tx,
        })
    }

    fn latest_handshake(&self, iface_name: &str) -> Result<u64> {
        let output = Command::new("wg")
            .args(["show", iface_name, "latest-handshakes"])
            .output()
            .context("Failed to execute wg show")?;

        if !output.status.success() {
            return Ok(0);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Output format: "<public_key>\t<timestamp>\n"
        // We take the first line's timestamp.
        for line in stdout.lines() {
            if let Some((_key, ts)) = line.split_once('\t') {
                return Ok(ts.trim().parse::<u64>().unwrap_or(0));
            }
        }

        Ok(0)
    }

    fn generate_key_pair(&self) -> Result<(String, String)> {
        let genkey = Command::new("wg")
            .arg("genkey")
            .output()
            .context("Failed to execute wg genkey")?;

        if !genkey.status.success() {
            let stderr = String::from_utf8_lossy(&genkey.stderr);
            bail!("wg genkey failed: {stderr}");
        }

        let private_key = String::from_utf8(genkey.stdout)
            .context("wg genkey output is not valid UTF-8")?
            .trim()
            .to_string();

        let mut pubkey_proc = Command::new("wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .context("Failed to spawn wg pubkey")?;

        pubkey_proc
            .stdin
            .take()
            .context("Failed to open stdin for wg pubkey")?
            .write_all(private_key.as_bytes())
            .context("Failed to write private key to wg pubkey")?;

        let pubkey_out = pubkey_proc
            .wait_with_output()
            .context("Failed to wait for wg pubkey")?;

        if !pubkey_out.status.success() {
            let stderr = String::from_utf8_lossy(&pubkey_out.stderr);
            bail!("wg pubkey failed: {stderr}");
        }

        let public_key = String::from_utf8(pubkey_out.stdout)
            .context("wg pubkey output is not valid UTF-8")?
            .trim()
            .to_string();

        Ok((private_key, public_key))
    }
}
