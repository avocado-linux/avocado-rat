use super::types::{Interface, Peer};

/// Encoder/decoder for wg-quick INI config files.
/// Includes an `# [Avocado]` metadata section for tunnel ID tracking.
pub struct QuickConfig;

impl QuickConfig {
    /// Encode an Interface + Peer into wg-quick INI format.
    pub fn encode(tunnel_id: &str, iface: &Interface, peer: &Peer) -> String {
        let mut out = String::new();

        // Avocado metadata section (comment-based, ignored by wg-quick)
        out.push_str("# [Avocado]\n");
        out.push_str(&format!("# ID = {tunnel_id}\n"));
        out.push_str(&format!("# Interface = {}\n", iface.id));
        out.push('\n');

        // [Interface] section
        out.push_str("[Interface]\n");
        out.push_str(&format!("Address = {}\n", iface.address));
        if iface.listen_port > 0 {
            out.push_str(&format!("ListenPort = {}\n", iface.listen_port));
        }
        out.push_str(&format!("PrivateKey = {}\n", iface.private_key));
        if iface.table != "auto" {
            out.push_str(&format!("Table = {}\n", iface.table));
        }
        if !iface.dns.is_empty() {
            out.push_str(&format!("DNS = {}\n", iface.dns.join(", ")));
        }

        // [Peer] section
        out.push_str("\n[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", peer.public_key));
        if let Some(psk) = &peer.preshared_key {
            out.push_str(&format!("PresharedKey = {psk}\n"));
        }
        out.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips.join(", ")));
        out.push_str(&format!(
            "Endpoint = {}:{}\n",
            peer.endpoint, peer.endpoint_port
        ));
        if peer.persistent_keepalive > 0 {
            out.push_str(&format!(
                "PersistentKeepalive = {}\n",
                peer.persistent_keepalive
            ));
        }

        out
    }

    /// Decode a wg-quick INI config back into components.
    /// Returns (tunnel_id, Interface, Peer) or None if parsing fails.
    pub fn decode(content: &str) -> Option<(String, Interface, Peer)> {
        let mut tunnel_id = String::new();
        let mut iface_id = String::new();
        let mut address = String::new();
        let mut listen_port: u16 = 0;
        let mut private_key = String::new();
        let mut table = "auto".to_string();
        let mut dns: Vec<String> = Vec::new();

        let mut public_key = String::new();
        let mut preshared_key: Option<String> = None;
        let mut allowed_ips: Vec<String> = Vec::new();
        let mut endpoint = String::new();
        let mut endpoint_port: u16 = 0;
        let mut persistent_keepalive: u16 = 25;

        let mut section = "";

        for line in content.lines() {
            let line = line.trim();

            // Parse Avocado metadata comments
            if line.starts_with("# ID = ") {
                tunnel_id = line.strip_prefix("# ID = ").unwrap().to_string();
                continue;
            }
            if line.starts_with("# Interface = ") {
                iface_id = line.strip_prefix("# Interface = ").unwrap().to_string();
                continue;
            }
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            if line == "[Interface]" {
                section = "interface";
                continue;
            }
            if line == "[Peer]" {
                section = "peer";
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();

            match (section, key) {
                ("interface", "Address") => address = value.to_string(),
                ("interface", "ListenPort") => listen_port = value.parse().unwrap_or(0),
                ("interface", "PrivateKey") => private_key = value.to_string(),
                ("interface", "Table") => table = value.to_string(),
                ("interface", "DNS") => {
                    dns = value.split(',').map(|s| s.trim().to_string()).collect();
                }
                ("peer", "PublicKey") => public_key = value.to_string(),
                ("peer", "PresharedKey") => preshared_key = Some(value.to_string()),
                ("peer", "AllowedIPs") => {
                    allowed_ips = value.split(',').map(|s| s.trim().to_string()).collect();
                }
                ("peer", "Endpoint") => {
                    if let Some((host, port)) = value.rsplit_once(':') {
                        endpoint = host.to_string();
                        endpoint_port = port.parse().unwrap_or(0);
                    }
                }
                ("peer", "PersistentKeepalive") => {
                    persistent_keepalive = value.parse().unwrap_or(25);
                }
                _ => {}
            }
        }

        if tunnel_id.is_empty() || private_key.is_empty() || public_key.is_empty() {
            return None;
        }

        Some((
            tunnel_id,
            Interface {
                id: iface_id,
                address,
                listen_port,
                table,
                private_key,
                dns,
            },
            Peer {
                allowed_ips,
                endpoint,
                endpoint_port,
                public_key,
                preshared_key,
                persistent_keepalive,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_interface() -> Interface {
        Interface {
            id: "avocado0".to_string(),
            address: "10.0.0.1/24".to_string(),
            listen_port: 51820,
            table: "auto".to_string(),
            private_key: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".to_string(),
            dns: vec!["1.1.1.1".to_string()],
        }
    }

    fn sample_peer() -> Peer {
        Peer {
            allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
            endpoint: "demo.wireguard.com".to_string(),
            endpoint_port: 12912,
            public_key: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=".to_string(),
            preshared_key: Some("AABBCC==".to_string()),
            persistent_keepalive: 25,
        }
    }

    #[test]
    fn encode_produces_valid_ini() {
        let iface = sample_interface();
        let peer = sample_peer();
        let encoded = QuickConfig::encode("tunnel-123", &iface, &peer);

        assert!(encoded.contains("# ID = tunnel-123"));
        assert!(encoded.contains("# Interface = avocado0"));
        assert!(encoded.contains("[Interface]"));
        assert!(encoded.contains("Address = 10.0.0.1/24"));
        assert!(encoded.contains("ListenPort = 51820"));
        assert!(encoded.contains("PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="));
        assert!(encoded.contains("DNS = 1.1.1.1"));
        assert!(encoded.contains("[Peer]"));
        assert!(encoded.contains("PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="));
        assert!(encoded.contains("PresharedKey = AABBCC=="));
        assert!(encoded.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(encoded.contains("Endpoint = demo.wireguard.com:12912"));
        assert!(encoded.contains("PersistentKeepalive = 25"));
        // "auto" table should be omitted
        assert!(!encoded.contains("Table ="));
    }

    #[test]
    fn encode_omits_optional_fields() {
        let iface = Interface {
            id: "avocado1".to_string(),
            address: "10.0.0.2/24".to_string(),
            listen_port: 0,
            table: "auto".to_string(),
            private_key: "KEY123=".to_string(),
            dns: vec![],
        };
        let peer = Peer {
            allowed_ips: vec!["10.0.0.0/24".to_string()],
            endpoint: "1.2.3.4".to_string(),
            endpoint_port: 51820,
            public_key: "PUBKEY=".to_string(),
            preshared_key: None,
            persistent_keepalive: 0,
        };
        let encoded = QuickConfig::encode("t1", &iface, &peer);

        assert!(!encoded.contains("ListenPort"));
        assert!(!encoded.contains("Table"));
        assert!(!encoded.contains("DNS"));
        assert!(!encoded.contains("PresharedKey"));
        assert!(!encoded.contains("PersistentKeepalive"));
    }

    #[test]
    fn round_trip() {
        let iface = sample_interface();
        let peer = sample_peer();
        let encoded = QuickConfig::encode("tunnel-abc", &iface, &peer);
        let (id, dec_iface, dec_peer) = QuickConfig::decode(&encoded).unwrap();

        assert_eq!(id, "tunnel-abc");
        assert_eq!(dec_iface.id, "avocado0");
        assert_eq!(dec_iface.address, "10.0.0.1/24");
        assert_eq!(dec_iface.listen_port, 51820);
        assert_eq!(dec_iface.private_key, iface.private_key);
        assert_eq!(dec_iface.dns, vec!["1.1.1.1"]);

        assert_eq!(dec_peer.public_key, peer.public_key);
        assert_eq!(
            dec_peer.preshared_key.as_deref(),
            peer.preshared_key.as_deref()
        );
        assert_eq!(dec_peer.allowed_ips, peer.allowed_ips);
        assert_eq!(dec_peer.endpoint, "demo.wireguard.com");
        assert_eq!(dec_peer.endpoint_port, 12912);
        assert_eq!(dec_peer.persistent_keepalive, 25);
    }

    #[test]
    fn decode_returns_none_for_empty() {
        assert!(QuickConfig::decode("").is_none());
        assert!(QuickConfig::decode("[Interface]\nAddress = 10.0.0.1/24").is_none());
    }
}
