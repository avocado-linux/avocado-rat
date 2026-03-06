use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct RatConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
    #[serde(default)]
    pub timers: TimerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimerConfig {
    #[serde(default = "default_status_check_secs")]
    pub status_check_secs: u64,
    #[serde(default = "default_stale_threshold_secs")]
    pub stale_threshold_secs: u64,
    #[serde(default = "default_interface_up_timeout_secs")]
    pub interface_up_timeout_secs: u64,
    #[serde(default = "default_ttl_secs")]
    pub default_ttl_secs: u64,
}

fn default_data_dir() -> String {
    "/var/lib/avocado-rat".to_string()
}

fn default_socket_path() -> String {
    "/run/avocado-rat.sock".to_string()
}

fn default_status_check_secs() -> u64 {
    10
}

fn default_stale_threshold_secs() -> u64 {
    120
}

fn default_interface_up_timeout_secs() -> u64 {
    10
}

fn default_ttl_secs() -> u64 {
    3600
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            status_check_secs: default_status_check_secs(),
            stale_threshold_secs: default_stale_threshold_secs(),
            interface_up_timeout_secs: default_interface_up_timeout_secs(),
            default_ttl_secs: default_ttl_secs(),
        }
    }
}

impl Default for RatConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            socket_path: default_socket_path(),
            timers: TimerConfig::default(),
        }
    }
}

impl RatConfig {
    pub fn default_path() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("AVOCADO_RAT_CONFIG") {
            return Ok(PathBuf::from(p));
        }
        let dir = dirs::config_dir()
            .context("Could not determine config directory")?
            .join("avocado-rat");
        Ok(dir.join("config.toml"))
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(path)?;
        let config: RatConfig = toml::from_str(&data)?;
        Ok(config)
    }

    pub fn data_dir_path(&self) -> PathBuf {
        PathBuf::from(&self.data_dir)
    }

    pub fn conf_dir(&self) -> PathBuf {
        self.data_dir_path().join("conf")
    }
}
