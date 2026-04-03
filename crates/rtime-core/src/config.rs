use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RtimeConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub clock: ClockConfig,
    #[serde(default)]
    pub ntp: NtpConfig,
    #[serde(default)]
    pub ptp: PtpConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub management: ManagementConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClockConfig {
    #[serde(default = "default_true")]
    pub discipline: bool,
    #[serde(default = "default_step_threshold_ms")]
    pub step_threshold_ms: f64,
    #[serde(default = "default_panic_threshold_ms")]
    pub panic_threshold_ms: f64,
    #[serde(default = "default_clock_interface")]
    pub interface: String,
}

impl Default for ClockConfig {
    fn default() -> Self {
        Self {
            discipline: true,
            step_threshold_ms: default_step_threshold_ms(),
            panic_threshold_ms: default_panic_threshold_ms(),
            interface: default_clock_interface(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_step_threshold_ms() -> f64 {
    128.0
}

fn default_panic_threshold_ms() -> f64 {
    1000.0
}

fn default_clock_interface() -> String {
    "system".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct NtpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ntp_listen")]
    pub listen: String,
    #[serde(default = "default_rate_limit")]
    pub rate_limit: f64,
    #[serde(default = "default_rate_burst")]
    pub rate_burst: u32,
    #[serde(default)]
    pub nts: NtsConfig,
    #[serde(default)]
    pub sources: Vec<NtpSourceConfig>,
}

impl Default for NtpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_ntp_listen(),
            rate_limit: default_rate_limit(),
            rate_burst: default_rate_burst(),
            nts: NtsConfig::default(),
            sources: Vec::new(),
        }
    }
}

fn default_ntp_listen() -> String {
    "0.0.0.0:123".into()
}

fn default_rate_limit() -> f64 {
    16.0
}

fn default_rate_burst() -> u32 {
    32
}

#[derive(Debug, Clone, Deserialize)]
pub struct NtsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_nts_ke_listen")]
    pub ke_listen: String,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
}

impl Default for NtsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ke_listen: default_nts_ke_listen(),
            certificate: None,
            private_key: None,
        }
    }
}

fn default_nts_ke_listen() -> String {
    "0.0.0.0:4460".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct NtpSourceConfig {
    pub address: String,
    #[serde(default)]
    pub nts: bool,
    #[serde(default = "default_min_poll")]
    pub min_poll: i8,
    #[serde(default = "default_max_poll")]
    pub max_poll: i8,
}

fn default_min_poll() -> i8 {
    4
}

fn default_max_poll() -> i8 {
    10
}

#[derive(Debug, Clone, Deserialize)]
pub struct PtpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domain: u8,
    #[serde(default = "default_ptp_interface")]
    pub interface: String,
    #[serde(default = "default_ptp_transport")]
    pub transport: String,
    #[serde(default = "default_priority")]
    pub priority1: u8,
    #[serde(default = "default_priority")]
    pub priority2: u8,
    #[serde(default = "default_delay_mechanism")]
    pub delay_mechanism: String,
}

impl Default for PtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domain: 0,
            interface: default_ptp_interface(),
            transport: default_ptp_transport(),
            priority1: default_priority(),
            priority2: default_priority(),
            delay_mechanism: default_delay_mechanism(),
        }
    }
}

fn default_ptp_interface() -> String {
    "eth0".into()
}

fn default_ptp_transport() -> String {
    "udp-ipv4".into()
}

fn default_priority() -> u8 {
    128
}

fn default_delay_mechanism() -> String {
    "e2e".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_listen")]
    pub listen: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_metrics_listen(),
        }
    }
}

fn default_metrics_listen() -> String {
    "127.0.0.1:9100".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagementConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_management_listen")]
    pub listen: String,
    /// Optional bearer token for API authentication.
    /// If set, all management API requests must include
    /// `Authorization: Bearer <token>` header.
    pub api_key: Option<String>,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_management_listen(),
            api_key: None,
        }
    }
}

fn default_management_listen() -> String {
    "127.0.0.1:9200".into()
}

impl RtimeConfig {
    /// Validate configuration values after deserialization.
    /// Returns an error describing the first invalid value found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Clock thresholds must be positive and finite
        if !self.clock.step_threshold_ms.is_finite() || self.clock.step_threshold_ms <= 0.0 {
            return Err(ConfigError::InvalidValue(
                "clock.step_threshold_ms must be a positive finite number".into(),
            ));
        }
        if !self.clock.panic_threshold_ms.is_finite() || self.clock.panic_threshold_ms <= 0.0 {
            return Err(ConfigError::InvalidValue(
                "clock.panic_threshold_ms must be a positive finite number".into(),
            ));
        }

        // Rate limiting values
        if !self.ntp.rate_limit.is_finite() || self.ntp.rate_limit <= 0.0 {
            return Err(ConfigError::InvalidValue(
                "ntp.rate_limit must be a positive finite number".into(),
            ));
        }
        if self.ntp.rate_burst == 0 {
            return Err(ConfigError::InvalidValue(
                "ntp.rate_burst must be greater than 0".into(),
            ));
        }

        // Validate poll intervals for each source
        for (i, source) in self.ntp.sources.iter().enumerate() {
            if source.min_poll < 0 || source.min_poll > 17 {
                return Err(ConfigError::InvalidValue(
                    format!("ntp.sources[{}].min_poll must be between 0 and 17", i),
                ));
            }
            if source.max_poll < 0 || source.max_poll > 17 {
                return Err(ConfigError::InvalidValue(
                    format!("ntp.sources[{}].max_poll must be between 0 and 17", i),
                ));
            }
            if source.min_poll > source.max_poll {
                return Err(ConfigError::InvalidValue(
                    format!("ntp.sources[{}].min_poll must be <= max_poll", i),
                ));
            }
        }

        // Validate listen addresses are parseable
        self.ntp.listen.parse::<std::net::SocketAddr>().map_err(|_| {
            ConfigError::InvalidValue(format!("invalid ntp.listen address: {}", self.ntp.listen))
        })?;
        if self.metrics.enabled {
            self.metrics.listen.parse::<std::net::SocketAddr>().map_err(|_| {
                ConfigError::InvalidValue(format!(
                    "invalid metrics.listen address: {}",
                    self.metrics.listen
                ))
            })?;
        }
        if self.management.enabled {
            self.management.listen.parse::<std::net::SocketAddr>().map_err(|_| {
                ConfigError::InvalidValue(format!(
                    "invalid management.listen address: {}",
                    self.management.listen
                ))
            })?;
        }
        if self.ntp.nts.enabled {
            self.ntp.nts.ke_listen.parse::<std::net::SocketAddr>().map_err(|_| {
                ConfigError::InvalidValue(format!(
                    "invalid nts.ke_listen address: {}",
                    self.ntp.nts.ke_listen
                ))
            })?;
        }

        // Warn-level checks: non-loopback management/metrics
        let mgmt_addr: std::net::SocketAddr = self.management.listen.parse().unwrap_or_else(|_| {
            "127.0.0.1:9200".parse().unwrap()
        });
        if self.management.enabled && !mgmt_addr.ip().is_loopback() {
            tracing::warn!(
                "Management API listen address {} is non-loopback and has no authentication",
                self.management.listen
            );
        }

        let metrics_addr: std::net::SocketAddr = self.metrics.listen.parse().unwrap_or_else(|_| {
            "127.0.0.1:9100".parse().unwrap()
        });
        if self.metrics.enabled && !metrics_addr.ip().is_loopback() {
            tracing::warn!(
                "Metrics endpoint listen address {} is non-loopback and has no authentication",
                self.metrics.listen
            );
        }

        Ok(())
    }
}

/// Configuration validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid config value: {0}")]
    InvalidValue(String),
}
