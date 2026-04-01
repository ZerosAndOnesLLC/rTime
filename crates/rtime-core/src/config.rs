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
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_management_listen(),
        }
    }
}

fn default_management_listen() -> String {
    "127.0.0.1:9200".into()
}
