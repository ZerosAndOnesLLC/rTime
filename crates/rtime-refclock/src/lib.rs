#[cfg(feature = "gps")]
pub mod gps;
#[cfg(feature = "pps")]
pub mod pps;

#[derive(Debug, thiserror::Error)]
pub enum RefClockError {
    #[error("device not found: {0}")]
    DeviceNotFound(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PPS: no edge detected within timeout")]
    PpsTimeout,
}
