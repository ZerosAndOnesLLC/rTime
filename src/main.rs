use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tracing::{error, info};

use rtime_core::config::RtimeConfig;
use rtime_core::timestamp::NtpTimestamp;
use rtime_ntp::client;
use rtime_ntp::packet::{NTP_HEADER_SIZE, NtpPacket};

mod clock_discipline;
mod daemon;
mod management;
mod ntp_client;
mod ntp_server;
mod ptp_node;
#[cfg(unix)]
mod single_instance;

#[derive(Parser)]
#[command(name = "rtime", version, about = "rTime - NTP/PTP time synchronization service")]
struct Cli {
    /// NTP server to query (host:port or just host for default port 123)
    #[arg(short, long)]
    server: Option<String>,

    /// Number of queries to send
    #[arg(short = 'n', long, default_value = "4")]
    count: u32,

    /// Path to config file
    #[arg(short, long, default_value = "/etc/rtime/rtime.toml")]
    config: String,

    /// Run without adjusting system clock
    #[arg(long)]
    no_discipline: bool,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Output logs as JSON (structured logging)
    #[arg(long)]
    json_log: bool,
}

fn resolve_server(server: &str) -> Result<SocketAddr> {
    // If no port specified, append default NTP port
    let addr_str = if server.contains(':') {
        server.to_string()
    } else {
        format!("{}:123", server)
    };

    addr_str
        .to_socket_addrs()
        .context("failed to resolve server address")?
        .next()
        .context("no addresses found for server")
}

fn query_ntp_server(addr: SocketAddr) -> Result<client::NtpResult> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind UDP socket")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .context("failed to set socket timeout")?;

    // Use a random-ish cookie (actual transmit time) for origin matching
    let cookie = NtpTimestamp::now();
    let request = client::build_request(cookie);
    let request_bytes = request.serialize();

    // Record T1 just before sending
    let t1 = NtpTimestamp::now();
    socket
        .send_to(&request_bytes, addr)
        .context("failed to send NTP request")?;

    // Receive response
    let mut buf = [0u8; 512];
    let (len, _from) = socket
        .recv_from(&mut buf)
        .context("failed to receive NTP response (timeout?)")?;

    // Record T4 immediately after receiving
    let t4 = NtpTimestamp::now();

    if len < NTP_HEADER_SIZE {
        bail!("response too short: {} bytes", len);
    }

    let response = NtpPacket::parse(&buf[..len]).context("failed to parse NTP response")?;
    let result =
        client::process_response(&response, t1, t4, cookie).context("failed to process response")?;

    Ok(result)
}

/// Load the rTime configuration from a TOML file.
/// Returns a default config if the file does not exist.
fn load_config(path: &str) -> Result<RtimeConfig> {
    let path = Path::new(path);
    if !path.exists() {
        info!("Config file not found at {}, using defaults", path.display());
        return Ok(RtimeConfig::default());
    }

    let contents = std::fs::read_to_string(path)
        .context(format!("failed to read config file: {}", path.display()))?;

    let config: RtimeConfig = toml::from_str(&contents)
        .context(format!("failed to parse config file: {}", path.display()))?;

    info!("Loaded config from {}", path.display());
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level));

    if cli.json_log {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .init();
    }

    if let Some(server) = &cli.server {
        // Single-query mode: query a specific NTP server.
        run_single_query(server, cli.count).await
    } else {
        // Daemon mode — refuse to start if another rtime instance already
        // holds the lock. Skipped above for one-shot --server queries.
        #[cfg(unix)]
        let _instance_lock = match single_instance::acquire("rtime") {
            Ok(lock) => lock,
            Err(e) => {
                eprintln!("rtime: {e}");
                std::process::exit(1);
            }
        };

        // Daemon mode: load config and run the full daemon.
        let mut config = load_config(&cli.config)?;
        config.validate().context("configuration validation failed")?;

        if cli.no_discipline {
            config.clock.discipline = false;
        }

        info!("rTime v{}", env!("CARGO_PKG_VERSION"));
        info!(
            "Config: {} NTP sources, server={}, listen={}, management={}",
            config.ntp.sources.len(),
            if config.ntp.enabled { "enabled" } else { "disabled" },
            config.ntp.listen,
            if config.management.enabled {
                config.management.listen.as_str()
            } else {
                "disabled"
            },
        );

        let mut daemon = daemon::Daemon::new(config);

        // Set up graceful shutdown on Ctrl+C.
        tokio::select! {
            result = daemon.run() => {
                result
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down");
                Ok(())
            }
        }
    }
}

/// Run the single-query mode against a specific NTP server.
async fn run_single_query(server: &str, count: u32) -> Result<()> {
    let addr = resolve_server(server)?;
    info!("Querying NTP server: {} ({})", server, addr);

    let mut offsets = Vec::new();
    let mut delays = Vec::new();

    for i in 0..count {
        match query_ntp_server(addr) {
            Ok(result) => {
                let offset_ms = result.offset.to_millis_f64();
                let delay_ms = result.delay.to_millis_f64();

                info!(
                    "[{}/{}] offset: {:+.3}ms, delay: {:.3}ms, stratum: {}",
                    i + 1,
                    count,
                    offset_ms,
                    delay_ms,
                    result.stratum,
                );

                offsets.push(offset_ms);
                delays.push(delay_ms);
            }
            Err(e) => {
                error!("[{}/{}] query failed: {}", i + 1, count, e);
            }
        }

        if i + 1 < count {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    if !offsets.is_empty() {
        let avg_offset: f64 = offsets.iter().sum::<f64>() / offsets.len() as f64;
        let avg_delay: f64 = delays.iter().sum::<f64>() / delays.len() as f64;
        let min_delay: f64 = delays.iter().cloned().fold(f64::INFINITY, f64::min);

        // Compute jitter (RMS of successive differences)
        let jitter = if offsets.len() > 1 {
            let sum_sq: f64 = offsets
                .windows(2)
                .map(|w| (w[1] - w[0]).powi(2))
                .sum();
            (sum_sq / (offsets.len() - 1) as f64).sqrt()
        } else {
            0.0
        };

        println!();
        println!("--- {} NTP statistics ---", server);
        println!(
            "{} queries, avg offset: {:+.3}ms, avg delay: {:.3}ms, min delay: {:.3}ms, jitter: {:.3}ms",
            offsets.len(),
            avg_offset,
            avg_delay,
            min_delay,
            jitter,
        );
    }

    Ok(())
}
