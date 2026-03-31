use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tracing::{error, info};

use rtime_core::timestamp::NtpTimestamp;
use rtime_ntp::client;
use rtime_ntp::packet::{NTP_HEADER_SIZE, NtpPacket};

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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .init();

    if let Some(server) = &cli.server {
        let addr = resolve_server(server)?;
        info!("Querying NTP server: {} ({})", server, addr);

        let mut offsets = Vec::new();
        let mut delays = Vec::new();

        for i in 0..cli.count {
            match query_ntp_server(addr) {
                Ok(result) => {
                    let offset_ms = result.offset.to_millis_f64();
                    let delay_ms = result.delay.to_millis_f64();

                    info!(
                        "[{}/{}] offset: {:+.3}ms, delay: {:.3}ms, stratum: {}",
                        i + 1,
                        cli.count,
                        offset_ms,
                        delay_ms,
                        result.stratum,
                    );

                    offsets.push(offset_ms);
                    delays.push(delay_ms);
                }
                Err(e) => {
                    error!("[{}/{}] query failed: {}", i + 1, cli.count, e);
                }
            }

            if i + 1 < cli.count {
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
    } else {
        info!("rTime v{}", env!("CARGO_PKG_VERSION"));
        info!("No server specified. Use --server <host> to query an NTP server.");
        info!("Full daemon mode coming in Phase 2.");
    }

    Ok(())
}
