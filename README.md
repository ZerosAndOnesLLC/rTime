# rTime

A high-performance NTP/PTP time synchronization service written in Rust. rTime implements NTPv4 (RFC 5905) with support for NTS (Network Time Security), PTP (IEEE 1588), clock discipline, and Prometheus metrics -- all in a single, lightweight binary.

## Features

- **NTPv4 Client & Server** -- Full NTPv4 implementation with sub-millisecond accuracy
- **Network Time Security (NTS)** -- TLS-based authentication for NTP (RFC 8915)
- **PTP / IEEE 1588** -- Precision Time Protocol support for LAN-level synchronization
- **Clock Discipline** -- PI servo loop with step/slew hybrid adjustment
- **Source Selection** -- Marzullo's algorithm with intersection and clustering
- **Per-IP Rate Limiting** -- Token bucket rate limiter with KoD (Kiss-o'-Death) RATE responses
- **Prometheus Metrics** -- Built-in `/metrics` endpoint for monitoring
- **Structured Logging** -- JSON log output for production observability
- **Minimal Dependencies** -- No paid crates, pure Rust where possible

## Quick Start

### Build

```bash
cargo build --release
```

The binary is produced at `target/release/rtime`.

### Run (single query)

Query an NTP server without running the daemon:

```bash
./target/release/rtime --server time.cloudflare.com -n 4
```

### Run (daemon mode)

Start the full daemon with the example config:

```bash
sudo ./target/release/rtime --config rtime.toml
```

Root (or `CAP_SYS_TIME` + `CAP_NET_BIND_SERVICE`) is required to bind port 123 and adjust the system clock.

### Dry run (no clock adjustment)

```bash
./target/release/rtime --config rtime.toml --no-discipline
```

## Configuration

rTime is configured via a TOML file. See `rtime.toml` for a complete example.

### `[general]`

| Key | Default | Description |
|-----|---------|-------------|
| `log_level` | `"info"` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` |

### `[clock]`

| Key | Default | Description |
|-----|---------|-------------|
| `discipline` | `true` | Enable clock adjustment |
| `step_threshold_ms` | `128` | Offset threshold (ms) above which the clock is stepped instead of slewed |
| `panic_threshold_ms` | `1000` | Offset threshold (ms) above which the daemon refuses to adjust (safety) |
| `interface` | `"system"` | Clock interface (`system` for standard adjtime) |

### `[ntp]`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable the NTP server (respond to client queries) |
| `listen` | `"0.0.0.0:123"` | Address and port to listen on |

### `[[ntp.sources]]`

Each source is an upstream NTP server to synchronize from:

| Key | Required | Description |
|-----|----------|-------------|
| `address` | Yes | Host or host:port of the upstream NTP server |
| `nts` | No | Enable NTS for this source (default `false`) |

### `[metrics]`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable Prometheus metrics endpoint |
| `listen` | `"127.0.0.1:9100"` | Address and port for the metrics HTTP server |

## Docker

### Build the image

```bash
docker build -t rtime .
```

### Run

```bash
docker run -d \
  --name rtime \
  --cap-add SYS_TIME \
  --cap-add NET_BIND_SERVICE \
  -p 123:123/udp \
  -p 9100:9100/tcp \
  -v /path/to/rtime.toml:/etc/rtime/rtime.toml:ro \
  rtime
```

The container exposes:

| Port | Protocol | Service |
|------|----------|---------|
| 123 | UDP | NTP server |
| 4460 | TCP | NTS-KE (when NTS is enabled) |
| 9100 | TCP | Prometheus metrics |

## systemd

A systemd unit file is provided in `deploy/rtime.service`:

```bash
sudo cp target/release/rtime /usr/bin/rtime
sudo mkdir -p /etc/rtime /var/lib/rtime
sudo cp rtime.toml /etc/rtime/rtime.toml
sudo cp deploy/rtime.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rtime
```

The unit file includes security hardening directives (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, etc.) and grants only the capabilities required: `CAP_SYS_TIME` and `CAP_NET_BIND_SERVICE`.

## Metrics

When metrics are enabled, rTime exposes Prometheus-compatible metrics at `http://<listen>/metrics`. Key metrics include:

| Metric | Type | Description |
|--------|------|-------------|
| `rtime_clock_offset_seconds` | Gauge | Current system clock offset |
| `rtime_clock_jitter_seconds` | Gauge | Current clock jitter |
| `rtime_clock_frequency_ppm` | Gauge | Frequency adjustment in PPM |
| `rtime_clock_stratum` | Gauge | Current stratum level |
| `rtime_ntp_packets_received_total` | Counter | Total NTP packets received |
| `rtime_ntp_packets_sent_total` | Counter | Total NTP responses sent |
| `rtime_ntp_packets_dropped_total` | Counter | Total packets dropped (invalid) |
| `rtime_ntp_rate_limited_total` | Counter | Total requests rate-limited (KoD RATE) |
| `rtime_ntp_source_offset_seconds` | Gauge | Per-source offset (labeled by peer) |
| `rtime_ntp_source_delay_seconds` | Gauge | Per-source round-trip delay |
| `rtime_selection_truechimers` | Gauge | Number of truechimers |
| `rtime_selection_falsetickers` | Gauge | Number of falsetickers |
| `rtime_uptime_seconds` | Gauge | Daemon uptime |

## Architecture

```
rtime (binary)
  |
  +-- daemon.rs            Orchestrator: spawns and manages all tasks
  |     |
  |     +-- ntp_client.rs   Per-source NTP client polling loop
  |     +-- ntp_server.rs   NTP server (with rate limiting)
  |     +-- clock_discipline.rs  PI servo clock adjustment loop
  |
  +-- crates/
        +-- rtime-core      Timestamps, config, source selection, servo
        +-- rtime-ntp       NTPv4 packet codec, client/server logic
        +-- rtime-nts       NTS-KE and cookie handling
        +-- rtime-ptp       PTP / IEEE 1588 protocol
        +-- rtime-clock      System clock interface (adjtime, adjtimex)
        +-- rtime-net        Network utilities and timestamping
        +-- rtime-refclock   Reference clock drivers (GPS, PPS)
        +-- rtime-metrics    Prometheus exporter and metric instruments
```

The daemon runs on Tokio's multi-threaded async runtime. Each upstream NTP source gets its own client task. Measurements are sent through an MPSC channel to the selection loop, which runs Marzullo's intersection algorithm to identify truechimers, select a system peer, and compute a system offset. That offset is forwarded via a watch channel to the clock discipline task, which applies PI-controlled slew or step corrections to the system clock.

## License

MIT
