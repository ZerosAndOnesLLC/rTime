FROM rust:1.86-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libcap2-bin && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/rtime /usr/bin/rtime
RUN setcap 'cap_sys_time,cap_net_bind_service+ep' /usr/bin/rtime
RUN useradd -r -s /usr/sbin/nologin rtime
USER rtime
EXPOSE 123/udp 4460/tcp 9100/tcp
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD ["/usr/bin/rtime", "--server", "127.0.0.1", "-n", "1"] || exit 1
ENTRYPOINT ["/usr/bin/rtime"]
CMD ["--config", "/etc/rtime/rtime.toml"]
