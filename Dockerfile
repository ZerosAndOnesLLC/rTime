FROM rust:1.83-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/rtime /usr/bin/rtime
COPY rtime.toml /etc/rtime/rtime.toml
EXPOSE 123/udp 4460/tcp 9100/tcp
ENTRYPOINT ["/usr/bin/rtime"]
CMD ["--config", "/etc/rtime/rtime.toml"]
