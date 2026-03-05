# syntax=docker/dockerfile:1
FROM debian:bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential pkg-config \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust via rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && strip target/release/pcap_to_netflow

# ─── Runtime image ────────────────────────────────────────────────────────────
FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    curl \
    ca-certificates \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/pcap_to_netflow /usr/local/bin/pcap_to_netflow
COPY pipeline.sh /usr/local/bin/pipeline.sh
RUN chmod +x /usr/local/bin/pipeline.sh

# Non-root user — give tcpdump cap via setcap instead of running as root
RUN setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

ENV INGEST_URL=""
ENV CAPTURE_IFACE="eth0"
ENV CAPTURE_FILTER=""
ENV FLOW_TIMEOUT="120"

ENTRYPOINT ["/usr/local/bin/pipeline.sh"]
