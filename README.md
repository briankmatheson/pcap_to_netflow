# pcap_to_netflow

Convert Wireshark PCAP/PCAPNG captures to raw netflow Parquet files.

Reads packet-level data, aggregates into bidirectional flows keyed by
5-tuple `(src_ip, dst_ip, src_port, dst_port, protocol)`, and writes a
Parquet file matching the schema used by `generate_netflow.py`.

## Output schema

| Column       | Type      |
|--------------|-----------|
| timestamp    | timestamp |
| duration     | float64   |
| src_ip       | string    |
| dst_ip       | string    |
| src_port     | int32     |
| dst_port     | int32     |
| protocol     | int32     |
| bytes_out    | int64     |
| bytes_in     | int64     |
| packets_out  | int32     |
| packets_in   | int32     |
| tcp_flags    | string    |

## Build

```sh
# requires Rust ≥ 1.75 and libpcap-dev
sudo apt install libpcap-dev   # Debian/Ubuntu
brew install libpcap            # macOS

make release          # → target/release/pcap_to_netflow
make tarball          # → pcap_to_netflow.tar.gz
make install          # → /usr/local/bin/pcap_to_netflow
```

## Usage

```sh
# Single file — outputs capture_netflow.parquet
pcap_to_netflow capture.pcap

# Explicit output path
pcap_to_netflow capture.pcap -o flows.parquet

# PCAPNG with custom timeout
pcap_to_netflow capture.pcapng --timeout 60

# Merge multiple files into one Parquet
pcap_to_netflow '*.pcap' --merge -o combined.parquet

# Process each file independently
pcap_to_netflow a.pcap b.pcap c.pcap
```

## Flow expiry rules

A flow is closed when either:
- no matching packet has been seen for `--timeout` seconds (default 120), or
- a TCP FIN or RST is observed and the last-seen gap exceeds 1 second.

Remaining open flows at EOF are flushed.
