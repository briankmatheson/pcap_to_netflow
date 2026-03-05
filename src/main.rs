//! Convert Wireshark PCAP/PCAPNG captures to raw netflow Parquet files.
//!
//! Reads packet-level data, aggregates into bidirectional flows keyed by
//! 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol), and writes a
//! Parquet file matching the schema used by generate_netflow.py.
//!
//! Output columns:
//!   timestamp, duration, src_ip, dst_ip, src_port, dst_port,
//!   protocol, bytes_out, bytes_in, packets_out, packets_in, tcp_flags
//!
//! Usage:
//!   pcap_to_netflow capture.pcap
//!   pcap_to_netflow capture.pcap -o flows.parquet
//!   pcap_to_netflow capture.pcapng --timeout 120
//!   pcap_to_netflow '*.pcap' --merge -o combined.parquet

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use arrow::array::{
    ArrayRef, Float64Array, Int32Array, Int64Array, StringArray,
    TimestampMicrosecondArray,
};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use chrono::DateTime;
use clap::Parser;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use pcap_file::PcapError;

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "pcap_to_netflow",
    about = "Convert PCAP/PCAPNG captures to netflow Parquet files",
    version
)]
struct Cli {
    /// PCAP/PCAPNG file(s) or glob patterns
    #[arg(required = true)]
    inputs: Vec<String>,

    /// Output Parquet file path (default: <input>_netflow.parquet)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Flow inactivity timeout in seconds
    #[arg(long, default_value = "120.0")]
    timeout: f64,

    /// Merge all input files into a single output Parquet
    #[arg(long)]
    merge: bool,
}

// ─── Flow types ──────────────────────────────────────────────────────────────

/// Canonical 5-tuple key (always src < dst so both directions share one entry)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

#[derive(Debug)]
struct Flow {
    first_seen: f64,
    last_seen: f64,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    bytes_out: i64,
    bytes_in: i64,
    packets_out: i32,
    packets_in: i32,
    /// union of all observed TCP flag bytes
    tcp_flags: u8,
}

// ─── Packet parsing ───────────────────────────────────────────────────────────

/// Raw info extracted from a single packet
struct PktInfo {
    ts: f64,
    len: usize,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    tcp_flags: u8,
}

fn parse_packet(data: &[u8], ts: f64) -> Option<PktInfo> {
    let sliced = SlicedPacket::from_ethernet(data)
        .or_else(|_| SlicedPacket::from_ip(data))
        .ok()?;

    let (src_ip, dst_ip, proto) = match &sliced.net {
        Some(InternetSlice::Ipv4(h, _)) => (
            h.source_addr().to_string(),
            h.destination_addr().to_string(),
            h.protocol().0,
        ),
        Some(InternetSlice::Ipv6(h, _)) => (
            h.source_addr().to_string(),
            h.destination_addr().to_string(),
            h.next_header().0,
        ),
        _ => return None,
    };

    let (src_port, dst_port, tcp_flags) = match &sliced.transport {
        Some(TransportSlice::Tcp(t)) => (t.source_port(), t.destination_port(), t.slice()[13]),
        Some(TransportSlice::Udp(u)) => (u.source_port(), u.destination_port(), 0u8),
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => (0, 0, 0u8),
        _ => (0, 0, 0u8),
    };

    Some(PktInfo {
        ts,
        len: data.len(),
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        tcp_flags,
    })
}

/// Returns (canonical_key, is_reverse)
fn canonical_key(p: &PktInfo) -> (FlowKey, bool) {
    let forward = (&p.src_ip, p.src_port) <= (&p.dst_ip, p.dst_port);
    if forward {
        (
            FlowKey {
                src_ip: p.src_ip.clone(),
                dst_ip: p.dst_ip.clone(),
                src_port: p.src_port,
                dst_port: p.dst_port,
                proto: p.proto,
            },
            false,
        )
    } else {
        (
            FlowKey {
                src_ip: p.dst_ip.clone(),
                dst_ip: p.src_ip.clone(),
                src_port: p.dst_port,
                dst_port: p.src_port,
                proto: p.proto,
            },
            true,
        )
    }
}

// ─── PCAP reading (both formats) ─────────────────────────────────────────────

/// Yields (timestamp_secs, packet_bytes) from a PCAP or PCAPNG file.
fn iter_packets(path: &Path) -> Result<Vec<(f64, Vec<u8>)>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut out: Vec<(f64, Vec<u8>)> = Vec::new();

    if ext == "pcapng" || ext == "npcapng" {
        let f = File::open(path)
            .with_context(|| format!("open {}", path.display()))?;
        let mut reader = PcapNgReader::new(BufReader::new(f))
            .map_err(|e| anyhow::anyhow!("pcapng open: {e}"))?;

        loop {
            match reader.next_block() {
                Some(Ok(block)) => {
                    use pcap_file::pcapng::blocks::PcapNgBlock;
                    if let PcapNgBlock::EnhancedPacket(ep) = block.into_block() {
                        // timestamp is in interface units; default is microseconds
                        let ts_us = ep.timestamp;
                        let ts = ts_us as f64 / 1_000_000.0;
                        out.push((ts, ep.data.into_owned()));
                    }
                }
                Some(Err(e)) => {
                    eprintln!("  Warning: block read error: {e}");
                    break;
                }
                None => break,
            }
        }
    } else {
        // Treat as PCAP (including .cap)
        let f = File::open(path)
            .with_context(|| format!("open {}", path.display()))?;
        let mut reader = PcapReader::new(BufReader::new(f))
            .map_err(|e| anyhow::anyhow!("pcap open: {e}"))?;

        loop {
            match reader.next_packet() {
                Some(Ok(pkt)) => {
                    let ts = pkt.header.ts_sec as f64
                        + pkt.header.ts_usec as f64 / 1_000_000.0;
                    out.push((ts, pkt.data.into_owned()));
                }
                Some(Err(PcapError::IoError(e))) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Some(Err(e)) => {
                    eprintln!("  Warning: packet read error: {e}");
                    break;
                }
                None => break,
            }
        }
    }

    Ok(out)
}

// ─── Flow aggregation ─────────────────────────────────────────────────────────

fn aggregate_flows(pcap_files: &[PathBuf], flow_timeout: f64) -> Vec<Flow> {
    let mut active: HashMap<FlowKey, Flow> = HashMap::new();
    let mut finished: Vec<Flow> = Vec::new();
    let mut total_packets: u64 = 0;
    let mut skipped: u64 = 0;

    for path in pcap_files {
        println!("  Reading {} ...", path.display());

        let packets = match iter_packets(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  Error reading {}: {e}", path.display());
                continue;
            }
        };

        for (ts, data) in &packets {
            total_packets += 1;

            let pkt_info = match parse_packet(data, *ts) {
                Some(p) => p,
                None => {
                    skipped += 1;
                    continue;
                }
            };

            let (key, is_reverse) = canonical_key(&pkt_info);
            let pkt_len = data.len() as i64;

            // Check existing flow for expiry
            if let Some(flow) = active.get(&key) {
                let gap = ts - flow.last_seen;
                let fin_rst = pkt_info.tcp_flags & 0x05 != 0;
                if gap > flow_timeout || (fin_rst && gap > 1.0) {
                    let done = active.remove(&key).unwrap();
                    finished.push(done);
                }
            }

            // Insert new flow if needed
            if !active.contains_key(&key) {
                active.insert(
                    key.clone(),
                    Flow {
                        first_seen: *ts,
                        last_seen: *ts,
                        src_ip: key.src_ip.clone(),
                        dst_ip: key.dst_ip.clone(),
                        src_port: key.src_port,
                        dst_port: key.dst_port,
                        protocol: key.proto,
                        bytes_out: 0,
                        bytes_in: 0,
                        packets_out: 0,
                        packets_in: 0,
                        tcp_flags: 0,
                    },
                );
            }

            let flow = active.get_mut(&key).unwrap();
            flow.last_seen = *ts;
            flow.tcp_flags |= pkt_info.tcp_flags;

            if !is_reverse {
                flow.bytes_out += pkt_len;
                flow.packets_out += 1;
            } else {
                flow.bytes_in += pkt_len;
                flow.packets_in += 1;
            }

            if total_packets % 100_000 == 0 {
                println!(
                    "    ... {:>10} packets processed, {:>6} active flows",
                    total_packets,
                    active.len()
                );
            }
        }
    }

    for flow in active.into_values() {
        finished.push(flow);
    }

    println!("\n  Packets processed : {:>10}", total_packets);
    println!("  Packets skipped   : {:>10}", skipped);
    println!("  Flows extracted   : {:>10}", finished.len());

    // Sort by first_seen ascending
    finished.sort_by(|a, b| a.first_seen.partial_cmp(&b.first_seen).unwrap());
    finished
}

// ─── Parquet output ───────────────────────────────────────────────────────────

fn flows_to_parquet(flows: &[Flow], out_path: &Path) -> Result<usize> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("timestamp",    DataType::Timestamp(TimeUnit::Microsecond, None), false),
        Field::new("duration",     DataType::Float64, false),
        Field::new("src_ip",       DataType::Utf8, false),
        Field::new("dst_ip",       DataType::Utf8, false),
        Field::new("src_port",     DataType::Int32, false),
        Field::new("dst_port",     DataType::Int32, false),
        Field::new("protocol",     DataType::Int32, false),
        Field::new("bytes_out",    DataType::Int64, false),
        Field::new("bytes_in",     DataType::Int64, false),
        Field::new("packets_out",  DataType::Int32, false),
        Field::new("packets_in",   DataType::Int32, false),
        Field::new("tcp_flags",    DataType::Utf8, false),
    ]));

    let mut timestamps: Vec<i64>  = Vec::with_capacity(flows.len());
    let mut durations:  Vec<f64>  = Vec::with_capacity(flows.len());
    let mut src_ips:    Vec<&str> = Vec::with_capacity(flows.len());
    let mut dst_ips:    Vec<&str> = Vec::with_capacity(flows.len());
    let mut src_ports:  Vec<i32>  = Vec::with_capacity(flows.len());
    let mut dst_ports:  Vec<i32>  = Vec::with_capacity(flows.len());
    let mut protocols:  Vec<i32>  = Vec::with_capacity(flows.len());
    let mut bytes_out:  Vec<i64>  = Vec::with_capacity(flows.len());
    let mut bytes_in:   Vec<i64>  = Vec::with_capacity(flows.len());
    let mut pkts_out:   Vec<i32>  = Vec::with_capacity(flows.len());
    let mut pkts_in:    Vec<i32>  = Vec::with_capacity(flows.len());
    let flags_hex: Vec<String>    = flows
        .iter()
        .map(|f| format!("{:#04x}", f.tcp_flags))
        .collect();

    for f in flows {
        let dt = DateTime::from_timestamp(
            f.first_seen as i64,
            ((f.first_seen.fract()) * 1e9) as u32,
        )
        .unwrap_or_default();
        timestamps.push(dt.timestamp_micros());
        durations.push((f.last_seen - f.first_seen * 1000.0).round() / 1000.0);
        src_ips.push(&f.src_ip);
        dst_ips.push(&f.dst_ip);
        src_ports.push(f.src_port as i32);
        dst_ports.push(f.dst_port as i32);
        protocols.push(f.protocol as i32);
        bytes_out.push(f.bytes_out);
        bytes_in.push(f.bytes_in);
        pkts_out.push(f.packets_out);
        pkts_in.push(f.packets_in);
    }

    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(TimestampMicrosecondArray::from(timestamps)) as ArrayRef,
            Arc::new(Float64Array::from(durations))               as ArrayRef,
            Arc::new(StringArray::from(src_ips))                  as ArrayRef,
            Arc::new(StringArray::from(dst_ips))                  as ArrayRef,
            Arc::new(Int32Array::from(src_ports))                 as ArrayRef,
            Arc::new(Int32Array::from(dst_ports))                 as ArrayRef,
            Arc::new(Int32Array::from(protocols))                 as ArrayRef,
            Arc::new(Int64Array::from(bytes_out))                 as ArrayRef,
            Arc::new(Int64Array::from(bytes_in))                  as ArrayRef,
            Arc::new(Int32Array::from(pkts_out))                  as ArrayRef,
            Arc::new(Int32Array::from(pkts_in))                   as ArrayRef,
            Arc::new(StringArray::from(
                flags_hex.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            ))                                                     as ArrayRef,
        ],
    )?;

    let file = File::create(out_path)
        .with_context(|| format!("create {}", out_path.display()))?;
    let props = WriterProperties::builder()
        .set_compression(parquet::basic::Compression::SNAPPY)
        .build();
    let mut writer = ArrowWriter::try_new(file, schema, Some(props))?;
    writer.write(&batch)?;
    writer.close()?;

    Ok(flows.len())
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Expand globs
    let mut pcap_files: Vec<PathBuf> = Vec::new();
    for pattern in &cli.inputs {
        let matches: Vec<PathBuf> = glob::glob(pattern)
            .with_context(|| format!("bad glob: {pattern}"))?
            .filter_map(|r| r.ok())
            .collect();
        if matches.is_empty() {
            eprintln!("Warning: no files matched '{pattern}'");
        }
        pcap_files.extend(matches);
    }
    pcap_files.sort();

    if pcap_files.is_empty() {
        anyhow::bail!("no input files found");
    }

    println!("{}", "=".repeat(56));
    println!("  PCAP → NetFlow Parquet Converter");
    println!("{}", "=".repeat(56));
    println!("  Input files  : {}", pcap_files.len());
    println!("  Flow timeout : {}s", cli.timeout);
    println!();

    if cli.merge || pcap_files.len() == 1 {
        println!("Aggregating flows ...");
        let flows = aggregate_flows(&pcap_files, cli.timeout);

        let out_path = cli.output.clone().unwrap_or_else(|| {
            let base = pcap_files[0].with_extension("");
            PathBuf::from(format!("{}_netflow.parquet", base.display()))
        });

        let rows = flows_to_parquet(&flows, &out_path)?;
        let fsize = std::fs::metadata(&out_path)?.len();

        println!("\n  Output : {}", out_path.display());
        println!("  Rows   : {rows:>10}");
        println!("  Size   : {:.1} KB", fsize as f64 / 1024.0);
    } else {
        for pcap_file in &pcap_files {
            println!("\n{}", "─".repeat(56));
            println!("Processing: {}", pcap_file.display());

            let flows = aggregate_flows(&[pcap_file.clone()], cli.timeout);

            let base = pcap_file.with_extension("");
            let out_path = PathBuf::from(format!("{}_netflow.parquet", base.display()));

            let rows = flows_to_parquet(&flows, &out_path)?;

            println!("  Output : {}", out_path.display());
            println!("  Rows   : {rows:>10}");
        }
    }

    println!("\n{}", "=".repeat(56));
    println!("  Done.");
    println!("{}", "=".repeat(56));
    Ok(())
}
