#!/usr/bin/env bash
# pipeline.sh — tcpdump | pcap_to_netflow | curl → DeepTempo ingest
#
# Environment:
#   DEEPTEMPO_TOKEN  (required) JWT bearer token
#   DEEPTEMPO_URL    upload base URL              (default: https://ui.deeptempo.ai)
#   CAPTURE_IFACE    network interface            (default: eth0)
#   CAPTURE_FILTER   BPF filter string            (default: "")
#   FLOW_TIMEOUT     pcap_to_netflow --timeout    (default: 120)
#   ROTATE_SECS      tcpdump -G rotation cadence  (default: 60)
#
# Pipeline:
#   tcpdump (rotating pcap segments)
#     → pcap_to_netflow  (each segment → parquet)
#       → curl multipart POST /upload  (Bearer JWT)

set -euo pipefail

# ─── Validate env ─────────────────────────────────────────────────────────────
: "${DEEPTEMPO_TOKEN:?DEEPTEMPO_TOKEN is required}"
BASE_URL="${DEEPTEMPO_URL:-https://ui.deeptempo.ai}"
UPLOAD_URL="${BASE_URL}/upload"
IFACE="${CAPTURE_IFACE:-eth0}"
FILTER="${CAPTURE_FILTER:-}"
TIMEOUT="${FLOW_TIMEOUT:-120}"
ROTATE="${ROTATE_SECS:-60}"

echo "================================================="
echo "  PCAP → NetFlow → DeepTempo"
echo "================================================="
echo "  Interface    : $IFACE"
echo "  BPF filter   : ${FILTER:-<none>}"
echo "  Flow timeout : ${TIMEOUT}s"
echo "  Rotate every : ${ROTATE}s"
echo "  Upload URL   : $UPLOAD_URL"
echo "================================================="

# ─── Scratch dir (tmpfs in k8s via emptyDir medium: Memory) ──────────────────
WORKDIR="$(mktemp -d)"
trap 'kill "${TCPDUMP_PID:-}" 2>/dev/null; rm -rf "$WORKDIR"' EXIT INT TERM

# ─── POST one parquet file to DeepTempo ──────────────────────────────────────
post_parquet() {
    local parquet_file="$1"
    local filename size http_code resp
    filename="$(basename "$parquet_file")"
    size="$(stat -c%s "$parquet_file")"

    echo "  [post] $filename  (${size} bytes) → $UPLOAD_URL"

    http_code=$(curl \
        --silent \
        --show-error \
        --write-out "%{http_code}" \
        --output "$WORKDIR/curl_resp.json" \
        --retry 3 \
        --retry-delay 2 \
        --retry-connrefused \
        -X POST \
        -H "Authorization: Bearer ${DEEPTEMPO_TOKEN}" \
        -F "file=@${parquet_file};type=application/octet-stream" \
        -F "filename=${filename}" \
        "$UPLOAD_URL"
    )

    resp="$(cat "$WORKDIR/curl_resp.json" 2>/dev/null || true)"

    if [[ "$http_code" =~ ^2 ]]; then
        echo "  [post] ✓ HTTP ${http_code}  ${resp}"
    else
        echo "  [post] ✗ HTTP ${http_code}  ${resp}" >&2
        # non-fatal: log and keep pipeline running
    fi
}

# ─── Process one pcap segment ─────────────────────────────────────────────────
process_segment() {
    local pcap_file="$1"
    local parquet_file="${pcap_file%.pcap}.parquet"

    echo "  [convert] $(basename "$pcap_file") ..."
    pcap_to_netflow "$pcap_file" \
        --timeout "$TIMEOUT" \
        -o "$parquet_file" \
        2>&1 | sed 's/^/    /'

    if [[ ! -f "$parquet_file" ]]; then
        echo "  [convert] Warning: no parquet produced — skipping" >&2
        rm -f "$pcap_file"
        return
    fi

    post_parquet "$parquet_file"
    rm -f "$pcap_file" "$parquet_file"
}

# ─── tcpdump with time-based rotation ─────────────────────────────────────────
# -G $ROTATE   new file every N seconds
# -w <pattern> strftime filename — epoch ts ensures chronological sort
# -U           packet-buffered (flush each pkt to disk immediately)
# -n           no reverse DNS

TCPDUMP_ARGS=(
    -i  "$IFACE"
    -w  "$WORKDIR/capture_%s.pcap"
    -G  "$ROTATE"
    -U
    -n
)
[[ -n "$FILTER" ]] && TCPDUMP_ARGS+=("$FILTER")

echo "  [pipeline] Starting tcpdump on $IFACE ..."
tcpdump "${TCPDUMP_ARGS[@]}" 2>&1 | sed 's/^/  [tcpdump] /' &
TCPDUMP_PID=$!

# ─── Rotation watcher ─────────────────────────────────────────────────────────
# tcpdump closes the previous file before opening the next one on each rotation.
# Poll every 5s; process all-but-the-newest (currently open) segment.

LAST_PROCESSED=""
while kill -0 "$TCPDUMP_PID" 2>/dev/null; do
    sleep 5

    mapfile -d '' ALL_SEGS < <(
        find "$WORKDIR" -maxdepth 1 -name 'capture_*.pcap' -print0 2>/dev/null \
        | sort -z
    )

    count="${#ALL_SEGS[@]}"
    (( count <= 1 )) && continue

    for (( i=0; i < count - 1; i++ )); do
        seg="${ALL_SEGS[$i]}"
        [[ "$seg" == "$LAST_PROCESSED" ]] && continue
        LAST_PROCESSED="$seg"
        echo "  [pipeline] Segment ready: $(basename "$seg")"
        process_segment "$seg"
    done
done

echo "  [pipeline] tcpdump exited — flushing remaining segments ..."
for pcap_file in "$WORKDIR"/capture_*.pcap; do
    [[ -f "$pcap_file" ]] && process_segment "$pcap_file"
done

echo "================================================="
echo "  Pipeline complete."
echo "================================================="
