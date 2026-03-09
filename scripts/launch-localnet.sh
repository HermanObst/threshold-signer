#!/usr/bin/env bash
set -euo pipefail

# Launch N MPC nodes locally for testing.
# Usage: ./launch-localnet.sh [N] [T] [--no-build]
#   N: number of nodes (default: 3)
#   T: threshold (default: 2)
#   --no-build: skip cargo build step

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
CONFIG_DIR="$ROOT_DIR/config"

BUILD=true
POSITIONAL=()
for arg in "$@"; do
    if [[ "$arg" == "--no-build" ]]; then
        BUILD=false
    elif [[ "$arg" =~ ^[0-9]+$ ]]; then
        POSITIONAL+=("$arg")
    fi
done
N="${POSITIONAL[0]:-3}"
T="${POSITIONAL[1]:-2}"

echo "=== MPC Localnet: $N nodes, threshold $T ==="

# Track child PIDs for cleanup
PIDS=()
cleanup() {
    echo ""
    echo "Shutting down nodes..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo "All nodes stopped."
}
trap cleanup EXIT INT TERM

# Step 1: Build binaries (must happen before generate-p2p-keys.sh which uses mpc-cli)
if $BUILD; then
    echo "Building binaries..."
    cargo build --release -p threshold-signer-node -p mpc-cli --manifest-path "$ROOT_DIR/Cargo.toml"
fi

NODE_BIN="$ROOT_DIR/target/release/threshold-signer-node"
CLI_BIN="$ROOT_DIR/target/release/mpc-cli"

if [[ ! -x "$NODE_BIN" ]]; then
    echo "Error: node binary not found at $NODE_BIN"
    exit 1
fi

# Step 2: Generate configs with --local
echo ""
echo "Generating configs for $N nodes (local mode)..."
bash "$SCRIPT_DIR/generate-p2p-keys.sh" "$N" "$T" --local

# Read AES key
AES_KEY=$(cat "$CONFIG_DIR/aes.key")

# Step 3: Create data directories and spawn nodes
echo ""
echo "Starting $N nodes..."

for (( i=1; i<=N; i++ )); do
    DATA_DIR="$ROOT_DIR/data/node${i}"
    mkdir -p "$DATA_DIR"

    API_PORT=$((3000 + i))
    LOG_FILE="$ROOT_DIR/data/node${i}.log"

    echo "  Starting node${i} (api=:${API_PORT}, p2p=:$((10000 + i)))..."
    MPC_AES_KEY="$AES_KEY" RUST_LOG="${RUST_LOG:-info}" \
        "$NODE_BIN" \
        --config "$CONFIG_DIR/node${i}.yaml" \
        --secret-key "$CONFIG_DIR/node${i}.key" \
        > "$LOG_FILE" 2>&1 &

    PIDS+=($!)
done

# Step 4: Wait for all nodes to be ready
echo ""
echo "Waiting for nodes to be ready..."

MAX_WAIT=120
INTERVAL=2
ELAPSED=0

all_ready() {
    for (( i=1; i<=N; i++ )); do
        API_PORT=$((3000 + i))
        if ! curl -sf "http://127.0.0.1:${API_PORT}/status" > /dev/null 2>&1; then
            return 1
        fi
    done
    return 0
}

while ! all_ready; do
    if (( ELAPSED >= MAX_WAIT )); then
        echo "Error: nodes did not become ready within ${MAX_WAIT}s"
        echo "Check logs in data/node*.log"
        exit 1
    fi
    # Check if any node process has died
    for idx in "${!PIDS[@]}"; do
        pid="${PIDS[$idx]}"
        if ! kill -0 "$pid" 2>/dev/null; then
            node_num=$((idx + 1))
            echo "Error: node${node_num} (pid $pid) exited unexpectedly"
            echo "Log: $ROOT_DIR/data/node${node_num}.log"
            cat "$ROOT_DIR/data/node${node_num}.log" | tail -20
            exit 1
        fi
    done
    sleep "$INTERVAL"
    ELAPSED=$((ELAPSED + INTERVAL))
    printf "."
done

echo ""
echo "All $N nodes are ready!"
echo ""
echo "=== Node endpoints ==="
for (( i=1; i<=N; i++ )); do
    echo "  node${i}: http://127.0.0.1:$((3000 + i))"
done
echo ""
echo "=== CLI usage ==="
echo "  CLI=$CLI_BIN"
echo "  \$CLI status --node http://localhost:3001"
echo "  \$CLI dkg --scheme eddsa --node http://localhost:3001"
echo "  \$CLI sign --scheme eddsa --payload \$(echo -n 'hello herman' | xxd -p) --node http://localhost:3001"
echo ""
echo "Logs: data/node*.log"
echo "Press Ctrl-C to stop all nodes."
echo ""

# Keep running until interrupted
wait
