#!/usr/bin/env bash
set -euo pipefail

# Generate Ed25519 P2P keys and AES keys for N MPC nodes.
# Usage: ./generate-p2p-keys.sh [N] [T] [--local]
#   N: number of nodes (default: 3)
#   T: threshold (default: 2)
#   --local: use 127.0.0.1 instead of Docker hostnames, ./data/nodeN instead of /data/nodeN

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/../config"
mkdir -p "$CONFIG_DIR"

# Parse arguments: positional N T, plus --local flag
LOCAL=false
POSITIONAL=()
for arg in "$@"; do
    if [[ "$arg" == "--local" ]]; then
        LOCAL=true
    elif [[ "$arg" =~ ^[0-9]+$ ]]; then
        POSITIONAL+=("$arg")
    fi
done
N="${POSITIONAL[0]:-3}"
T="${POSITIONAL[1]:-2}"

# Validate
if (( T > N )); then
    echo "Error: threshold T=$T must be <= number of nodes N=$N"
    exit 1
fi

echo "Generating keys for $N MPC nodes (threshold=$T, local=$LOCAL)..."

generate_hex_key() {
    local size=$1
    openssl rand -hex "$size"
}

# Locate or build the mpc-cli binary for Ed25519 key derivation
ROOT_DIR="$SCRIPT_DIR/.."
CLI_BIN="$ROOT_DIR/target/release/mpc-cli"
if [[ ! -x "$CLI_BIN" ]]; then
    CLI_BIN="$ROOT_DIR/target/debug/mpc-cli"
fi
if [[ ! -x "$CLI_BIN" ]]; then
    echo "Building mpc-cli for key derivation..."
    cargo build -p mpc-cli --manifest-path "$ROOT_DIR/Cargo.toml" 2>/dev/null
    CLI_BIN="$ROOT_DIR/target/debug/mpc-cli"
fi

# Generate N Ed25519 key pairs
KEYS=()
PUB_KEYS=()

for (( i=1; i<=N; i++ )); do
    SECRET_KEY=$(generate_hex_key 32)
    KEYS+=("$SECRET_KEY")

    # Derive public key using the Rust CLI (guaranteed compatible with ed25519-dalek)
    PUB_KEY=$("$CLI_BIN" derive-pubkey --secret-key "$SECRET_KEY")
    PUB_KEYS+=("$PUB_KEY")

    echo "Node $i:"
    echo "  Secret key: $SECRET_KEY"
    echo "  Public key: $PUB_KEY"

    echo "$SECRET_KEY" > "$CONFIG_DIR/node${i}.key"
done

# Generate AES key
AES_KEY=$(generate_hex_key 16)
echo ""
echo "AES-128 key: $AES_KEY"

# Build participants YAML block
build_participants() {
    local indent="$1"
    for (( j=1; j<=N; j++ )); do
        local idx=$((j - 1))
        local addr
        if $LOCAL; then
            addr="127.0.0.1"
        else
            addr="node${j}"
        fi
        local p2p_port=$((10000 + j))
        echo "${indent}- id: ${idx}"
        echo "${indent}  name: node${j}"
        echo "${indent}  address: ${addr}"
        echo "${indent}  port: ${p2p_port}"
        echo "${indent}  p2p_public_key: ${PUB_KEYS[$idx]}"
    done
}

PARTICIPANTS_BLOCK=$(build_participants "    ")

# Write config files
for (( i=1; i<=N; i++ )); do
    local_data_dir="./data/node${i}"
    docker_data_dir="/data/node${i}"
    if $LOCAL; then
        data_dir="$local_data_dir"
    else
        data_dir="$docker_data_dir"
    fi

    p2p_port=$((10000 + i))
    api_port=$((3000 + i))

    cat > "$CONFIG_DIR/node${i}.yaml" <<EOF
node_name: node${i}
p2p_port: ${p2p_port}
api_port: ${api_port}
data_dir: ${data_dir}

triple:
  concurrency: 2
  desired_triples_to_buffer: 128
  timeout_sec: 120
  parallel_triple_generation_stagger_time_sec: 1

presignature:
  concurrency: 4
  desired_presignatures_to_buffer: 64
  timeout_sec: 120

signature:
  timeout_sec: 60

keygen:
  timeout_sec: 120

participants:
  threshold: ${T}
  participants:
${PARTICIPANTS_BLOCK}
EOF
done

echo ""
echo "Generated config files in $CONFIG_DIR/"
echo "Secret key files: $(for (( i=1; i<=N; i++ )); do printf "node${i}.key "; done)"
echo ""
echo "To use with Docker, set MPC_AES_KEY=$AES_KEY"
echo "$AES_KEY" > "$CONFIG_DIR/aes.key"
