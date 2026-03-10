#!/usr/bin/env bash
set -euo pipefail

# End-to-end test: spawn nodes, run DKG, sign "hello herman", verify.
# Usage: ./test-e2e.sh [N] [T]
#   N: number of nodes (default: 3)
#   T: threshold (default: 2)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
CONFIG_DIR="$ROOT_DIR/config"

N=${1:-3}
T=${2:-2}
NODE_URL="http://127.0.0.1:3001"
PASS=0
FAIL=0

# Track child PIDs for cleanup
PIDS=()
cleanup() {
    echo ""
    echo "Cleaning up..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo ""
    echo "================================"
    echo "Results: $PASS passed, $FAIL failed"
    if (( FAIL > 0 )); then
        echo "FAIL"
        exit 1
    else
        echo "ALL TESTS PASSED"
    fi
}
trap cleanup EXIT INT TERM

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

echo "=== MPC E2E Test: $N nodes, threshold $T ==="
echo ""

# Step 1: Build binaries (must happen before setup-nodes.sh which uses mpc-cli)
echo "--- Building binaries ---"
cargo build --release -p threshold-signer-node -p mpc-cli --manifest-path "$ROOT_DIR/Cargo.toml"

NODE_BIN="$ROOT_DIR/target/release/threshold-signer-node"
CLI="$ROOT_DIR/target/release/mpc-cli"

# Step 2: Generate configs
echo ""
echo "--- Generating configs ---"
bash "$SCRIPT_DIR/setup-nodes.sh" "$N" "$T" --local

AES_KEY=$(cat "$CONFIG_DIR/aes.key")

# Step 3: Start nodes
echo ""
echo "--- Starting $N nodes ---"

for (( i=1; i<=N; i++ )); do
    DATA_DIR="$ROOT_DIR/data/node${i}"
    rm -rf "$DATA_DIR"
    mkdir -p "$DATA_DIR"
    LOG_FILE="$ROOT_DIR/data/node${i}.log"

    MPC_AES_KEY="$AES_KEY" RUST_LOG="${RUST_LOG:-info}" \
        "$NODE_BIN" \
        --config "$CONFIG_DIR/node${i}.yaml" \
        --secret-key "$CONFIG_DIR/node${i}.key" \
        > "$LOG_FILE" 2>&1 &
    PIDS+=($!)
    echo "  Started node${i} (pid ${PIDS[-1]})"
done

# Step 4: Wait for all nodes ready
echo ""
echo "--- Waiting for nodes to be ready ---"

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
        for (( i=1; i<=N; i++ )); do
            echo "--- node${i} log (last 20 lines) ---"
            tail -20 "$ROOT_DIR/data/node${i}.log" || true
        done
        exit 1
    fi
    for idx in "${!PIDS[@]}"; do
        pid="${PIDS[$idx]}"
        if ! kill -0 "$pid" 2>/dev/null; then
            node_num=$((idx + 1))
            echo "Error: node${node_num} (pid $pid) died"
            tail -20 "$ROOT_DIR/data/node${node_num}.log" || true
            exit 1
        fi
    done
    sleep "$INTERVAL"
    ELAPSED=$((ELAPSED + INTERVAL))
    printf "."
done

echo ""
echo "All $N nodes ready!"

# Helper: the message we'll sign
MESSAGE="hello herman"
MESSAGE_HEX=$(echo -n "$MESSAGE" | xxd -p | tr -d '\n')

echo ""
echo "================================"
echo "=== Test: EdDSA Flow ==="
echo "================================"

# EdDSA DKG
echo ""
echo "--- EdDSA DKG ---"
EDDSA_DKG_OUT=$("$CLI" dkg --scheme eddsa --node "$NODE_URL" 2>&1)
echo "$EDDSA_DKG_OUT"

EDDSA_PK=$(echo "$EDDSA_DKG_OUT" | grep "Public key:" | awk '{print $3}')
if [[ -n "$EDDSA_PK" ]]; then
    pass "EdDSA DKG returned public key"
else
    fail "EdDSA DKG did not return public key"
fi

# EdDSA Sign
echo ""
echo "--- EdDSA Sign ---"
EDDSA_SIGN_OUT=$("$CLI" sign --scheme eddsa --payload "$MESSAGE_HEX" --node "$NODE_URL" 2>&1)
echo "$EDDSA_SIGN_OUT"

EDDSA_SIG=$(echo "$EDDSA_SIGN_OUT" | python3 -c "
import sys, json
lines = sys.stdin.read()
# Extract JSON from output (skip 'Signature result:' and 'Signing with scheme:' lines)
json_start = lines.index('{')
data = json.loads(lines[json_start:])
print(data.get('signature', ''))
" 2>/dev/null || echo "")

EDDSA_SIG_PK=$(echo "$EDDSA_SIGN_OUT" | python3 -c "
import sys, json
lines = sys.stdin.read()
json_start = lines.index('{')
data = json.loads(lines[json_start:])
print(data.get('public_key', ''))
" 2>/dev/null || echo "")

if [[ -n "$EDDSA_SIG" ]]; then
    pass "EdDSA sign returned signature"
else
    fail "EdDSA sign did not return signature"
fi

# EdDSA Verify
echo ""
echo "--- EdDSA Verify ---"
if [[ -n "$EDDSA_SIG" && -n "$EDDSA_SIG_PK" ]]; then
    VERIFY_OUT=$("$CLI" verify --scheme eddsa --payload "$MESSAGE_HEX" --signature "$EDDSA_SIG" --public-key "$EDDSA_SIG_PK" 2>&1)
    echo "$VERIFY_OUT"
    if echo "$VERIFY_OUT" | grep -q "VALID"; then
        pass "EdDSA signature verified"
    else
        fail "EdDSA signature verification failed"
    fi
else
    fail "EdDSA verify skipped (missing signature or public key)"
fi

echo ""
echo "================================"
echo "=== Test: ECDSA Flow ==="
echo "================================"

# ECDSA DKG
echo ""
echo "--- ECDSA DKG ---"
ECDSA_DKG_OUT=$("$CLI" dkg --scheme ecdsa --node "$NODE_URL" 2>&1)
echo "$ECDSA_DKG_OUT"

ECDSA_PK=$(echo "$ECDSA_DKG_OUT" | grep "Public key:" | awk '{print $3}')
if [[ -n "$ECDSA_PK" ]]; then
    pass "ECDSA DKG returned public key"
else
    fail "ECDSA DKG did not return public key"
fi

# ECDSA: Generate triples
echo ""
echo "--- Generate Triples ---"
TRIPLES_OUT=$("$CLI" generate --asset triples --node "$NODE_URL" 2>&1)
echo "$TRIPLES_OUT"
if echo "$TRIPLES_OUT" | grep -q "Generated"; then
    pass "Generated triples"
else
    fail "Failed to generate triples"
fi

# ECDSA: Generate presignatures
echo ""
echo "--- Generate Presignatures ---"
PRESIG_OUT=$("$CLI" generate --asset presignatures --node "$NODE_URL" 2>&1)
echo "$PRESIG_OUT"
if echo "$PRESIG_OUT" | grep -q "Generated"; then
    pass "Generated presignatures"
else
    fail "Failed to generate presignatures"
fi

# ECDSA Sign (payload must be 32-byte hash)
echo ""
echo "--- ECDSA Sign ---"
ECDSA_HASH=$(echo -n "$MESSAGE" | shasum -a 256 | cut -d' ' -f1)
echo "SHA-256(\"$MESSAGE\") = $ECDSA_HASH"

ECDSA_SIGN_OUT=$("$CLI" sign --scheme ecdsa --payload "$ECDSA_HASH" --node "$NODE_URL" 2>&1)
echo "$ECDSA_SIGN_OUT"

ECDSA_R=$(echo "$ECDSA_SIGN_OUT" | python3 -c "
import sys, json
lines = sys.stdin.read()
json_start = lines.index('{')
data = json.loads(lines[json_start:])
print(data.get('r', ''))
" 2>/dev/null || echo "")

ECDSA_S=$(echo "$ECDSA_SIGN_OUT" | python3 -c "
import sys, json
lines = sys.stdin.read()
json_start = lines.index('{')
data = json.loads(lines[json_start:])
print(data.get('s', ''))
" 2>/dev/null || echo "")

ECDSA_SIG_PK=$(echo "$ECDSA_SIGN_OUT" | python3 -c "
import sys, json
lines = sys.stdin.read()
json_start = lines.index('{')
data = json.loads(lines[json_start:])
print(data.get('public_key', ''))
" 2>/dev/null || echo "")

if [[ -n "$ECDSA_R" && -n "$ECDSA_S" ]]; then
    pass "ECDSA sign returned (r, s)"
else
    fail "ECDSA sign did not return (r, s)"
fi

# ECDSA Verify
echo ""
echo "--- ECDSA Verify ---"
if [[ -n "$ECDSA_R" && -n "$ECDSA_S" && -n "$ECDSA_SIG_PK" ]]; then
    VERIFY_OUT=$("$CLI" verify --scheme ecdsa --payload "$ECDSA_HASH" --signature-r "$ECDSA_R" --signature-s "$ECDSA_S" --public-key "$ECDSA_SIG_PK" 2>&1)
    echo "$VERIFY_OUT"
    if echo "$VERIFY_OUT" | grep -q "VALID"; then
        pass "ECDSA signature verified"
    else
        fail "ECDSA signature verification failed"
    fi
else
    fail "ECDSA verify skipped (missing r, s, or public key)"
fi

# Final status check
echo ""
echo "--- Final Status ---"
"$CLI" status --node "$NODE_URL"
