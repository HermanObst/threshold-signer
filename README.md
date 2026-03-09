# Threshold Signer

Standalone threshold MPC node for distributed ECDSA (Secp256k1) and EdDSA (Ed25519) signatures. Nodes form a P2P mesh, run distributed key generation, and produce threshold signatures without any single party holding the complete key.

This project is extracted from the [NEAR MPC](https://github.com/near/mpc) repository, with all NEAR blockchain dependencies removed. The core cryptographic protocols (`threshold-signatures` crate) and TLS transport (`tls` crate) are taken directly from the upstream project. The `node` and `cli` crates are rewritten to run as a standalone P2P network driven by HTTP API calls instead of an on-chain contract.

Built on [FROST](https://eprint.iacr.org/2020/852) for EdDSA and an [OT-based protocol](https://github.com/cronokirby/cait-sith) (derived from Cait-Sith) for ECDSA.

## Architecture

```
+-------------------+     +-------------------+     +-------------------+
|      Node 1       |     |      Node 2       |     |      Node 3       |
|  (HTTP API :3001) |<--->|  (HTTP API :3002) |<--->|  (HTTP API :3003) |
|  (P2P TLS :10001) |     |  (P2P TLS :10002) |     |  (P2P TLS :10003) |
+-------------------+     +-------------------+     +-------------------+
         |                         |                         |
         +---------+---------------+---------+---------------+
                   |                         |
          +--------+--------+       +--------+--------+
          | threshold-sigs  |       |       tls       |
          | (crypto library)|       | (mTLS transport)|
          +-----------------+       +-----------------+
```

Four workspace crates:

| Crate | Type | Purpose |
|-------|------|---------|
| `threshold-signatures` | Library | Pure cryptographic protocols: ECDSA, EdDSA (FROST), CKD (BLS12-381). No networking or I/O. |
| `node` | Binary | MPC node: P2P mesh, orchestrator, HTTP API. Wires crypto protocols to network transport. |
| `tls` | Library | Mutual TLS (mTLS) using Ed25519 identity keys for P2P authentication. |
| `cli` | Binary | Command-line client for interacting with running MPC nodes. |

## Quick Start (Docker)

1. **Generate keys** for a 3-node network with threshold 2:

   ```bash
   ./scripts/generate-p2p-keys.sh 3 2
   ```

   This creates `config/node{1,2,3}.yaml`, `config/node{1,2,3}.key`, and `config/aes.key`.

2. **Set the AES key** in `docker/docker-compose.yml`. Copy the key from `config/aes.key`:

   ```bash
   export MPC_AES_KEY=$(cat config/aes.key)
   ```

3. **Start the network**:

   ```bash
   cd docker && docker compose up --build
   ```

4. **Wait** for `"All peers connected!"` in the logs.

5. **Interact via CLI**:

   ```bash
   cargo run -p mpc-cli -- dkg --scheme eddsa --node http://localhost:3001
   ```

## Quick Start (Local)

Launch all nodes as local processes:

```bash
./scripts/launch-localnet.sh 3 2
```

This builds the binaries, generates configs with `--local`, starts 3 nodes, and waits for them to connect. Use the CLI against `http://localhost:3001`.

Flags:
- `--no-build` -- skip the `cargo build` step

## CLI Reference

Install: `cargo build --release -p mpc-cli`

All commands accept `--node <URL>` (default: `http://localhost:3001`).

| Command | Description | Example |
|---------|-------------|---------|
| `dkg` | Run distributed key generation | `mpc-cli dkg --scheme eddsa` |
| `sign` | Create a threshold signature | `mpc-cli sign --scheme eddsa --payload 68656c6c6f` |
| `verify` | Verify a signature locally | See below |
| `generate` | Generate ECDSA triples or presignatures | `mpc-cli generate --asset triples` |
| `status` | Query node state and peer info | `mpc-cli status` |
| `derive-pubkey` | Derive Ed25519 public key from secret | `mpc-cli derive-pubkey --secret-key <hex>` |

### Verification

**EdDSA:**

```bash
mpc-cli verify --scheme eddsa \
  --payload <hex> \
  --public-key <hex> \
  --signature <hex>
```

**ECDSA:**

```bash
mpc-cli verify --scheme ecdsa \
  --payload <32-byte-hash-hex> \
  --public-key <sec1-hex> \
  --signature-r <hex> \
  --signature-s <hex>
```

The `--signature-r` value is the hex encoding of the JSON-serialized `AffinePoint` returned by the sign endpoint. The CLI decodes this to extract the x-coordinate as the ECDSA `r` scalar.

## Full Signing Walkthrough

### EdDSA (2 steps: DKG then sign)

```bash
# 1. Distributed key generation
mpc-cli dkg --scheme eddsa --node http://localhost:3001
# Output: Public key: <hex>

# 2. Sign a message (arbitrary bytes as hex)
PAYLOAD=$(echo -n "hello" | xxd -p)
mpc-cli sign --scheme eddsa --payload $PAYLOAD --node http://localhost:3001
# Output: { "signature": "<hex>", "public_key": "<hex>" }

# 3. Verify
mpc-cli verify --scheme eddsa \
  --payload $PAYLOAD \
  --public-key <public_key from sign> \
  --signature <signature from sign>
```

### ECDSA (4 steps: DKG, triples, presignatures, sign)

```bash
# 1. Distributed key generation
mpc-cli dkg --scheme ecdsa --node http://localhost:3001

# 2. Generate Beaver triples (offline preprocessing)
mpc-cli generate --asset triples --node http://localhost:3001

# 3. Generate presignatures (consumes 2 triples each)
mpc-cli generate --asset presignatures --node http://localhost:3001

# 4. Sign a 32-byte hash
HASH=$(echo -n "hello" | shasum -a 256 | cut -d' ' -f1)
mpc-cli sign --scheme ecdsa --payload $HASH --node http://localhost:3001
# Output: { "r": "<hex>", "s": "<hex>", "public_key": "<hex>" }

# 5. Verify
mpc-cli verify --scheme ecdsa \
  --payload $HASH \
  --public-key <public_key> \
  --signature-r <r> \
  --signature-s <s>
```

## Running Tests

**End-to-end tests** (builds, spawns nodes, runs DKG + sign + verify for both schemes):

```bash
./scripts/test-e2e.sh
```

**Unit and integration tests**:

```bash
cargo test
```

## Configuration

Node configs are YAML files generated by `scripts/generate-p2p-keys.sh`. Key fields:

```yaml
node_name: node1           # Must match a participant name
p2p_port: 10001            # TLS P2P port
api_port: 3001             # HTTP API port
data_dir: /data/node1      # RocksDB storage directory

triple:                     # ECDSA triple generation tuning
  concurrency: 2
  desired_triples_to_buffer: 128
  timeout_sec: 120

presignature:               # ECDSA presignature tuning
  concurrency: 4
  desired_presignatures_to_buffer: 64
  timeout_sec: 120

signature:
  timeout_sec: 60

keygen:
  timeout_sec: 120

participants:
  threshold: 2              # Min participants needed for signing
  participants:
    - id: 0
      name: node1
      address: node1        # Hostname or IP
      port: 10001
      p2p_public_key: <hex> # Ed25519 public key
```

Environment variables:
- `MPC_AES_KEY` -- hex-encoded AES-128 key for encrypting local RocksDB storage
- `RUST_LOG` -- tracing filter (default: `info`)

## Project Structure

```
threshold-signer/
  crates/
    threshold-signatures/  -- Pure crypto: ECDSA, EdDSA (FROST), CKD, DKG
    node/                  -- MPC node binary: P2P mesh, orchestrator, HTTP API
    tls/                   -- Mutual TLS with Ed25519 identity keys
    cli/                   -- CLI client for interacting with nodes
  scripts/
    generate-p2p-keys.sh   -- Generate Ed25519 P2P identity keys and YAML configs
    launch-localnet.sh     -- Launch local multi-node network
    test-e2e.sh            -- End-to-end test suite
  docker/
    Dockerfile             -- Multi-stage build for node + CLI
    docker-compose.yml     -- 3-node Docker Compose setup
  config/                  -- Generated node configs (gitignored)
  data/                    -- Runtime data directories (gitignored)
```
