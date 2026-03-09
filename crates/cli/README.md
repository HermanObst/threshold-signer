# mpc-cli

Command-line client for interacting with MPC standalone nodes.

## Installation

```bash
cargo build --release -p mpc-cli
```

The binary is at `target/release/mpc-cli`.

## Usage

All commands accept `--node <URL>` (default: `http://localhost:3001`).

### dkg -- Distributed Key Generation

```bash
mpc-cli dkg --scheme eddsa --node http://localhost:3001
```

Output:
```
Running DKG for scheme: eddsa
DKG complete!
Public key: 3b5f1c...
```

### sign -- Create Threshold Signature

**EdDSA** -- payload is arbitrary bytes (hex-encoded):

```bash
mpc-cli sign --scheme eddsa --payload $(echo -n "hello" | xxd -p)
```

Output:
```json
{
  "signature": "a1b2c3...",
  "public_key": "3b5f1c..."
}
```

**ECDSA** -- payload must be a 32-byte hash (hex-encoded):

```bash
HASH=$(echo -n "hello" | shasum -a 256 | cut -d' ' -f1)
mpc-cli sign --scheme ecdsa --payload $HASH
```

Output:
```json
{
  "r": "7b2261...",
  "s": "4fa3b2...",
  "public_key": "02a1b2..."
}
```

### generate -- ECDSA Preprocessing Assets

Generate Beaver triples (required before presignatures):

```bash
mpc-cli generate --asset triples
```

Generate presignatures (requires triples and a prior ECDSA DKG):

```bash
mpc-cli generate --asset presignatures
```

### verify -- Local Signature Verification

**EdDSA:**

```bash
mpc-cli verify --scheme eddsa \
  --payload <hex> \
  --public-key <32-byte-hex> \
  --signature <64-byte-hex>
```

**ECDSA:**

```bash
mpc-cli verify --scheme ecdsa \
  --payload <32-byte-hash-hex> \
  --public-key <sec1-hex> \
  --signature-r <hex> \
  --signature-s <hex>
```

Output: `Signature is VALID` (exit 0) or `Signature is INVALID` (exit 1).

### status -- Node Status

```bash
mpc-cli status
```

Output:
```
Node Status:
  State: HasBothKeys
  Connected peers: ["0", "1", "2"]
  Presignatures: 3
  Triples: 12
```

### derive-pubkey -- Ed25519 Key Derivation

Derive the Ed25519 public key from a hex-encoded 32-byte secret key:

```bash
mpc-cli derive-pubkey --secret-key <hex>
```

This is used internally by `scripts/generate-p2p-keys.sh` to produce public keys that are compatible with `ed25519-dalek`.

## Verification Details

**ECDSA**: The `r` value from the sign response is `hex(json(AffinePoint))`. The CLI decodes this as hex -> JSON bytes -> `k256::AffinePoint`, then extracts the x-coordinate to reconstruct the standard ECDSA `(r, s)` signature. Verification uses `k256::ecdsa::VerifyingKey::verify_prehash`.

**EdDSA**: The signature is a standard 64-byte Ed25519 signature. Verification uses `ed25519_dalek::VerifyingKey::verify` directly on the raw payload bytes (not hashed).
