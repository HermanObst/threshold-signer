# mpc-tls

Mutual TLS (mTLS) transport for MPC node P2P communication using Ed25519 identity keys.

## How It Works

Each MPC node has an Ed25519 keypair (the P2P identity key). The TLS layer uses these keys for mutual authentication:

1. A **hardcoded dummy CA** signs certificates for all nodes. The CA private key is embedded in `constants.rs` -- it is not secret. Authentication comes from verifying that the peer's Ed25519 public key (extracted from their certificate) matches the expected key from the config, not from certificate trust.

2. **TLS 1.3 only**, with mandatory client certificate verification on both sides (true mTLS).

3. After the TLS handshake, `extract_public_key()` reads the peer's Ed25519 public key from their certificate. The P2P layer uses this to confirm the peer's identity matches the participant list.

```
Node A                                          Node B
  |                                               |
  |-- TLS ClientHello (with client cert) -------->|
  |<-- TLS ServerHello (with server cert) --------|
  |                                               |
  |  Both sides verify peer cert was signed       |
  |  by the dummy CA, then extract the Ed25519    |
  |  public key from the peer's certificate.      |
  |                                               |
  |<============ Encrypted channel ==============>|
```

## Public API

```rust
// Main setup: creates both server and client TLS configs from a signing key
fn configure_tls(p2p_private_key: &SigningKey) -> (ServerConfig, ClientConfig)

// After handshake: extract peer's Ed25519 public key from the TLS session
fn extract_public_key(common_state: &CommonState) -> VerifyingKey
```

## Module Map

| File | Purpose |
|------|---------|
| `tls.rs` | `configure_tls()` and `extract_public_key()`. Builds server/client TLS configs with mTLS, issues peer certificates signed by the dummy CA. |
| `keygen.rs` | `raw_ed25519_secret_key_to_keypair()`. Converts `ed25519_dalek::SigningKey` to PKCS8-encoded `rcgen::KeyPair` by manually constructing the DER payload (16-byte header + 32-byte private key + 3-byte middle + 32-byte public key). |
| `constants.rs` | `DUMMY_ISSUER_PRIVATE_KEY` (PEM Ed25519 key), `SERVER_NAME` ("dummy"), `ROOT_CERT` ("root"), `TLS_PROTOCOL_VERSION` (TLS 1.3). |

## Dependencies

- `rustls` -- TLS protocol implementation
- `rcgen` -- X.509 certificate generation (Ed25519 via `PKCS_ED25519`)
- `ed25519-dalek` -- Ed25519 signing and verification
- `x509-parser` -- X.509 DER parsing for public key extraction
