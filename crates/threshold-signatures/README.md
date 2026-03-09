# threshold-signatures

Pure cryptographic library for threshold signature schemes. No networking, no I/O -- all protocols are expressed as state machines via the `Protocol` trait.

## Supported Schemes

| Scheme | Curve | Use Case | Offline Phase | Online Signing |
|--------|-------|----------|---------------|----------------|
| OT-based ECDSA | Secp256k1 | Bitcoin, Ethereum signatures | Triple generation + Presigning | 1 round |
| Robust ECDSA | Secp256k1 | Secp256k1 without preprocessing | Presigning (3 rounds, no triples) | 1 round |
| EdDSA (FROST) | Ed25519 | Ed25519 signatures | Optional presigning | 1-2 rounds |
| RedDSA (FROST) | JubJub | Zcash Spend Authorization (ZIP-312) | Optional presigning | 1-2 rounds |
| CKD | BLS12-381 | Confidential key derivation | -- | OT-based protocol |

All schemes share the same DKG implementation (`dkg.rs`), which is generic over the `Ciphersuite` trait.

## Key Concepts

### Protocol Trait

All cryptographic operations are expressed as state machines:

```rust
trait Protocol {
    type Output;
    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError>;
    fn message(&mut self, from: Participant, data: MessageData);
}

enum Action<T> {
    Wait,                              // Need more messages
    SendMany(MessageData),             // Broadcast to all participants
    SendPrivate(Participant, MessageData),  // Send to one participant
    Return(T),                         // Protocol complete
}
```

The caller drives the protocol by calling `poke()` in a loop, sending messages as directed, and delivering incoming messages via `message()`.

### Participants

`Participant(u32)` identifies a party. `ParticipantList` is a sorted, deduplicated collection with O(1) lookup and Lagrange coefficient computation.

### Thresholds

Two threshold types exist:

- `ReconstructionLowerBound(t)` -- minimum shares needed to reconstruct. Used by OT-based ECDSA, EdDSA, CKD. Requires `N >= t` participants.
- `MaxMalicious(t)` -- max tolerated malicious parties. Used by Robust ECDSA. Requires exactly `N = 2t + 1` participants.

### Ciphersuite Trait

Extends `frost_core::Ciphersuite` with byte ordering metadata (`BigEndian` for Secp256k1, `LittleEndian` for Ed25519/JubJub/BLS12-381).

## Module Map

| Module | Description | Details |
|--------|-------------|---------|
| `protocol/` | Protocol trait, SharedChannel, PrivateChannel, Waitpoint, Echo Broadcast | [protocol/README.md](src/protocol/README.md) |
| `crypto/` | Ciphersuite trait, polynomials, commitments, hashing, randomness | [crypto/README.md](src/crypto/README.md) |
| `crypto/proofs/` | Maurer NIZK sigma proofs (dlog, dlogeq) with Fiat-Shamir | [crypto/proofs/README.md](src/crypto/proofs/README.md) |
| `ecdsa/` | OT-based and Robust ECDSA over Secp256k1 | [ecdsa/README.md](src/ecdsa/README.md) |
| `ecdsa/ot_based_ecdsa/` | Triple generation, presigning, signing | [ecdsa/ot_based_ecdsa/README.md](src/ecdsa/ot_based_ecdsa/README.md) |
| `ecdsa/robust_ecdsa/` | Presigning and signing without triples | [ecdsa/robust_ecdsa/README.md](src/ecdsa/robust_ecdsa/README.md) |
| `frost/` | FROST threshold signatures for EdDSA and RedDSA | [frost/README.md](src/frost/README.md) |
| `confidential_key_derivation/` | BLS12-381 key derivation with OT and ElGamal | [confidential_key_derivation/README.md](src/confidential_key_derivation/README.md) |
| `dkg.rs` | Shared DKG, reshare, and refresh protocols. Generic over `Ciphersuite`. Uses echo broadcast (tolerates n/3 malicious). |
| `participants.rs` | `Participant`, `ParticipantList`, Lagrange coefficient computation |
| `thresholds.rs` | `MaxMalicious`, `ReconstructionLowerBound` |
| `errors.rs` | Error types for protocol initialization and execution |

## DKG

The `dkg` module provides three operations, all generic over `Ciphersuite`:

- **`keygen`** -- Initial distributed key generation. Each participant gets a signing share; no single party knows the full key.
- **`reshare`** -- Redistribute key shares to a new participant set (possibly with a new threshold).
- **`refresh`** -- Re-randomize shares among the same participants and threshold.

All three use echo broadcast for reliable delivery and Schnorr proofs-of-knowledge for coefficient commitments. The echo broadcast limits Byzantine tolerance to `n/3` malicious parties.

All network-dependent functions wait indefinitely for messages -- the caller is responsible for implementing timeouts.
