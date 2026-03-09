# FROST Module

[FROST](https://eprint.iacr.org/2020/852) (Flexible Round-Optimized Schnorr Threshold) signatures for EdDSA and RedDSA.

## Overview

FROST is a threshold Schnorr signature scheme. A `t`-of-`n` group of participants can collaboratively produce a valid Schnorr signature without any party learning the full signing key. This module wraps the `frost-core` library with the `Protocol` trait interface used throughout the crate.

## Supported Curves

| Type | Curve | Hash | Crate |
|------|-------|------|-------|
| `Ed25519Sha512` | Curve25519 | SHA-512 | `frost-ed25519` |
| `JubjubBlake2b512` | JubJub | Blake2b-512 | `reddsa` |

EdDSA uses standard Ed25519. RedDSA follows [ZIP-312](https://zips.z.cash/zip-0312) for Zcash Spend Authorization.

## Key Types

```rust
// Output of DKG: a private signing share and the group's public verifying key
struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    pub public_key: VerifyingKey<C>,
}

// Output of presigning: nonces and commitments for all participants
struct PresignOutput<C: Ciphersuite> {
    pub nonces: SigningNonces<C>,
    pub commitments_map: BTreeMap<Identifier<C>, SigningCommitments<C>>,
}

// Arguments for presigning
struct PresignArguments<C: Ciphersuite> {
    pub keygen_out: KeygenOutput<C>,
    pub threshold: ReconstructionLowerBound,
}
```

## Signing Flows

### v1: 2-round signing (without presignature)

Used when no presignature is available. Requires an RNG.

```
Round 1: Each participant generates (nonce, commitment)
         Coordinator collects all commitments

Round 2: Coordinator distributes the signing package (message + all commitments)
         Each participant produces a signature share
         Coordinator aggregates shares into the final signature
```

The coordinator receives `Some(signature)`. Non-coordinator participants receive `None`.

### v2: 1-round signing (with presignature)

Used when a `PresignOutput` has been pre-computed. No RNG needed at signing time.

```
Round 1: Coordinator distributes the signing package
         (commitments are already known from the presign phase)
         Each participant produces a signature share
         Coordinator aggregates shares into the final signature
```

### Presign Protocol

Generates nonces and commitments offline for faster online signing:

1. Each participant calls `frost::round1::commit()` to generate a `(SigningNonces, SigningCommitments)` pair
2. Commitments are exchanged and stored as `PresignOutput`
3. At signing time, `sign_v2()` uses the stored nonces/commitments directly

## Coordinator vs Participant

In both signing flows:
- The **coordinator** collects signature shares, aggregates the final signature, and returns `Some(signature)`.
- **Participants** produce their signature share and return `None`.

This maps to the node's leader-centric computation pattern: the leader is always the coordinator.

## Module Structure

```
frost/
  mod.rs               -- PresignArguments, PresignOutput, presign() function
  eddsa/
    mod.rs             -- Ed25519 type aliases (KeygenOutput, PresignArguments, PresignOutput)
    sign.rs            -- sign_v1() and sign_v2() for Ed25519
    test.rs            -- EdDSA signing tests
  redjubjub/
    mod.rs             -- JubJub type aliases
    sign.rs            -- sign_v1() and sign_v2() for RedDSA
    test.rs            -- RedDSA signing tests
```
