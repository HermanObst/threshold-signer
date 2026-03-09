# threshold-signer-node

The MPC node binary. Manages a P2P mesh of threshold-signing participants, exposes an HTTP API for key generation and signing, and orchestrates all MPC protocols.

## Startup Flow

1. Load YAML config and Ed25519 secret key from disk
2. Create TLS mesh network (`p2p.rs`) using the secret key for mutual authentication
3. Start `MeshNetworkClient` with task-based channel multiplexing
4. Wait for all configured peers to connect
5. Create `Orchestrator` and spawn the incoming-channel handler for follower processing
6. Start Axum HTTP API server

## Module Map

```
main.rs              -- Entry point: CLI args, config loading, wiring
orchestrator.rs      -- State machine, manages keyshares/triples/presignatures
api.rs               -- Axum HTTP endpoints (POST /dkg, /sign, /generate; GET /status)
config.rs            -- YAML config structs (StandaloneConfigFile, ParticipantsConfig)
protocol.rs          -- Bridges Protocol trait to NetworkTaskChannel (poke/message loop)
p2p.rs               -- TLS mesh: persistent TCP connections, Borsh packets, ping keepalive
db.rs                -- AES-encrypted RocksDB persistence
primitives.rs        -- Domain types: ParticipantId, UniqueId, MpcTaskId, MpcMessage
tracking.rs          -- Task-local progress tracking, AutoAbortTask
network/
  mod.rs             -- MeshNetworkClient: task-based channel multiplexing, leader selection
  computation.rs     -- MpcLeaderCentricComputation trait
providers/
  mod.rs             -- Provider trait wiring
  ecdsa/             -- ECDSA providers: key_generation, triple, presign, sign
  eddsa/             -- EdDSA providers: key_generation, sign
```

## Orchestrator State Machine

The `Orchestrator` replaces the NEAR-based Coordinator from the upstream MPC repo. It manages state via direct API calls instead of monitoring a blockchain contract.

```
WaitingForPeers --> Ready --> HasEcdsaKey / HasEddsaKey --> HasBothKeys
```

- **WaitingForPeers**: Not enough connected peers to meet threshold
- **Ready**: Enough peers connected, no keys generated yet
- **HasEcdsaKey / HasEddsaKey**: One scheme's DKG has completed
- **HasBothKeys**: Both ECDSA and EdDSA DKG complete

The orchestrator holds in-memory:
- ECDSA and EdDSA keyshares (from DKG)
- A queue of ECDSA Beaver triples
- A queue of ECDSA presignatures

## HTTP API

| Method | Path | Request Body | Description |
|--------|------|-------------|-------------|
| POST | `/dkg` | `{ "scheme": "ecdsa"\|"eddsa" }` | Run distributed key generation |
| POST | `/sign` | `{ "scheme": "...", "payload": "<hex>" }` | Create threshold signature |
| POST | `/generate` | `{ "asset": "triples"\|"presignatures" }` | Generate ECDSA preprocessing assets |
| GET | `/status` | -- | Node state, connected peers, asset counts |

## Leader-Centric Computation

All MPC operations follow the same pattern via `MpcLeaderCentricComputation`:

```
Leader                              Followers
  |                                    |
  |-- new_channel_for_task(id, ...) -->|
  |                                    |
  |====== Start message =============>|  (leader sends Start to all)
  |                                    |
  |<======= Protocol rounds =========>|  (both sides run Protocol via run_protocol)
  |                                    |
  |<========= Success ================|  (followers confirm completion)
  |                                    |
  +-- returns result                   +-- stores result locally
```

The leader creates the channel, sends a `Start` message to all followers, then both sides execute the cryptographic protocol. On success, followers send a `Success` message back; on failure, an `Abort` propagates to all participants.

## Message Flow

```
Protocol::poke()      returns Action::SendMany / SendPrivate
    |
run_protocol()        batches messages per-participant, sends via channel
    |
NetworkTaskChannel    multiplexes by MpcTaskId over the transport
    |
TlsMeshSender         Borsh-serializes Packet, writes to TLS stream
    |
TLS TCP connection    persistent, auto-reconnecting, 5s ping keepalive
```

## P2P Transport Details

- **TLS 1.3** with mutual authentication (Ed25519 identity keys)
- **Borsh** serialization for wire packets
- **Ping keepalive**: every 5 seconds
- **Reconnect delay**: 1 second
- **Max message size**: 100 MB
- **Packet types**: `Ping`, `Mpc(MpcMessage)`
