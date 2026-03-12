use anyhow::Context;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use threshold_signatures::participants::Participant;

/// A unique ID representing a resource (e.g., a triple/presignature/signature, or a channel).
/// The ID shall be globally unique across all participants and across time.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UniqueId(u128);

impl UniqueId {
    pub fn new(participant_id: ParticipantId, timestamp: u64, counter: u32) -> Self {
        let id =
            ((participant_id.raw() as u128) << 96) | ((timestamp as u128) << 32) | counter as u128;
        Self(id)
    }

    pub fn generate(participant_id: ParticipantId) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self::new(participant_id, now, 0)
    }

    pub fn participant_id(&self) -> ParticipantId {
        ParticipantId::from_raw((self.0 >> 96) as u32)
    }

    pub fn timestamp(&self) -> u64 {
        ((self.0 >> 32) & ((1u128 << 64) - 1)) as u64
    }

    pub fn counter(&self) -> u32 {
        (self.0 & ((1u128 << 32) - 1)) as u32
    }

    pub fn prefix_for_participant_id(participant_id: ParticipantId) -> Vec<u8> {
        participant_id.raw().to_be_bytes().to_vec()
    }

    pub fn pick_new_after(&self) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > self.timestamp() {
            Self::new(self.participant_id(), now, 0)
        } else {
            Self::new(self.participant_id(), self.timestamp(), self.counter() + 1)
        }
    }

    pub fn add_to_counter(&self, delta: u32) -> anyhow::Result<Self> {
        let new_counter = self
            .counter()
            .checked_add(delta)
            .context("Counter overflow")?;
        Ok(Self::new(
            self.participant_id(),
            self.timestamp(),
            new_counter,
        ))
    }
}

impl Debug for UniqueId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UniqueId")
            .field(&self.participant_id())
            .field(&self.timestamp())
            .field(&self.counter())
            .finish()
    }
}

impl BorshSerialize for UniqueId {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_be_bytes())
    }
}

impl BorshDeserialize for UniqueId {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; 16];
        reader.read_exact(&mut bytes)?;
        Ok(Self(u128::from_be_bytes(bytes)))
    }
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct ParticipantId(u32);

impl From<Participant> for ParticipantId {
    fn from(participant: Participant) -> Self {
        ParticipantId(participant.into())
    }
}

impl From<ParticipantId> for Participant {
    fn from(participant_id: ParticipantId) -> Self {
        Participant::from(participant_id.0)
    }
}

impl ParticipantId {
    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn from_raw(raw: u32) -> Self {
        ParticipantId(raw)
    }
}

impl Display for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A batched list of multiple cait-sith protocol messages.
pub type BatchedMessages = Vec<Vec<u8>>;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BorshSerialize, BorshDeserialize,
)]
pub struct ChannelId(pub UniqueId);

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcMessage {
    pub channel_id: ChannelId,
    pub kind: MpcMessageKind,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum MpcMessageKind {
    Start(MpcStartMessage),
    Computation(Vec<Vec<u8>>),
    Abort(String),
    Success,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcStartMessage {
    pub task_id: MpcTaskId,
    pub participants: Vec<ParticipantId>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcPeerMessage {
    pub from: ParticipantId,
    pub message: MpcMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum MpcTaskId {
    EcdsaKeyGeneration {
        key_event: u64,
    },
    EcdsaManyTriples {
        start: UniqueId,
        count: u32,
    },
    EcdsaPresignature {
        id: UniqueId,
        domain_id: u64,
        paired_triple_id: UniqueId,
    },
    /// For ECDSA signing, `msg_hash` carries the 32-byte hash that all participants sign.
    EcdsaSignature {
        msg_hash: [u8; 32],
        presignature_id: UniqueId,
    },
    EddsaKeyGeneration {
        key_event: u64,
    },
    /// For EdDSA signing, `payload` carries the full message that all participants sign.
    EddsaSignature {
        payload: Vec<u8>,
    },
}

pub enum PeerMessage {
    Mpc(MpcPeerMessage),
}
