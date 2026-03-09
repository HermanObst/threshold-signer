use crate::primitives::ParticipantId;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub type AesKey128 = [u8; 16];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TripleConfig {
    pub concurrency: usize,
    pub desired_triples_to_buffer: usize,
    pub timeout_sec: u64,
    pub parallel_triple_generation_stagger_time_sec: u64,
}

impl Default for TripleConfig {
    fn default() -> Self {
        Self {
            concurrency: 2,
            desired_triples_to_buffer: 128,
            timeout_sec: 120,
            parallel_triple_generation_stagger_time_sec: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresignatureConfig {
    pub concurrency: usize,
    pub desired_presignatures_to_buffer: usize,
    pub timeout_sec: u64,
}

impl Default for PresignatureConfig {
    fn default() -> Self {
        Self {
            concurrency: 4,
            desired_presignatures_to_buffer: 64,
            timeout_sec: 120,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureConfig {
    pub timeout_sec: u64,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self { timeout_sec: 60 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeygenConfig {
    pub timeout_sec: u64,
}

impl Default for KeygenConfig {
    fn default() -> Self {
        Self { timeout_sec: 60 }
    }
}

/// Configuration about the MPC protocol.
#[derive(Debug, Clone)]
pub struct MpcConfig {
    pub my_participant_id: ParticipantId,
    pub participants: ParticipantsConfig,
}

impl MpcConfig {
    pub fn new(my_participant_id: ParticipantId, participants: ParticipantsConfig) -> Self {
        Self {
            my_participant_id,
            participants,
        }
    }

    pub fn is_leader(&self) -> bool {
        let my_participant_id = self.my_participant_id;
        let participant_with_lowest_id = self
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .min()
            .expect("Participants list should not be empty");
        my_participant_id == participant_with_lowest_id
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantsConfig {
    pub threshold: u64,
    pub participants: Vec<ParticipantInfo>,
}

impl ParticipantsConfig {
    pub fn get_info(&self, id: ParticipantId) -> Option<&ParticipantInfo> {
        self.participants
            .iter()
            .find(|participant_info| participant_info.id == id)
    }

    pub fn get_participant_id_by_name(&self, name: &str) -> Option<ParticipantId> {
        self.participants
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.id)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantInfo {
    pub id: ParticipantId,
    pub name: String,
    pub address: String,
    pub port: u16,
    #[serde(
        serialize_with = "serialize_verifying_key",
        deserialize_with = "deserialize_verifying_key"
    )]
    pub p2p_public_key: ed25519_dalek::VerifyingKey,
}

fn serialize_verifying_key<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(key.as_bytes()))
}

fn deserialize_verifying_key<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str: String = serde::Deserialize::deserialize(deserializer)?;
    let bytes: [u8; 32] = hex::decode(&hex_str)
        .map_err(serde::de::Error::custom)?
        .try_into()
        .map_err(|_| serde::de::Error::custom("Public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
}

/// The standalone config file loaded from YAML.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StandaloneConfigFile {
    pub node_name: String,
    pub p2p_port: u16,
    pub api_port: u16,
    pub data_dir: String,
    #[serde(default)]
    pub triple: TripleConfig,
    #[serde(default)]
    pub presignature: PresignatureConfig,
    #[serde(default)]
    pub signature: SignatureConfig,
    #[serde(default)]
    pub keygen: KeygenConfig,
    pub participants: ParticipantsConfig,
}

impl StandaloneConfigFile {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let config_string = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&config_string)?;
        Ok(config)
    }

    /// Build MpcConfig by finding our participant ID from the participant list.
    pub fn to_mpc_config(&self, my_p2p_public_key: &VerifyingKey) -> anyhow::Result<MpcConfig> {
        let my_id = self
            .participants
            .participants
            .iter()
            .find(|p| p.name == self.node_name && &p.p2p_public_key == my_p2p_public_key)
            .map(|p| p.id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Could not find participant with name '{}' and matching p2p key",
                    self.node_name
                )
            })?;
        Ok(MpcConfig::new(my_id, self.participants.clone()))
    }
}
