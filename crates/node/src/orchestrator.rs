use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, ParticipantId, UniqueId};
use crate::providers::ecdsa::key_generation::KeyGenerationComputation as EcdsaKeygenComputation;
use crate::providers::ecdsa::presign::PresignComputation;
use crate::providers::ecdsa::sign::SignComputation as EcdsaSignComputation;
use crate::providers::ecdsa::triple::{
    participants_from_triples, ManyTripleGenerationComputation, PairedTriple,
    SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
};
use crate::providers::eddsa::key_generation::KeyGenerationComputation as EddsaKeygenComputation;
use crate::providers::eddsa::sign::SignComputation as EddsaSignComputation;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use threshold_signatures::ecdsa::ot_based_ecdsa::PresignOutput;
use threshold_signatures::ecdsa::KeygenOutput as EcdsaKeygenOutput;
use threshold_signatures::frost::eddsa::KeygenOutput as EddsaKeygenOutput;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Ecdsa,
    Eddsa,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OrchestratorState {
    WaitingForPeers,
    Ready,
    HasEcdsaKey,
    HasEddsaKey,
    HasBothKeys,
}

/// The standalone orchestrator replaces the NEAR-based Coordinator.
/// It manages DKG, triple/presignature generation, and signing via direct API calls.
pub struct Orchestrator {
    pub client: Arc<MeshNetworkClient>,
    threshold: usize,
    state: Arc<Mutex<OrchestratorInner>>,
}

struct OrchestratorInner {
    ecdsa_keyshare: Option<EcdsaKeygenOutput>,
    eddsa_keyshare: Option<EddsaKeygenOutput>,
    /// ECDSA presignatures ready for use
    presignatures: VecDeque<(PresignOutput, Vec<ParticipantId>)>,
    /// ECDSA triples ready for presignature generation
    triples: VecDeque<PairedTriple>,
    key_event_counter: u64,
}

impl Orchestrator {
    pub fn new(client: Arc<MeshNetworkClient>, threshold: usize) -> Self {
        Self {
            client,
            threshold,
            state: Arc::new(Mutex::new(OrchestratorInner {
                ecdsa_keyshare: None,
                eddsa_keyshare: None,
                presignatures: VecDeque::new(),
                triples: VecDeque::new(),
                key_event_counter: 0,
            })),
        }
    }

    pub fn get_state(&self) -> OrchestratorState {
        let inner = self.state.lock().unwrap();
        match (&inner.ecdsa_keyshare, &inner.eddsa_keyshare) {
            (Some(_), Some(_)) => OrchestratorState::HasBothKeys,
            (Some(_), None) => OrchestratorState::HasEcdsaKey,
            (None, Some(_)) => OrchestratorState::HasEddsaKey,
            (None, None) => {
                let alive = self.client.all_alive_participant_ids();
                if alive.len() >= self.threshold {
                    OrchestratorState::Ready
                } else {
                    OrchestratorState::WaitingForPeers
                }
            }
        }
    }

    pub fn presignature_count(&self) -> usize {
        self.state.lock().unwrap().presignatures.len()
    }

    pub fn triple_count(&self) -> usize {
        self.state.lock().unwrap().triples.len()
    }

    fn next_key_event(&self) -> u64 {
        let mut inner = self.state.lock().unwrap();
        let id = inner.key_event_counter;
        inner.key_event_counter += 1;
        id
    }

    /// Run ECDSA DKG. Only the leader should call this.
    pub async fn run_ecdsa_dkg(&self) -> anyhow::Result<String> {
        let key_event = self.next_key_event();
        let all_participants = self.client.all_participant_ids();
        let channel = self.client.new_channel_for_task(
            MpcTaskId::EcdsaKeyGeneration { key_event },
            all_participants,
        )?;

        let keygen_output = EcdsaKeygenComputation {
            threshold: self.threshold,
        }
        .perform_leader_centric_computation(channel, Duration::from_secs(120))
        .await?;

        let public_key = hex::encode(
            keygen_output
                .public_key
                .serialize()
                .map_err(|e| anyhow::anyhow!("{}", e))?,
        );
        {
            let mut inner = self.state.lock().unwrap();
            inner.ecdsa_keyshare = Some(keygen_output);
        }

        tracing::info!("ECDSA DKG complete. Public key: {}", public_key);
        Ok(public_key)
    }

    /// Run EdDSA DKG. Only the leader should call this.
    pub async fn run_eddsa_dkg(&self) -> anyhow::Result<String> {
        let key_event = self.next_key_event();
        let all_participants = self.client.all_participant_ids();
        let channel = self.client.new_channel_for_task(
            MpcTaskId::EddsaKeyGeneration { key_event },
            all_participants,
        )?;

        let keygen_output = EddsaKeygenComputation {
            threshold: self.threshold,
        }
        .perform_leader_centric_computation(channel, Duration::from_secs(120))
        .await?;

        let public_key = hex::encode(
            keygen_output
                .public_key
                .serialize()
                .map_err(|e| anyhow::anyhow!("{}", e))?,
        );
        {
            let mut inner = self.state.lock().unwrap();
            inner.eddsa_keyshare = Some(keygen_output);
        }

        tracing::info!("EdDSA DKG complete. Public key: {}", public_key);
        Ok(public_key)
    }

    /// Generate a batch of ECDSA triples (background).
    pub async fn generate_triples(&self) -> anyhow::Result<usize> {
        let all_participants = self.client.all_participant_ids();
        let participants = self
            .client
            .select_random_active_participants_including_me(self.threshold, &all_participants)?;

        let id_start = UniqueId::generate(self.client.my_participant_id());
        let task_id = MpcTaskId::EcdsaManyTriples {
            start: id_start,
            count: SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE as u32,
        };
        let channel = self.client.new_channel_for_task(task_id, participants)?;

        let triples = ManyTripleGenerationComputation::<SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE> {
            threshold: self.threshold,
        }
        .perform_leader_centric_computation(channel, Duration::from_secs(120))
        .await?;

        let count = triples.len();
        {
            let mut inner = self.state.lock().unwrap();
            for triple in triples {
                inner.triples.push_back(triple);
            }
        }
        tracing::info!("Generated {} triple pairs", count);
        Ok(count)
    }

    /// Generate a presignature from a triple pair.
    pub async fn generate_presignature(&self) -> anyhow::Result<()> {
        let (triple_pair, keygen_out) = {
            let mut inner = self.state.lock().unwrap();
            let keygen_out = inner
                .ecdsa_keyshare
                .clone()
                .ok_or_else(|| anyhow::anyhow!("No ECDSA keyshare - run DKG first"))?;
            let triple_pair = inner
                .triples
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("No triples available - generate triples first"))?;
            (triple_pair, keygen_out)
        };

        let (triple0, triple1) = triple_pair;
        let participants = participants_from_triples(&triple0, &triple1);

        let presign_id = UniqueId::generate(self.client.my_participant_id());
        let triple_id = UniqueId::generate(self.client.my_participant_id());
        let task_id = MpcTaskId::EcdsaPresignature {
            id: presign_id,
            domain_id: 0,
            paired_triple_id: triple_id,
        };
        let channel = self
            .client
            .new_channel_for_task(task_id, participants.clone())?;

        let presignature = PresignComputation {
            threshold: self.threshold,
            triple0,
            triple1,
            keygen_out,
        }
        .perform_leader_centric_computation(channel, Duration::from_secs(120))
        .await?;

        {
            let mut inner = self.state.lock().unwrap();
            inner.presignatures.push_back((presignature, participants));
        }
        tracing::info!("Generated presignature");
        Ok(())
    }

    /// Sign with ECDSA. The payload must be a 32-byte hash.
    pub async fn sign_ecdsa(&self, msg_hash: [u8; 32]) -> anyhow::Result<EcdsaSignResult> {
        let (presign_out, participants, keygen_out) = {
            let mut inner = self.state.lock().unwrap();
            let keygen_out = inner
                .ecdsa_keyshare
                .clone()
                .ok_or_else(|| anyhow::anyhow!("No ECDSA keyshare"))?;
            let (presign_out, participants) = inner
                .presignatures
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("No presignatures available"))?;
            (presign_out, participants, keygen_out)
        };

        let presig_id = UniqueId::generate(self.client.my_participant_id());
        let task_id = MpcTaskId::EcdsaSignature {
            msg_hash,
            presignature_id: presig_id,
        };
        let channel = self.client.new_channel_for_task(task_id, participants)?;

        let (signature_opt, public_key) = EcdsaSignComputation {
            keygen_out,
            threshold: self.threshold,
            presign_out,
            msg_hash,
        }
        .perform_leader_centric_computation(channel, Duration::from_secs(60))
        .await?;

        let signature =
            signature_opt.ok_or_else(|| anyhow::anyhow!("No signature returned (not leader?)"))?;

        Ok(EcdsaSignResult {
            r: hex::encode(serde_json::to_vec(&signature.big_r).unwrap_or_default()),
            s: hex::encode(signature.s.to_bytes()),
            public_key: hex::encode(
                public_key
                    .serialize()
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
        })
    }

    /// Sign with EdDSA. The payload can be arbitrary bytes.
    pub async fn sign_eddsa(&self, message: Vec<u8>) -> anyhow::Result<EddsaSignResult> {
        let keygen_output = {
            let inner = self.state.lock().unwrap();
            inner
                .eddsa_keyshare
                .clone()
                .ok_or_else(|| anyhow::anyhow!("No EdDSA keyshare"))?
        };

        let all_participants = self.client.all_participant_ids();
        let participants = self
            .client
            .select_random_active_participants_including_me(self.threshold, &all_participants)?;

        let task_id = MpcTaskId::EddsaSignature {
            payload: message.clone(),
        };
        let channel = self.client.new_channel_for_task(task_id, participants)?;

        let result = EddsaSignComputation {
            keygen_output: keygen_output.clone(),
            threshold: self.threshold,
            message,
        }
        .perform_leader_centric_computation(channel, Duration::from_secs(60))
        .await?;

        let (signature, verifying_key) =
            result.ok_or_else(|| anyhow::anyhow!("No signature returned (not leader?)"))?;

        Ok(EddsaSignResult {
            signature: hex::encode(
                signature
                    .serialize()
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            public_key: hex::encode(
                verifying_key
                    .serialize()
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
        })
    }

    /// Process incoming channels from followers (for follower nodes).
    pub async fn process_incoming_channel(
        &self,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::EcdsaKeyGeneration { key_event: _ } => {
                let keygen_output = EcdsaKeygenComputation {
                    threshold: self.threshold,
                }
                .perform_leader_centric_computation(channel, Duration::from_secs(120))
                .await?;
                let mut inner = self.state.lock().unwrap();
                inner.ecdsa_keyshare = Some(keygen_output);
                tracing::info!("ECDSA DKG complete (follower)");
            }
            MpcTaskId::EddsaKeyGeneration { key_event: _ } => {
                let keygen_output = EddsaKeygenComputation {
                    threshold: self.threshold,
                }
                .perform_leader_centric_computation(channel, Duration::from_secs(120))
                .await?;
                let mut inner = self.state.lock().unwrap();
                inner.eddsa_keyshare = Some(keygen_output);
                tracing::info!("EdDSA DKG complete (follower)");
            }
            MpcTaskId::EcdsaManyTriples { start: _, count: _ } => {
                let triples =
                    ManyTripleGenerationComputation::<SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE> {
                        threshold: self.threshold,
                    }
                    .perform_leader_centric_computation(channel, Duration::from_secs(120))
                    .await?;
                let mut inner = self.state.lock().unwrap();
                for triple in triples {
                    inner.triples.push_back(triple);
                }
                tracing::info!("Triple generation complete (follower)");
            }
            MpcTaskId::EcdsaPresignature {
                id: _,
                domain_id: _,
                paired_triple_id: _,
            } => {
                let (triple_pair, keygen_out) = {
                    let mut inner = self.state.lock().unwrap();
                    let keygen_out = inner
                        .ecdsa_keyshare
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("No ECDSA keyshare for presign"))?;
                    let triple_pair = inner
                        .triples
                        .pop_front()
                        .ok_or_else(|| anyhow::anyhow!("No triples for presign (follower)"))?;
                    (triple_pair, keygen_out)
                };
                let (triple0, triple1) = triple_pair;
                let presignature = PresignComputation {
                    threshold: self.threshold,
                    triple0,
                    triple1,
                    keygen_out,
                }
                .perform_leader_centric_computation(channel, Duration::from_secs(120))
                .await?;
                let participants = Vec::new(); // follower doesn't need to track
                {
                    let mut inner = self.state.lock().unwrap();
                    inner.presignatures.push_back((presignature, participants));
                }
                tracing::info!("Presignature generation complete (follower)");
            }
            MpcTaskId::EcdsaSignature {
                msg_hash,
                presignature_id: _,
            } => {
                let msg_hash = *msg_hash;
                let (presign_out, keygen_out) = {
                    let mut inner = self.state.lock().unwrap();
                    let keygen_out = inner
                        .ecdsa_keyshare
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("No ECDSA keyshare for sign"))?;
                    let (presign_out, _) = inner
                        .presignatures
                        .pop_front()
                        .ok_or_else(|| anyhow::anyhow!("No presignature for sign (follower)"))?;
                    (presign_out, keygen_out)
                };
                EcdsaSignComputation {
                    keygen_out,
                    threshold: self.threshold,
                    presign_out,
                    msg_hash,
                }
                .perform_leader_centric_computation(channel, Duration::from_secs(60))
                .await?;
                tracing::info!("ECDSA sign complete (follower)");
            }
            MpcTaskId::EddsaSignature { payload } => {
                let payload = payload.clone();
                let keygen_output = {
                    let inner = self.state.lock().unwrap();
                    inner
                        .eddsa_keyshare
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("No EdDSA keyshare for sign"))?
                };
                EddsaSignComputation {
                    keygen_output,
                    threshold: self.threshold,
                    message: payload,
                }
                .perform_leader_centric_computation(channel, Duration::from_secs(60))
                .await?;
                tracing::info!("EdDSA sign complete (follower)");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaSignResult {
    pub r: String,
    pub s: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EddsaSignResult {
    pub signature: String,
    pub public_key: String,
}
