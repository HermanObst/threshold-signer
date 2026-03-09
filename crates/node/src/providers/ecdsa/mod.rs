pub mod key_generation;
pub mod presign;
pub mod sign;
pub mod triple;

use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, ParticipantId};
use std::sync::Arc;
use threshold_signatures::ecdsa::KeygenOutput;

pub struct EcdsaProvider {
    pub client: Arc<MeshNetworkClient>,
    pub threshold: usize,
    pub keyshare: Option<KeygenOutput>,
}

impl EcdsaProvider {
    pub fn new_channel_for_task(
        &self,
        task_id: impl Into<MpcTaskId>,
        participants: Vec<ParticipantId>,
    ) -> anyhow::Result<NetworkTaskChannel> {
        self.client.new_channel_for_task(task_id, participants)
    }
}
