use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use serde::{Deserialize, Serialize};
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleGenerationOutput;
use threshold_signatures::ecdsa::ot_based_ecdsa::{
    presign::presign, PresignArguments, PresignOutput,
};
use threshold_signatures::ecdsa::KeygenOutput;
use threshold_signatures::participants::Participant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutputWithParticipants {
    pub presignature: PresignOutput,
    pub participants: Vec<ParticipantId>,
}

pub struct PresignComputation {
    pub threshold: usize,
    pub triple0: TripleGenerationOutput,
    pub triple1: TripleGenerationOutput,
    pub keygen_out: KeygenOutput,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<PresignOutput> for PresignComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<PresignOutput> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let me = channel.my_participant_id();
        let protocol = presign(
            &cs_participants,
            me.into(),
            PresignArguments {
                triple0: self.triple0,
                triple1: self.triple1,
                keygen_out: self.keygen_out,
                threshold: self.threshold.into(),
            },
        )?;
        let presignature = run_protocol("presign cait-sith", channel, protocol).await?;
        Ok(presignature)
    }

    fn leader_waits_for_success(&self) -> bool {
        true
    }
}
