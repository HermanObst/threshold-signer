use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use rand::rngs::OsRng;
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleGenerationOutput;
use threshold_signatures::participants::Participant;

pub type PairedTriple = (TripleGenerationOutput, TripleGenerationOutput);

pub const SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE: usize = 64;

/// Generates many cait-sith triples at once.
pub struct ManyTripleGenerationComputation<const N: usize> {
    pub threshold: usize,
}

#[async_trait::async_trait]
impl<const N: usize> MpcLeaderCentricComputation<Vec<PairedTriple>>
    for ManyTripleGenerationComputation<N>
{
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<Vec<PairedTriple>> {
        assert_eq!(
            N % 2,
            0,
            "Expected to generate even number of triples in a batch"
        );
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let me = channel.my_participant_id();
        let protocol = threshold_signatures::ecdsa::ot_based_ecdsa::triples::generate_triple_many::<
            N,
        >(&cs_participants, me.into(), self.threshold, OsRng)?;
        let triples = run_protocol("many triple gen", channel, protocol).await?;
        assert_eq!(N, triples.len());
        let iter = triples.into_iter();
        let pairs = iter.clone().step_by(2).zip(iter.skip(1).step_by(2));
        Ok(pairs.collect())
    }

    fn leader_waits_for_success(&self) -> bool {
        true
    }
}

pub fn participants_from_triples(
    triple0: &TripleGenerationOutput,
    triple1: &TripleGenerationOutput,
) -> Vec<ParticipantId> {
    triple0
        .1
        .participants
        .iter()
        .copied()
        .filter(|p| triple1.1.participants.contains(p))
        .map(|p| p.into())
        .collect()
}
