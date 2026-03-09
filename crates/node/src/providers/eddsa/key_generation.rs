use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::protocol::run_protocol;
use rand::rngs::OsRng;
use threshold_signatures::frost::eddsa::KeygenOutput;
use threshold_signatures::frost_ed25519::Ed25519Sha512;
use threshold_signatures::participants::Participant;

pub struct KeyGenerationComputation {
    pub threshold: usize,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<KeygenOutput> for KeyGenerationComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<KeygenOutput> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let me = channel.my_participant_id();
        let protocol = threshold_signatures::keygen::<Ed25519Sha512>(
            &cs_participants,
            me.into(),
            self.threshold,
            OsRng,
        )?;
        run_protocol("eddsa key generation", channel, protocol).await
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
