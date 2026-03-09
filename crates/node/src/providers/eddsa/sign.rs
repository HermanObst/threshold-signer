use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::protocol::run_protocol;
use rand::rngs::OsRng;
use threshold_signatures::frost::eddsa::sign::sign;
use threshold_signatures::frost::eddsa::KeygenOutput;
use threshold_signatures::frost_ed25519::{Signature, VerifyingKey};
use threshold_signatures::participants::Participant;

/// Performs an EdDSA FROST signature operation.
pub struct SignComputation {
    pub keygen_output: KeygenOutput,
    pub threshold: usize,
    pub message: Vec<u8>,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<Option<(Signature, VerifyingKey)>> for SignComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<Option<(Signature, VerifyingKey)>> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();

        let me: Participant = channel.my_participant_id().into();
        let coordinator: Participant = channel.sender().get_leader().into();
        tracing::info!(
            "EdDSA sign: me={:?}, coordinator={:?}, is_leader={}, participants={:?}, channel_participants={:?}",
            me, coordinator, channel.sender().is_leader(), cs_participants, channel.participants()
        );

        let protocol = sign(
            cs_participants.as_slice(),
            self.threshold,
            me,
            coordinator,
            self.keygen_output.clone(),
            self.message,
            OsRng,
        )?;

        let signature: Option<Signature> = run_protocol("sign eddsa", channel, protocol).await?;
        Ok(signature.map(|sig| (sig, self.keygen_output.public_key)))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
