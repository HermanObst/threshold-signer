use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::protocol::run_protocol;
use anyhow::Context;
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use threshold_signatures::ecdsa::ot_based_ecdsa::{PresignOutput, RerandomizedPresignOutput};
use threshold_signatures::ecdsa::KeygenOutput;
use threshold_signatures::ecdsa::{RerandomizationArguments, SignatureOption};
use threshold_signatures::frost_secp256k1::VerifyingKey;
use threshold_signatures::participants::Participant;
use threshold_signatures::ParticipantList;

/// Performs an ECDSA signature operation.
/// No tweak (key derivation) in standalone mode - signs with the base key.
pub struct SignComputation {
    pub keygen_out: KeygenOutput,
    pub threshold: usize,
    pub presign_out: PresignOutput,
    pub msg_hash: [u8; 32],
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<(SignatureOption, VerifyingKey)> for SignComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<(SignatureOption, VerifyingKey)> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();

        let msg_hash = Scalar::from_repr(self.msg_hash.into())
            .into_option()
            .context("Couldn't construct k256 scalar from msg_hash")?;

        let public_key = self.keygen_out.public_key.to_element().to_affine();
        let participants = ParticipantList::new(&cs_participants).unwrap();

        // Use zero tweak (no key derivation) and zero entropy
        let zero_tweak = threshold_signatures::Tweak::new(Scalar::ZERO);
        let zero_entropy = [0u8; 32];

        let rerand_args = RerandomizationArguments::new(
            public_key,
            zero_tweak,
            self.msg_hash,
            self.presign_out.big_r,
            participants,
            zero_entropy,
        );
        let rerandomized_presignature =
            RerandomizedPresignOutput::rerandomize_presign(&self.presign_out, &rerand_args)?;

        let protocol = threshold_signatures::ecdsa::ot_based_ecdsa::sign::sign(
            &cs_participants,
            channel.sender().get_leader().into(),
            self.threshold,
            channel.my_participant_id().into(),
            public_key,
            rerandomized_presignature,
            msg_hash,
        )?;
        let signature = run_protocol("sign ecdsa", channel, protocol).await?;
        Ok((signature, VerifyingKey::new(public_key.into())))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
