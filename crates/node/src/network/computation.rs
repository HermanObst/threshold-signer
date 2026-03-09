use super::NetworkTaskChannel;
use crate::tracking;
use std::future::Future;

/// Interface for a computation that is leader-centric:
///  - If any follower's computation returns error, it sends an Abort message to the leader.
///  - If the leader's computation returns error, it sends an Abort to all followers.
///
/// If leader_waits_for_success returns true, followers send Success after completing,
/// and the leader waits for all before returning.
#[async_trait::async_trait]
pub trait MpcLeaderCentricComputation<T>: Sized + 'static {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<T>;
    fn leader_waits_for_success(&self) -> bool;

    fn perform_leader_centric_computation(
        self,
        mut channel: NetworkTaskChannel,
        timeout: std::time::Duration,
    ) -> impl Future<Output = anyhow::Result<T>> + 'static {
        let leader_waits_for_success = self.leader_waits_for_success();
        let sender = channel.sender();
        let sender_clone = sender.clone();

        let fut = async move {
            if !sender.is_leader() {
                sender.initialize_all_participants_connections().await?;
            }
            let result = self.compute(&mut channel).await;
            let result = match result {
                Ok(result) => result,
                Err(err) => {
                    sender.communicate_failure(&err);
                    return Err(err);
                }
            };
            if leader_waits_for_success && sender.is_leader() {
                if let Err(err) = channel.wait_for_followers_to_succeed().await {
                    sender.communicate_failure(&err);
                    return Err(err);
                }
            }
            Ok(result)
        };

        async move {
            let sender = sender_clone;
            let result = tokio::time::timeout(timeout, fut).await;
            let result = match result {
                Ok(result) => result,
                Err(_) => {
                    let err = anyhow::anyhow!("Timeout");
                    sender.communicate_failure(&err);
                    return Err(err);
                }
            };
            if result.is_ok() {
                if !sender.is_leader() && leader_waits_for_success {
                    sender.communicate_success()?;
                }
                tracking::set_progress("Computation complete");
            }
            result
        }
    }
}
