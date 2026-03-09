use crate::primitives::{BatchedMessages, ParticipantId};
use crate::tracking;
use crate::{network::NetworkTaskChannel, tracking::TaskHandle};
use futures::TryFutureExt;
use std::collections::{BTreeMap, HashMap};
use std::sync::{atomic::AtomicUsize, Arc};
use threshold_signatures::protocol::{Action, Protocol};
use tokio::sync::mpsc;

/// Runs any cait-sith protocol, returning the result.
pub async fn run_protocol<T>(
    name: &'static str,
    channel: &mut NetworkTaskChannel,
    mut protocol: impl Protocol<Output = T>,
) -> anyhow::Result<T> {
    let counters = Arc::new(MessageCounters::new(
        name.to_string(),
        channel.participants(),
    ));
    let mut queue_senders: HashMap<ParticipantId, mpsc::UnboundedSender<BatchedMessages>> =
        HashMap::new();
    let mut queue_receivers: HashMap<ParticipantId, mpsc::UnboundedReceiver<BatchedMessages>> =
        HashMap::new();

    for p in channel.participants() {
        let (send, recv) = mpsc::unbounded_channel();
        queue_senders.insert(*p, send);
        queue_receivers.insert(*p, recv);
    }

    let sending_handle = {
        let counters = counters.clone();
        let sender = channel.sender();
        tracking::spawn_checked("message senders for all participants", async move {
            let futures = queue_receivers
                .into_iter()
                .map(move |(participant_id, mut receiver)| {
                    let sender = sender.clone();
                    let counters = counters.clone();
                    async move {
                        while let Some(messages) = receiver.recv().await {
                            let num_messages = messages.len();
                            sender.send(participant_id, messages)?;
                            counters.sent(participant_id, num_messages);
                        }
                        anyhow::Ok(())
                    }
                });
            futures::future::try_join_all(futures).await?;
            anyhow::Ok(())
        })
        .map_err(anyhow::Error::from)
    };

    let participants = channel.participants().to_vec();
    let my_participant_id = channel.my_participant_id();
    let computation_handle = async move {
        loop {
            let mut messages_to_send: HashMap<ParticipantId, _> = HashMap::new();
            let done = loop {
                match protocol.poke()? {
                    Action::Wait => break None,
                    Action::SendMany(vec) => {
                        for participant in &participants {
                            if participant == &my_participant_id {
                                continue;
                            }
                            messages_to_send
                                .entry(*participant)
                                .or_insert(Vec::new())
                                .push(vec.clone());
                        }
                    }
                    Action::SendPrivate(participant, vec) => {
                        messages_to_send
                            .entry(From::from(participant))
                            .or_insert(Vec::new())
                            .push(vec.clone());
                    }
                    Action::Return(result) => {
                        break Some(result);
                    }
                }
            };

            for (p, messages) in messages_to_send {
                if messages.is_empty() {
                    continue;
                }
                counters.queue_send(p, messages.len());
                queue_senders.get(&p).unwrap().send(messages)?;
            }

            if let Some(result) = done {
                return anyhow::Ok(result);
            }

            counters.set_receiving();

            let msg = channel.receive().await?;
            counters.received(msg.from, msg.data.len());

            for one_msg in msg.data {
                protocol.message(msg.from.into(), one_msg);
            }
        }
    };
    let (computation_result, _) = futures::try_join!(computation_handle, sending_handle)?;
    Ok(computation_result)
}

struct MessageCounters {
    name: String,
    task: Arc<TaskHandle>,
    counters: BTreeMap<ParticipantId, PerParticipantCounters>,
    current_action: AtomicUsize,
}

struct PerParticipantCounters {
    sent: AtomicUsize,
    in_flight: AtomicUsize,
    received: AtomicUsize,
}

impl MessageCounters {
    pub fn new(name: String, participants: &[ParticipantId]) -> Self {
        Self {
            name,
            task: tracking::current_task(),
            counters: participants
                .iter()
                .map(|p| {
                    (
                        *p,
                        PerParticipantCounters {
                            sent: AtomicUsize::new(0),
                            in_flight: AtomicUsize::new(0),
                            received: AtomicUsize::new(0),
                        },
                    )
                })
                .collect(),
            current_action: AtomicUsize::new(0),
        }
    }

    pub fn queue_send(&self, participant: ParticipantId, num_messages: usize) {
        if let Some(c) = self.counters.get(&participant) {
            c.in_flight
                .fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
        }
        self.report_progress();
    }

    pub fn sent(&self, participant: ParticipantId, num_messages: usize) {
        if let Some(c) = self.counters.get(&participant) {
            c.sent
                .fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
            c.in_flight
                .fetch_sub(num_messages, std::sync::atomic::Ordering::Relaxed);
        }
        self.report_progress();
    }

    pub fn received(&self, participant: ParticipantId, num_messages: usize) {
        if let Some(c) = self.counters.get(&participant) {
            c.received
                .fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
        }
        self.current_action
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_receiving(&self) {
        self.current_action
            .store(1, std::sync::atomic::Ordering::Relaxed);
        self.report_progress();
    }

    fn report_progress(&self) {
        self.task.set_progress(&format!(
            "{}: sent {:?}, received [{:?}]",
            self.name,
            self.counters
                .values()
                .map(|c| c.sent.load(std::sync::atomic::Ordering::Relaxed))
                .collect::<Vec<_>>(),
            self.counters
                .values()
                .map(|c| c.received.load(std::sync::atomic::Ordering::Relaxed))
                .collect::<Vec<_>>(),
        ));
    }
}
