pub mod computation;

use crate::primitives::{
    ChannelId, MpcMessage, MpcMessageKind, MpcPeerMessage, MpcStartMessage, MpcTaskId,
    ParticipantId, PeerMessage, UniqueId,
};
use crate::tracking::{self};
use lru::LruCache;
use rand::prelude::IteratorRandom;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Abstraction of the networking layer, sender side.
#[async_trait::async_trait]
pub trait MeshNetworkTransportSender: Send + Sync + 'static {
    fn my_participant_id(&self) -> ParticipantId;
    fn all_participant_ids(&self) -> Vec<ParticipantId>;
    fn is_connected(&self, participant_id: ParticipantId) -> bool;
    fn send(
        &self,
        recipient_id: ParticipantId,
        message: MpcMessage,
    ) -> anyhow::Result<()>;
    async fn wait_for_ready(
        &self,
        threshold: usize,
        peers_to_consider: &[ParticipantId],
    ) -> anyhow::Result<()>;
}

/// Receiving side of the networking layer.
#[async_trait::async_trait]
pub trait MeshNetworkTransportReceiver: Send + 'static {
    async fn receive(&mut self) -> anyhow::Result<PeerMessage>;
}

/// Manages MPC task channels multiplexed onto the transport layer.
pub struct MeshNetworkClient {
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
    channels: Arc<Mutex<NetworkTaskChannelManager>>,
    last_id: Arc<Mutex<UniqueId>>,
}

struct NetworkTaskChannelManager {
    senders: HashMap<ChannelId, mpsc::UnboundedSender<MpcPeerMessage>>,
    channels_waiting_for_start: LruCache<ChannelId, IncompleteNetworkTaskChannel>,
}

impl NetworkTaskChannelManager {
    fn new() -> Self {
        Self {
            senders: HashMap::new(),
            channels_waiting_for_start: LruCache::new(LRU_CAPACITY.try_into().unwrap()),
        }
    }
}

const LRU_CAPACITY: usize = 10000;

impl MeshNetworkClient {
    fn new(
        transport_sender: Arc<dyn MeshNetworkTransportSender>,
        channels: Arc<Mutex<NetworkTaskChannelManager>>,
    ) -> Self {
        let last_id = Arc::new(Mutex::new(UniqueId::generate(
            transport_sender.my_participant_id(),
        )));
        Self {
            transport_sender,
            channels,
            last_id,
        }
    }

    fn generate_unique_channel_id(&self) -> ChannelId {
        let mut last_id = self.last_id.lock().unwrap();
        let new = last_id.pick_new_after();
        *last_id = new;
        ChannelId(new)
    }

    pub fn new_channel_for_task(
        &self,
        task_id: impl Into<MpcTaskId>,
        participants: Vec<ParticipantId>,
    ) -> anyhow::Result<NetworkTaskChannel> {
        let task_id: MpcTaskId = task_id.into();
        tracing::debug!(
            target: "network",
            "[{}] Creating new channel for task {:?}",
            self.my_participant_id(),
            task_id
        );
        let channel_id = self.generate_unique_channel_id();
        let start_message = MpcStartMessage {
            task_id,
            participants: participants.clone(),
        };
        let SenderOrNewChannel::NewChannel(channel) =
            self.sender_for(channel_id, Some(&start_message), self.my_participant_id())
        else {
            anyhow::bail!("Channel already exists");
        };
        for participant in &participants {
            if participant == &self.my_participant_id() {
                continue;
            }
            channel.sender.send_raw(
                *participant,
                MpcMessage {
                    channel_id,
                    kind: MpcMessageKind::Start(start_message.clone()),
                },
            )?;
        }
        Ok(channel)
    }

    pub fn my_participant_id(&self) -> ParticipantId {
        self.transport_sender.my_participant_id()
    }

    pub fn all_participant_ids(&self) -> Vec<ParticipantId> {
        self.transport_sender.all_participant_ids()
    }

    pub fn all_alive_participant_ids(&self) -> Vec<ParticipantId> {
        let mut result = Vec::new();
        for participant in self.all_participant_ids() {
            if participant == self.my_participant_id() {
                continue;
            }
            if self.transport_sender.is_connected(participant) {
                result.push(participant);
            }
        }
        result.push(self.my_participant_id());
        result.sort();
        result
    }

    pub fn select_random_active_participants_including_me(
        &self,
        total: usize,
        peers_to_consider: &[ParticipantId],
    ) -> anyhow::Result<Vec<ParticipantId>> {
        let me = self.my_participant_id();
        let participants = self.all_alive_participant_ids();
        anyhow::ensure!(
            participants.contains(&me),
            "There's no `me` in active participants"
        );
        let mut res = participants
            .into_iter()
            .filter(|p| {
                let peer_is_not_me = p != &me;
                let peer_is_considered = peers_to_consider.contains(p);
                peer_is_not_me && peer_is_considered
            })
            .choose_multiple(&mut rand::thread_rng(), total - 1);
        // Put ourselves first so we are the leader (first participant = leader)
        res.insert(0, me);
        anyhow::ensure!(
            res.len() == total,
            "Not enough active participants: need {}, got {}",
            total,
            res.len()
        );
        Ok(res)
    }

    pub async fn leader_wait_for_all_connected(&self) -> anyhow::Result<()> {
        self.transport_sender
            .wait_for_ready(
                self.all_participant_ids().len(),
                &self.all_participant_ids(),
            )
            .await
    }

    fn sender_for(
        &self,
        channel_id: ChannelId,
        start_message: Option<&MpcStartMessage>,
        _from: ParticipantId,
    ) -> SenderOrNewChannel {
        let mut channels = self.channels.lock().unwrap();
        if let Some(sender) = channels.senders.get(&channel_id) {
            return SenderOrNewChannel::ExistingSender(sender.clone());
        }
        match channels.channels_waiting_for_start.get_mut(&channel_id) {
            Some(incomplete) => {
                if let Some(start_message) = start_message {
                    let (sender, receiver) = mpsc::unbounded_channel();
                    // Drain buffered messages into the sender
                    for msg in incomplete.buffered_messages.drain(..) {
                        let _ = sender.send(msg);
                    }
                    channels.senders.insert(channel_id, sender.clone());
                    channels.channels_waiting_for_start.pop(&channel_id);
                    let channel = NetworkTaskChannel::new(
                        channel_id,
                        start_message.clone(),
                        self.my_participant_id(),
                        self.transport_sender.clone(),
                        receiver,
                    );
                    SenderOrNewChannel::NewChannel(channel)
                } else {
                    SenderOrNewChannel::ExistingSender(
                        channels.senders.get(&channel_id).unwrap().clone(),
                    )
                }
            }
            None => {
                if let Some(start_message) = start_message {
                    let (sender, receiver) = mpsc::unbounded_channel();
                    channels.senders.insert(channel_id, sender.clone());
                    let channel = NetworkTaskChannel::new(
                        channel_id,
                        start_message.clone(),
                        self.my_participant_id(),
                        self.transport_sender.clone(),
                        receiver,
                    );
                    SenderOrNewChannel::NewChannel(channel)
                } else {
                    // Buffer messages until Start arrives
                    channels.channels_waiting_for_start.put(
                        channel_id,
                        IncompleteNetworkTaskChannel {
                            buffered_messages: Vec::new(),
                        },
                    );
                    SenderOrNewChannel::Buffered
                }
            }
        }
    }

    fn remove_channel(&self, channel_id: ChannelId) {
        let mut channels = self.channels.lock().unwrap();
        channels.senders.remove(&channel_id);
        channels.channels_waiting_for_start.pop(&channel_id);
    }
}

enum SenderOrNewChannel {
    ExistingSender(mpsc::UnboundedSender<MpcPeerMessage>),
    NewChannel(NetworkTaskChannel),
    Buffered,
}

struct IncompleteNetworkTaskChannel {
    buffered_messages: Vec<MpcPeerMessage>,
}

pub struct ReceivedMessage {
    pub from: ParticipantId,
    pub data: Vec<Vec<u8>>,
}

/// A per-task communication channel within the mesh network.
pub struct NetworkTaskChannel {
    pub channel_id: ChannelId,
    pub task_id: MpcTaskId,
    participants: Vec<ParticipantId>,
    my_participant_id: ParticipantId,
    pub sender: NetworkTaskChannelSender,
    receiver: mpsc::UnboundedReceiver<MpcPeerMessage>,
}

impl NetworkTaskChannel {
    fn new(
        channel_id: ChannelId,
        start_message: MpcStartMessage,
        my_participant_id: ParticipantId,
        transport_sender: Arc<dyn MeshNetworkTransportSender>,
        receiver: mpsc::UnboundedReceiver<MpcPeerMessage>,
    ) -> Self {
        let leader = start_message.participants.first().copied().unwrap_or(my_participant_id);
        Self {
            channel_id,
            task_id: start_message.task_id,
            participants: start_message.participants.clone(),
            my_participant_id,
            sender: NetworkTaskChannelSender {
                channel_id,
                transport_sender,
                participants: start_message.participants,
                leader,
                my_participant_id,
            },
            receiver,
        }
    }

    pub fn task_id(&self) -> &MpcTaskId {
        &self.task_id
    }

    pub fn participants(&self) -> &[ParticipantId] {
        &self.participants
    }

    pub fn my_participant_id(&self) -> ParticipantId {
        self.my_participant_id
    }

    pub fn sender(&self) -> NetworkTaskChannelSender {
        self.sender.clone()
    }

    pub async fn receive(&mut self) -> anyhow::Result<ReceivedMessage> {
        loop {
            let msg = self
                .receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("Channel closed"))?;
            match &msg.message.kind {
                MpcMessageKind::Computation(data) => {
                    return Ok(ReceivedMessage {
                        from: msg.from,
                        data: data.clone(),
                    });
                }
                MpcMessageKind::Abort(reason) => {
                    anyhow::bail!("Received abort from {}: {}", msg.from, reason);
                }
                MpcMessageKind::Success => {
                    // Handled separately in wait_for_followers_to_succeed
                    continue;
                }
                MpcMessageKind::Start(_) => {
                    // Start messages are handled during channel creation
                    continue;
                }
            }
        }
    }

    pub async fn wait_for_followers_to_succeed(&mut self) -> anyhow::Result<()> {
        let followers: HashSet<_> = self
            .participants
            .iter()
            .filter(|p| **p != self.my_participant_id)
            .copied()
            .collect();
        let mut successes = HashSet::new();
        while successes.len() < followers.len() {
            let msg = self
                .receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("Channel closed while waiting for success"))?;
            match &msg.message.kind {
                MpcMessageKind::Success => {
                    successes.insert(msg.from);
                }
                MpcMessageKind::Abort(reason) => {
                    anyhow::bail!(
                        "Follower {} aborted while waiting for success: {}",
                        msg.from,
                        reason
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct NetworkTaskChannelSender {
    channel_id: ChannelId,
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
    participants: Vec<ParticipantId>,
    leader: ParticipantId,
    my_participant_id: ParticipantId,
}

impl NetworkTaskChannelSender {
    pub fn is_leader(&self) -> bool {
        self.my_participant_id == self.leader
    }

    pub fn get_leader(&self) -> ParticipantId {
        self.leader
    }

    pub fn send(
        &self,
        recipient: ParticipantId,
        messages: Vec<Vec<u8>>,
    ) -> anyhow::Result<()> {
        self.send_raw(
            recipient,
            MpcMessage {
                channel_id: self.channel_id,
                kind: MpcMessageKind::Computation(messages),
            },
        )
    }

    pub fn send_raw(
        &self,
        recipient: ParticipantId,
        message: MpcMessage,
    ) -> anyhow::Result<()> {
        self.transport_sender.send(recipient, message)
    }

    pub fn communicate_failure(&self, err: &anyhow::Error) {
        let message = MpcMessage {
            channel_id: self.channel_id,
            kind: MpcMessageKind::Abort(err.to_string()),
        };
        for p in &self.participants {
            if *p == self.my_participant_id {
                continue;
            }
            let _ = self.transport_sender.send(*p, message.clone());
        }
    }

    pub fn communicate_success(&self) -> anyhow::Result<()> {
        let message = MpcMessage {
            channel_id: self.channel_id,
            kind: MpcMessageKind::Success,
        };
        self.transport_sender.send(self.leader, message)
    }

    pub async fn initialize_all_participants_connections(&self) -> anyhow::Result<()> {
        // In the standalone version, we wait for the mesh to be ready
        self.transport_sender
            .wait_for_ready(self.participants.len(), &self.participants)
            .await
    }
}

/// Runs the network client: receives messages from the transport and dispatches them.
pub async fn run_network_client(
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
    mut transport_receiver: impl MeshNetworkTransportReceiver,
    incoming_channel_sender: mpsc::UnboundedSender<NetworkTaskChannel>,
) -> anyhow::Result<(Arc<MeshNetworkClient>, tracking::AutoAbortTask<()>)> {
    let channels = Arc::new(Mutex::new(NetworkTaskChannelManager::new()));
    let client = Arc::new(MeshNetworkClient::new(
        transport_sender.clone(),
        channels.clone(),
    ));

    let client_clone = client.clone();
    let _receiver_task = tracking::spawn("network receiver loop", async move {
        loop {
            match transport_receiver.receive().await {
                Ok(PeerMessage::Mpc(peer_msg)) => {
                    let channel_id = peer_msg.message.channel_id;
                    let _from = peer_msg.from;

                    // Try to find the channel sender
                    let mut channels_guard = channels.lock().unwrap();
                    if let Some(sender) = channels_guard.senders.get(&channel_id) {
                        let _ = sender.send(peer_msg);
                    } else if let MpcMessageKind::Start(ref start_message) = peer_msg.message.kind
                    {
                        // Create a new channel from the start message
                        let (sender, receiver) = mpsc::unbounded_channel();
                        channels_guard.senders.insert(channel_id, sender);
                        drop(channels_guard);

                        let channel = NetworkTaskChannel::new(
                            channel_id,
                            start_message.clone(),
                            transport_sender.my_participant_id(),
                            transport_sender.clone(),
                            receiver,
                        );
                        let _ = incoming_channel_sender.send(channel);
                    } else {
                        // Buffer the message waiting for Start
                        match channels_guard
                            .channels_waiting_for_start
                            .get_or_insert_mut(channel_id, || IncompleteNetworkTaskChannel {
                                buffered_messages: Vec::new(),
                            })
                        {
                            incomplete => {
                                incomplete.buffered_messages.push(peer_msg);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Error receiving message: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok((client_clone, _receiver_task))
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::mpsc;

    /// In-memory mesh transport for testing
    struct InMemoryTransport {
        my_id: ParticipantId,
        all_ids: Vec<ParticipantId>,
        senders: HashMap<ParticipantId, mpsc::UnboundedSender<MpcPeerMessage>>,
    }

    struct InMemoryReceiver {
        receiver: mpsc::UnboundedReceiver<MpcPeerMessage>,
    }

    #[async_trait::async_trait]
    impl MeshNetworkTransportSender for InMemoryTransport {
        fn my_participant_id(&self) -> ParticipantId {
            self.my_id
        }

        fn all_participant_ids(&self) -> Vec<ParticipantId> {
            self.all_ids.clone()
        }

        fn is_connected(&self, participant_id: ParticipantId) -> bool {
            self.senders.contains_key(&participant_id)
        }

        fn send(
            &self,
            recipient_id: ParticipantId,
            message: MpcMessage,
        ) -> anyhow::Result<()> {
            let sender = self
                .senders
                .get(&recipient_id)
                .ok_or_else(|| anyhow::anyhow!("No sender for {}", recipient_id))?;
            sender.send(MpcPeerMessage {
                from: self.my_id,
                message,
            })?;
            Ok(())
        }

        async fn wait_for_ready(
            &self,
            _threshold: usize,
            _peers_to_consider: &[ParticipantId],
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl MeshNetworkTransportReceiver for InMemoryReceiver {
        async fn receive(&mut self) -> anyhow::Result<PeerMessage> {
            let msg = self
                .receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("Channel closed"))?;
            Ok(PeerMessage::Mpc(msg))
        }
    }

    /// Creates in-memory connected mesh transport for n participants.
    pub fn create_in_memory_mesh(
        participant_ids: &[ParticipantId],
    ) -> Vec<(Arc<dyn MeshNetworkTransportSender>, InMemoryReceiver)> {
        let mut incoming_senders: HashMap<ParticipantId, mpsc::UnboundedSender<MpcPeerMessage>> =
            HashMap::new();
        let mut incoming_receivers: HashMap<
            ParticipantId,
            mpsc::UnboundedReceiver<MpcPeerMessage>,
        > = HashMap::new();

        for &id in participant_ids {
            let (tx, rx) = mpsc::unbounded_channel();
            incoming_senders.insert(id, tx);
            incoming_receivers.insert(id, rx);
        }

        participant_ids
            .iter()
            .map(|&my_id| {
                let senders: HashMap<ParticipantId, mpsc::UnboundedSender<MpcPeerMessage>> =
                    incoming_senders
                        .iter()
                        .filter(|(&id, _)| id != my_id)
                        .map(|(&id, sender)| (id, sender.clone()))
                        .collect();

                let transport = Arc::new(InMemoryTransport {
                    my_id,
                    all_ids: participant_ids.to_vec(),
                    senders,
                }) as Arc<dyn MeshNetworkTransportSender>;

                let receiver = InMemoryReceiver {
                    receiver: incoming_receivers.remove(&my_id).unwrap(),
                };

                (transport, receiver)
            })
            .collect()
    }

    /// Run test clients with in-memory networking.
    pub async fn run_test_clients<F, Fut, R>(
        participant_ids: Vec<ParticipantId>,
        client_fn: F,
    ) -> anyhow::Result<Vec<R>>
    where
        F: Fn(Arc<MeshNetworkClient>, mpsc::UnboundedReceiver<NetworkTaskChannel>) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: std::future::Future<Output = anyhow::Result<R>> + Send + 'static,
        R: Send + 'static,
    {
        let mesh = create_in_memory_mesh(&participant_ids);
        let client_fn = Arc::new(client_fn);

        let mut handles = Vec::new();
        for (transport_sender, transport_receiver) in mesh {
            let client_fn = client_fn.clone();
            let handle = tokio::spawn(async move {
                let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
                let (client, _background) =
                    run_network_client(transport_sender, transport_receiver, incoming_tx).await?;
                client_fn(client, incoming_rx).await
            });
            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await??);
        }
        Ok(results)
    }
}
