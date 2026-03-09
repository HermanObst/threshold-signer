use crate::config::ParticipantsConfig;
use crate::network::{MeshNetworkTransportReceiver, MeshNetworkTransportSender};
use crate::primitives::{MpcMessage, MpcPeerMessage, ParticipantId, PeerMessage};
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::SigningKey;
use mpc_tls::tls::{configure_tls, extract_public_key};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const PING_INTERVAL: Duration = Duration::from_secs(5);
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const MAX_MESSAGE_SIZE: u32 = 100 * 1024 * 1024; // 100MB

#[derive(BorshSerialize, BorshDeserialize)]
enum Packet {
    Ping,
    Mpc(MpcMessage),
}

pub struct TlsMeshSender {
    my_id: ParticipantId,
    all_ids: Vec<ParticipantId>,
    outgoing: HashMap<ParticipantId, mpsc::UnboundedSender<MpcMessage>>,
    connected: Arc<Mutex<HashMap<ParticipantId, bool>>>,
}

pub struct TlsMeshReceiver {
    receiver: mpsc::UnboundedReceiver<MpcPeerMessage>,
}

#[async_trait::async_trait]
impl MeshNetworkTransportSender for TlsMeshSender {
    fn my_participant_id(&self) -> ParticipantId {
        self.my_id
    }

    fn all_participant_ids(&self) -> Vec<ParticipantId> {
        self.all_ids.clone()
    }

    fn is_connected(&self, participant_id: ParticipantId) -> bool {
        let connected = self.connected.lock().unwrap();
        connected.get(&participant_id).copied().unwrap_or(false)
    }

    fn send(
        &self,
        recipient_id: ParticipantId,
        message: MpcMessage,
    ) -> anyhow::Result<()> {
        let sender = self
            .outgoing
            .get(&recipient_id)
            .ok_or_else(|| anyhow::anyhow!("No connection to participant {}", recipient_id))?;
        sender
            .send(message)
            .map_err(|_| anyhow::anyhow!("Send channel closed for {}", recipient_id))?;
        Ok(())
    }

    async fn wait_for_ready(
        &self,
        threshold: usize,
        peers_to_consider: &[ParticipantId],
    ) -> anyhow::Result<()> {
        loop {
            let connected_count = {
                let connected = self.connected.lock().unwrap();
                peers_to_consider
                    .iter()
                    .filter(|p| {
                        **p == self.my_id || connected.get(p).copied().unwrap_or(false)
                    })
                    .count()
            };
            if connected_count >= threshold {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

#[async_trait::async_trait]
impl MeshNetworkTransportReceiver for TlsMeshReceiver {
    async fn receive(&mut self) -> anyhow::Result<PeerMessage> {
        let msg = self
            .receiver
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Receiver channel closed"))?;
        Ok(PeerMessage::Mpc(msg))
    }
}

async fn write_message(
    stream: &mut (impl AsyncWriteExt + Unpin),
    data: &[u8],
) -> anyhow::Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_message(stream: &mut (impl AsyncReadExt + Unpin)) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_SIZE {
        anyhow::bail!("Message too large: {} bytes", len);
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Creates a TLS mesh network for the MPC nodes.
pub async fn new_tls_mesh_network(
    my_signing_key: &SigningKey,
    participants: &ParticipantsConfig,
    my_id: ParticipantId,
    listen_port: u16,
) -> anyhow::Result<(
    Arc<TlsMeshSender>,
    TlsMeshReceiver,
)> {
    let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
    let connected: Arc<Mutex<HashMap<ParticipantId, bool>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut outgoing_senders: HashMap<ParticipantId, mpsc::UnboundedSender<MpcMessage>> =
        HashMap::new();
    let all_ids: Vec<ParticipantId> = participants.participants.iter().map(|p| p.id).collect();

    // Set up outgoing connections to each peer
    for peer in &participants.participants {
        if peer.id == my_id {
            continue;
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<MpcMessage>();
        outgoing_senders.insert(peer.id, tx);

        let peer_address = format!("{}:{}", peer.address, peer.port);
        let peer_id = peer.id;
        let connected_clone = connected.clone();
        let signing_key = my_signing_key.clone();

        // Spawn outgoing connection task
        tokio::spawn(async move {
            loop {
                match connect_to_peer(&signing_key, &peer_address).await {
                    Ok(mut stream) => {
                        tracing::info!("Connected to peer {}", peer_id);
                        {
                            let mut c = connected_clone.lock().unwrap();
                            c.insert(peer_id, true);
                        }

                        // Send loop
                        loop {
                            tokio::select! {
                                msg = rx.recv() => {
                                    match msg {
                                        Some(message) => {
                                            let packet = Packet::Mpc(message);
                                            let data = borsh::to_vec(&packet).unwrap();
                                            if let Err(e) = write_message(&mut stream, &data).await {
                                                tracing::warn!("Failed to send to {}: {}", peer_id, e);
                                                break;
                                            }
                                        }
                                        None => return, // Channel closed
                                    }
                                }
                                _ = tokio::time::sleep(PING_INTERVAL) => {
                                    let ping = borsh::to_vec(&Packet::Ping).unwrap();
                                    if let Err(e) = write_message(&mut stream, &ping).await {
                                        tracing::warn!("Ping to {} failed: {}", peer_id, e);
                                        break;
                                    }
                                }
                            }
                        }

                        {
                            let mut c = connected_clone.lock().unwrap();
                            c.insert(peer_id, false);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Failed to connect to peer {}: {}", peer_id, e);
                    }
                }
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        });
    }

    // Set up TLS listener for incoming connections
    let listener = TcpListener::bind(format!("0.0.0.0:{}", listen_port)).await?;
    let (server_config, _client_config_listener) = configure_tls(my_signing_key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let participants_map: HashMap<ed25519_dalek::VerifyingKey, ParticipantId> = participants
        .participants
        .iter()
        .map(|p| (p.p2p_public_key.clone(), p.id))
        .collect();

    let incoming_tx_clone = incoming_tx.clone();
    let connected_clone = connected.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp_stream, addr)) => {
                    let acceptor = acceptor.clone();
                    let incoming_tx = incoming_tx_clone.clone();
                    let participants_map = participants_map.clone();
                    let connected = connected_clone.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(tcp_stream).await {
                            Ok(tls_stream) => {
                                let (_, server_conn) = tls_stream.get_ref();
                                let peer_pk = match extract_public_key(server_conn) {
                                    Ok(pk) => pk,
                                    Err(e) => {
                                        tracing::warn!("No peer public key from {}: {}", addr, e);
                                        return;
                                    }
                                };

                                let peer_id = match participants_map.get(&peer_pk) {
                                    Some(id) => *id,
                                    None => {
                                        tracing::warn!(
                                            "Unknown peer public key from {}",
                                            addr
                                        );
                                        return;
                                    }
                                };

                                tracing::info!("Accepted connection from peer {}", peer_id);
                                {
                                    let mut c = connected.lock().unwrap();
                                    c.insert(peer_id, true);
                                }

                                let mut stream = tls_stream;
                                loop {
                                    match read_message(&mut stream).await {
                                        Ok(data) => {
                                            match borsh::from_slice::<Packet>(&data) {
                                                Ok(Packet::Mpc(message)) => {
                                                    let _ = incoming_tx.send(MpcPeerMessage {
                                                        from: peer_id,
                                                        message,
                                                    });
                                                }
                                                Ok(Packet::Ping) => {}
                                                Err(e) => {
                                                    tracing::warn!(
                                                        "Failed to deserialize from {}: {}",
                                                        peer_id,
                                                        e
                                                    );
                                                    break;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::debug!(
                                                "Read error from peer {}: {}",
                                                peer_id,
                                                e
                                            );
                                            break;
                                        }
                                    }
                                }

                                {
                                    let mut c = connected.lock().unwrap();
                                    c.insert(peer_id, false);
                                }
                            }
                            Err(e) => {
                                tracing::warn!("TLS accept error from {}: {}", addr, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("TCP accept error: {}", e);
                }
            }
        }
    });

    let sender = Arc::new(TlsMeshSender {
        my_id,
        all_ids,
        outgoing: outgoing_senders,
        connected,
    });

    Ok((sender, TlsMeshReceiver { receiver: incoming_rx }))
}

async fn connect_to_peer(
    signing_key: &SigningKey,
    address: &str,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let (_server_config, client_config) = configure_tls(signing_key)?;
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = mpc_tls::constants::SERVER_NAME
        .try_into()
        .map_err(|e| anyhow::anyhow!("Invalid server name: {:?}", e))?;
    let tcp_stream = TcpStream::connect(address).await?;
    tcp_stream.set_nodelay(true)?;
    let tls_stream = connector.connect(server_name, tcp_stream).await?;
    Ok(tls_stream)
}
