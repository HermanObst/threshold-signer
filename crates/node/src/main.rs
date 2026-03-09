mod api;
mod config;
mod db;
mod network;
mod orchestrator;
mod p2p;
mod primitives;
mod protocol;
mod providers;
mod tracking;

use crate::api::{AppState, create_router};
use crate::config::StandaloneConfigFile;
use crate::network::run_network_client;
use crate::orchestrator::Orchestrator;
use crate::p2p::new_tls_mesh_network;
use crate::tracking::start_root_task;
use clap::Parser;
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(name = "threshold-signer-node")]
#[command(about = "Threshold signature node for distributed ECDSA and EdDSA")]
struct Cli {
    /// Path to config YAML file
    #[arg(short, long)]
    config: PathBuf,

    /// Path to secret key file (hex-encoded Ed25519 secret key)
    #[arg(short, long)]
    secret_key: PathBuf,

    /// Hex-encoded AES-128 key for local storage encryption
    #[arg(long, env = "MPC_AES_KEY")]
    aes_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Load config
    let config = StandaloneConfigFile::from_file(&cli.config)?;
    tracing::info!("Loaded config for node: {}", config.node_name);

    // Load secret key
    let secret_key_hex = std::fs::read_to_string(&cli.secret_key)?.trim().to_string();
    let secret_key_bytes: [u8; 32] = hex::decode(&secret_key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Secret key must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let verifying_key = signing_key.verifying_key();

    tracing::info!(
        "P2P public key: {}",
        hex::encode(verifying_key.as_bytes())
    );

    // Build MPC config
    let mpc_config = config.to_mpc_config(&verifying_key)?;
    let my_id = mpc_config.my_participant_id;
    let threshold = config.participants.threshold as usize;
    tracing::info!("My participant ID: {}, threshold: {}", my_id, threshold);

    // Start the main task
    let (future, _handle) = start_root_task("threshold-signer", async move {
        // Create TLS mesh network
        let (transport_sender, transport_receiver) = new_tls_mesh_network(
            &signing_key,
            &config.participants,
            my_id,
            config.p2p_port,
        )
        .await
        .expect("Failed to create TLS mesh network");

        tracing::info!("TLS mesh network started on port {}", config.p2p_port);

        // Start network client
        let (incoming_channel_tx, mut incoming_channel_rx) = mpsc::unbounded_channel();
        let (client, _network_receiver_task) = run_network_client(
            transport_sender,
            transport_receiver,
            incoming_channel_tx,
        )
        .await
        .expect("Failed to start network client");

        // Wait for peers to connect
        tracing::info!("Waiting for peers to connect...");
        client
            .leader_wait_for_all_connected()
            .await
            .expect("Failed waiting for peers");
        tracing::info!("All peers connected!");

        // Create orchestrator
        let orchestrator = Arc::new(Orchestrator::new(client.clone(), threshold));

        // Spawn incoming channel handler (for follower processing)
        let orchestrator_clone = orchestrator.clone();
        let _incoming_handler = tracking::spawn("incoming channel handler", async move {
            while let Some(channel) = incoming_channel_rx.recv().await {
                let orchestrator = orchestrator_clone.clone();
                tokio::spawn(async move {
                    if let Err(e) = orchestrator.process_incoming_channel(channel).await {
                        tracing::warn!("Failed to process incoming channel: {}", e);
                    }
                });
            }
        });

        // Start HTTP API server
        let app_state = AppState {
            orchestrator: orchestrator.clone(),
        };
        let router = create_router(app_state);
        let api_addr = format!("0.0.0.0:{}", config.api_port);
        tracing::info!("Starting API server on {}", api_addr);

        let listener = tokio::net::TcpListener::bind(&api_addr)
            .await
            .expect("Failed to bind API server");
        axum::serve(listener, router)
            .await
            .expect("API server failed");
    });

    future.await;
    Ok(())
}
