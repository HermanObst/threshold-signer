use anyhow::Context;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "mpc-cli")]
#[command(about = "CLI for standalone MPC nodes")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// URL of the MPC node API (e.g., http://localhost:3001)
    #[arg(long, default_value = "http://localhost:3001", global = true)]
    node: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Run distributed key generation
    Dkg {
        /// Signature scheme: "ecdsa" or "eddsa"
        #[arg(long)]
        scheme: String,
    },
    /// Generate ECDSA triples or presignatures
    Generate {
        /// Asset type: "triples" or "presignatures"
        #[arg(long)]
        asset: String,
    },
    /// Sign a payload
    Sign {
        /// Signature scheme: "ecdsa" or "eddsa"
        #[arg(long)]
        scheme: String,
        /// Hex-encoded payload (with optional 0x prefix)
        #[arg(long)]
        payload: String,
    },
    /// Verify a signature
    Verify {
        /// Signature scheme: "ecdsa" or "eddsa"
        #[arg(long)]
        scheme: String,
        /// Hex-encoded payload (same as was passed to sign)
        #[arg(long)]
        payload: String,
        /// Hex-encoded public key (from DKG or sign response)
        #[arg(long)]
        public_key: String,
        /// Hex-encoded signature (for EdDSA: 64-byte signature; for ECDSA: not used)
        #[arg(long)]
        signature: Option<String>,
        /// Hex-encoded r value from ECDSA sign response (hex of JSON-serialized AffinePoint)
        #[arg(long)]
        signature_r: Option<String>,
        /// Hex-encoded s value from ECDSA sign response
        #[arg(long)]
        signature_s: Option<String>,
    },
    /// Get node status
    Status,
    /// Derive Ed25519 public key from a hex-encoded secret key
    DerivePubkey {
        /// Hex-encoded 32-byte Ed25519 secret key
        #[arg(long)]
        secret_key: String,
    },
}

#[derive(Debug, Serialize)]
struct DkgRequest {
    scheme: String,
}

#[derive(Debug, Deserialize)]
struct DkgResponse {
    public_key: String,
}

#[derive(Debug, Serialize)]
struct SignRequest {
    scheme: String,
    payload: String,
}

#[derive(Debug, Serialize)]
struct GenerateRequest {
    asset: String,
}

#[derive(Debug, Deserialize)]
struct GenerateResponse {
    count: usize,
}

#[derive(Debug, Deserialize)]
struct StatusResponse {
    state: String,
    peers: Vec<String>,
    presignature_count: usize,
    triple_count: usize,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

fn verify_ecdsa(
    payload_hex: &str,
    r_hex: &str,
    s_hex: &str,
    public_key_hex: &str,
) -> anyhow::Result<bool> {
    use k256::ecdsa::{Signature, VerifyingKey};
    use k256::{AffinePoint, EncodedPoint};

    // The r field from the sign response is hex(json(AffinePoint)).
    // Decode: hex -> JSON bytes -> AffinePoint -> extract x-coordinate as r scalar.
    let r_json_bytes = hex::decode(r_hex).context("Invalid hex for signature r")?;
    let r_point: AffinePoint =
        serde_json::from_slice(&r_json_bytes).context("Failed to deserialize r as AffinePoint")?;
    let r_encoded = EncodedPoint::from(r_point);
    let r_x_bytes = r_encoded.x().context("r point is identity")?;

    // s is hex of raw 32-byte scalar
    let s_bytes = hex::decode(s_hex).context("Invalid hex for signature s")?;
    anyhow::ensure!(s_bytes.len() == 32, "s must be 32 bytes, got {}", s_bytes.len());

    // Construct standard ECDSA signature from (r, s) as two 32-byte big-endian values
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r_x_bytes);
    sig_bytes[32..].copy_from_slice(&s_bytes);
    let sig = Signature::from_bytes((&sig_bytes).into())
        .context("Failed to construct ECDSA signature")?;

    // Decode public key (SEC1 compressed or uncompressed)
    let pk_bytes = hex::decode(public_key_hex).context("Invalid hex for public key")?;
    let vk = VerifyingKey::from_sec1_bytes(&pk_bytes)
        .context("Failed to parse public key as SEC1")?;

    // For ECDSA, payload is already a 32-byte hash
    let payload_bytes = hex::decode(payload_hex).context("Invalid hex for payload")?;
    anyhow::ensure!(
        payload_bytes.len() == 32,
        "ECDSA payload must be 32-byte hash, got {} bytes",
        payload_bytes.len()
    );

    // Use low-level verify with prehashed message
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    match vk.verify_prehash(&payload_bytes, &sig) {
        Ok(()) => Ok(true),
        Err(e) => {
            eprintln!("Verification failed: {}", e);
            Ok(false)
        }
    }
}

fn verify_eddsa(
    payload_hex: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> anyhow::Result<bool> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let sig_bytes = hex::decode(signature_hex).context("Invalid hex for signature")?;
    anyhow::ensure!(
        sig_bytes.len() == 64,
        "EdDSA signature must be 64 bytes, got {}",
        sig_bytes.len()
    );
    let sig = Signature::from_bytes(sig_bytes[..64].try_into().unwrap());

    let pk_bytes = hex::decode(public_key_hex).context("Invalid hex for public key")?;
    anyhow::ensure!(
        pk_bytes.len() == 32,
        "EdDSA public key must be 32 bytes, got {}",
        pk_bytes.len()
    );
    let vk = VerifyingKey::from_bytes(pk_bytes[..32].try_into().unwrap())
        .context("Invalid EdDSA public key")?;

    let payload_bytes = hex::decode(payload_hex).context("Invalid hex for payload")?;

    match vk.verify(&payload_bytes, &sig) {
        Ok(()) => Ok(true),
        Err(e) => {
            eprintln!("Verification failed: {}", e);
            Ok(false)
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::new();

    match cli.command {
        Commands::Dkg { scheme } => {
            println!("Running DKG for scheme: {}", scheme);
            let resp = client
                .post(format!("{}/dkg", cli.node))
                .json(&DkgRequest { scheme })
                .send()
                .await
                .context("Failed to connect to node")?;

            if resp.status().is_success() {
                let result: DkgResponse = resp.json().await?;
                println!("DKG complete!");
                println!("Public key: {}", result.public_key);
            } else {
                let err: ErrorResponse = resp.json().await?;
                eprintln!("Error: {}", err.error);
                std::process::exit(1);
            }
        }

        Commands::Generate { asset } => {
            println!("Generating {}...", asset);
            let resp = client
                .post(format!("{}/generate", cli.node))
                .json(&GenerateRequest { asset })
                .send()
                .await
                .context("Failed to connect to node")?;

            if resp.status().is_success() {
                let result: GenerateResponse = resp.json().await?;
                println!("Generated {} items", result.count);
            } else {
                let err: ErrorResponse = resp.json().await?;
                eprintln!("Error: {}", err.error);
                std::process::exit(1);
            }
        }

        Commands::Sign { scheme, payload } => {
            let payload = payload.trim_start_matches("0x").to_string();
            println!("Signing with scheme: {}", scheme);

            let resp = client
                .post(format!("{}/sign", cli.node))
                .json(&SignRequest {
                    scheme,
                    payload,
                })
                .send()
                .await
                .context("Failed to connect to node")?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                println!("Signature result:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                let err: ErrorResponse = resp.json().await?;
                eprintln!("Error: {}", err.error);
                std::process::exit(1);
            }
        }

        Commands::Verify {
            scheme,
            payload,
            public_key,
            signature,
            signature_r,
            signature_s,
        } => {
            let payload = payload.trim_start_matches("0x").to_string();
            let public_key = public_key.trim_start_matches("0x").to_string();

            let valid = match scheme.to_lowercase().as_str() {
                "ecdsa" => {
                    let r = signature_r
                        .as_deref()
                        .context("--signature-r is required for ECDSA")?
                        .trim_start_matches("0x");
                    let s = signature_s
                        .as_deref()
                        .context("--signature-s is required for ECDSA")?
                        .trim_start_matches("0x");
                    verify_ecdsa(&payload, r, s, &public_key)?
                }
                "eddsa" => {
                    let sig = signature
                        .as_deref()
                        .context("--signature is required for EdDSA")?
                        .trim_start_matches("0x");
                    verify_eddsa(&payload, sig, &public_key)?
                }
                other => {
                    anyhow::bail!("Unknown scheme: {}. Use 'ecdsa' or 'eddsa'.", other);
                }
            };

            if valid {
                println!("Signature is VALID");
            } else {
                println!("Signature is INVALID");
                std::process::exit(1);
            }
        }

        Commands::DerivePubkey { secret_key } => {
            let secret_key = secret_key.trim_start_matches("0x");
            let secret_bytes: [u8; 32] = hex::decode(secret_key)
                .context("Invalid hex for secret key")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Secret key must be 32 bytes"))?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
            let verifying_key = signing_key.verifying_key();
            println!("{}", hex::encode(verifying_key.as_bytes()));
            return Ok(());
        }

        Commands::Status => {
            let resp = client
                .get(format!("{}/status", cli.node))
                .send()
                .await
                .context("Failed to connect to node")?;

            if resp.status().is_success() {
                let status: StatusResponse = resp.json().await?;
                println!("Node Status:");
                println!("  State: {}", status.state);
                println!("  Connected peers: {:?}", status.peers);
                println!("  Presignatures: {}", status.presignature_count);
                println!("  Triples: {}", status.triple_count);
            } else {
                let err: ErrorResponse = resp.json().await?;
                eprintln!("Error: {}", err.error);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
