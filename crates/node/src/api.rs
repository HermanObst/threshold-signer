use crate::orchestrator::{EcdsaSignResult, EddsaSignResult, Orchestrator, Scheme};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub orchestrator: Arc<Orchestrator>,
}

#[derive(Debug, Deserialize)]
pub struct DkgRequest {
    pub scheme: Scheme,
}

#[derive(Debug, Serialize)]
pub struct DkgResponse {
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    pub scheme: Scheme,
    /// Hex-encoded payload. For ECDSA: 32-byte hash. For EdDSA: arbitrary bytes.
    pub payload: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum SignResponse {
    Ecdsa(EcdsaSignResult),
    Eddsa(EddsaSignResult),
}

#[derive(Debug, Deserialize)]
pub struct GenerateRequest {
    /// "triples" or "presignatures"
    pub asset: String,
}

#[derive(Debug, Serialize)]
pub struct GenerateResponse {
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub state: String,
    pub peers: Vec<String>,
    pub presignature_count: usize,
    pub triple_count: usize,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

async fn handle_dkg(
    State(state): State<AppState>,
    Json(req): Json<DkgRequest>,
) -> Result<Json<DkgResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = match req.scheme {
        Scheme::Ecdsa => state.orchestrator.run_ecdsa_dkg().await,
        Scheme::Eddsa => state.orchestrator.run_eddsa_dkg().await,
    };

    match result {
        Ok(public_key) => Ok(Json(DkgResponse { public_key })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn handle_sign(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, (StatusCode, Json<ErrorResponse>)> {
    let payload_bytes = hex::decode(req.payload.trim_start_matches("0x")).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid hex payload: {}", e),
            }),
        )
    })?;

    let result = match req.scheme {
        Scheme::Ecdsa => {
            if payload_bytes.len() != 32 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "ECDSA payload must be exactly 32 bytes".to_string(),
                    }),
                ));
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&payload_bytes);
            state
                .orchestrator
                .sign_ecdsa(hash)
                .await
                .map(SignResponse::Ecdsa)
        }
        Scheme::Eddsa => state
            .orchestrator
            .sign_eddsa(payload_bytes)
            .await
            .map(SignResponse::Eddsa),
    };

    match result {
        Ok(sig) => Ok(Json(sig)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn handle_generate(
    State(state): State<AppState>,
    Json(req): Json<GenerateRequest>,
) -> Result<Json<GenerateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = match req.asset.as_str() {
        "triples" => state.orchestrator.generate_triples().await,
        "presignatures" => state.orchestrator.generate_presignature().await.map(|_| 1),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Unknown asset type: {}", req.asset),
                }),
            ))
        }
    };

    match result {
        Ok(count) => Ok(Json(GenerateResponse { count })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn handle_status(State(state): State<AppState>) -> Json<StatusResponse> {
    let orchestrator = &state.orchestrator;
    let peers: Vec<String> = orchestrator
        .client
        .all_alive_participant_ids()
        .iter()
        .map(|p| p.to_string())
        .collect();

    Json(StatusResponse {
        state: format!("{:?}", orchestrator.get_state()),
        peers,
        presignature_count: orchestrator.presignature_count(),
        triple_count: orchestrator.triple_count(),
    })
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/dkg", post(handle_dkg))
        .route("/sign", post(handle_sign))
        .route("/generate", post(handle_generate))
        .route("/status", get(handle_status))
        .with_state(state)
}
