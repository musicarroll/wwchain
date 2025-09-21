use axum::{routing::{get, post}, Json, Router};
use http::StatusCode;
use axum::http::HeaderMap;
use serde::Deserialize;
use std::{env, net::SocketAddr, sync::{Arc, Mutex}};

use wwchain::{
    network_serialize::{send_message, NetworkMessage, request_chain_and_reconcile},
    blockchain::Blockchain,
};

use secp256k1::SecretKey;

#[derive(Clone)]
struct AppState {
    peer_addr: String,
    secret: Arc<SecretKey>,
    auth_token: Option<String>,
}

#[derive(Deserialize)]
struct TextReq {
    text: String,
    #[serde(default)]
    peer: Option<String>,
}

#[derive(Deserialize)]
struct TxReq {
    recipient: String,
    amount: u64,
    nonce: u64,
    #[serde(default)]
    peer: Option<String>,
}

#[derive(Deserialize)]
struct EventReq {
    kind: String,
    #[serde(default)]
    data: serde_json::Value,
    #[serde(default)]
    peer: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let peer_addr = env::var("WWCHAIN_PEER_ADDR").unwrap_or_else(|_| "127.0.0.1:6001".to_string());
    let listen_addr: SocketAddr = env::var("WWCHAIN_REST_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7000".to_string())
        .parse()
        .expect("invalid WWCHAIN_REST_ADDR");
    let secret_hex = env::var("WWCHAIN_SECRET_HEX").ok();
    let secret = match secret_hex {
        Some(h) => SecretKey::from_slice(&hex::decode(h).expect("SECRET hex")).expect("secret key"),
        None => {
            eprintln!("WWCHAIN_SECRET_HEX not set — generating ephemeral key");
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            SecretKey::from_slice(&bytes).expect("random secret key")
        }
    };
    let auth_token = env::var("WWCHAIN_REST_TOKEN").ok();
    let state = AppState { peer_addr, secret: Arc::new(secret), auth_token };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/chain", get(get_chain))
        .route("/text", post(post_text))
        .route("/tx", post(post_tx))
        .route("/event", post(post_event))
        .with_state(state);

    tracing::info!("REST shim listening on http://{}", listen_addr);
    axum::serve(tokio::net::TcpListener::bind(listen_addr).await.unwrap(), app)
        .await
        .unwrap();
}

async fn post_text(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(req): Json<TextReq>,
) -> Result<&'static str, (StatusCode, String)> {
    let target = req.peer.unwrap_or_else(|| state.peer_addr.clone());
    let msg = NetworkMessage::Text(req.text);
    send_message(&target, &msg, &state.secret)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok("ok")
}

async fn post_tx(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(req): Json<TxReq>,
) -> Result<&'static str, (StatusCode, String)> {
    use wwchain::transaction::Transaction;
    use secp256k1::{PublicKey, Secp256k1};

    let target = req.peer.unwrap_or_else(|| state.peer_addr.clone());
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &state.secret);
    let sender = hex::encode(pk.serialize());
    let mut tx = Transaction {
        sender,
        recipient: req.recipient,
        amount: req.amount,
        nonce: req.nonce,
        signature: None,
    };
    tx.sign(&state.secret);
    let msg = NetworkMessage::Transaction(tx);
    send_message(&target, &msg, &state.secret)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok("ok")
}

fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    if let Some(expected) = &state.auth_token {
        // Accept either X-Auth-Token or Authorization: Bearer <token>
        let header_token = headers
            .get("x-auth-token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|s| {
                    s.strip_prefix("Bearer ").map(|t| t.to_string())
                })
            });
        if header_token.as_deref() != Some(expected.as_str()) {
            return Err((StatusCode::UNAUTHORIZED, "invalid auth token".into()));
        }
    }
    Ok(())
}

async fn post_event(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EventReq>,
) -> Result<&'static str, (StatusCode, String)> {
    check_auth(&state, &headers)?;
    let target = req.peer.unwrap_or_else(|| state.peer_addr.clone());
    let msg = NetworkMessage::AppEvent { kind: req.kind, data: req.data };
    send_message(&target, &msg, &state.secret)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok("ok")
}

async fn get_chain(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Build a temporary local blockchain and fetch the peer chain into it
    let bc = Arc::new(Mutex::new(Blockchain::new(None)));
    // Request and reconcile from peer; ignore errors but try
    request_chain_and_reconcile(&state.peer_addr, bc.clone(), "rest_shim", &state.secret).await;
    let chain = {
        let guard = bc.lock().map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "mutex poisoned".to_string()))?;
        serde_json::to_value(&guard.chain).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };
    Ok(Json(chain))
}
