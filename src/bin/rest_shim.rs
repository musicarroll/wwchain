use axum::{routing::{get, post}, Json, Router};
use http::StatusCode;
use axum::http::HeaderMap;
use serde::Deserialize;
use std::{env, net::SocketAddr, sync::{Arc, Mutex}};
use serde_json::{json, Value as JsonValue};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use wwchain::{
    network_serialize::{send_message, NetworkMessage, request_chain_and_reconcile, SignedMessage},
    blockchain::Blockchain,
};

use secp256k1::SecretKey;

#[derive(Clone)]
struct AppState {
    peer_addr: String,
    secret: Arc<SecretKey>,
    auth_token: Option<String>,
    network_label: String,
    pubkey_hex: String,
    ephemeral: bool,
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

#[derive(Deserialize)]
struct SignedReq {
    signed: SignedMessage,
    #[serde(default)]
    peer: Option<String>,
}

#[derive(Deserialize)]
struct VerifyReq {
    pubkey: String,
    message: String,
    signature: String,
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
    let (secret, ephemeral) = match secret_hex {
        Some(h) => (SecretKey::from_slice(&hex::decode(h).expect("SECRET hex")).expect("secret key"), false),
        None => {
            eprintln!("WWCHAIN_SECRET_HEX not set — generating ephemeral key");
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            (SecretKey::from_slice(&bytes).expect("random secret key"), true)
        }
    };
    let auth_token = env::var("WWCHAIN_REST_TOKEN").ok();
    let network_label = env::var("WWCHAIN_NETWORK").unwrap_or_else(|_| "unknown".to_string());
    // Precompute pubkey hex for info endpoint
    let secp = secp256k1::Secp256k1::new();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let pubkey_hex = hex::encode(pk.serialize());
    let state = AppState { peer_addr, secret: Arc::new(secret), auth_token, network_label, pubkey_hex, ephemeral };

    let app = Router::new()
        .route("/health", get(get_health))
        .route("/info", get(get_info))
        .route("/balance/:pubkey", get(get_balance))
        .route("/chain", get(get_chain))
        .route("/text", post(post_text))
        .route("/tx", post(post_tx))
        .route("/event", post(post_event))
        // Forward pre-signed messages created by clients
        .route("/tx_signed", post(post_tx_signed))
        .route("/event_signed", post(post_event_signed))
        .route("/verify_signature", post(post_verify_signature))
        .with_state(state);

    tracing::info!("REST shim listening on http://{}", listen_addr);
    axum::serve(tokio::net::TcpListener::bind(listen_addr).await.unwrap(), app)
        .await
        .unwrap();
}

async fn post_text(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TextReq>,
) -> Result<&'static str, (StatusCode, Json<JsonValue>)> {
    check_auth(&state, &headers)?;
    let target = req.peer.unwrap_or_else(|| state.peer_addr.clone());
    let msg = NetworkMessage::Text(req.text);
    send_message(&target, &msg, &state.secret)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(json!({"error": e.to_string()}))))?;
    Ok("ok")
}

async fn post_tx(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TxReq>,
) -> Result<&'static str, (StatusCode, Json<JsonValue>)> {
    check_auth(&state, &headers)?;
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
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(json!({"error": e.to_string()}))))?;
    Ok("ok")
}

fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, Json<JsonValue>)> {
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
            return Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid auth token"}))));
        }
    }
    Ok(())
}

async fn post_event(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EventReq>,
) -> Result<&'static str, (StatusCode, Json<JsonValue>)> {
    check_auth(&state, &headers)?;
    let target = req.peer.unwrap_or_else(|| state.peer_addr.clone());
    let msg = NetworkMessage::AppEvent { kind: req.kind, data: req.data };
    send_message(&target, &msg, &state.secret)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(json!({"error": e.to_string()}))))?;
    Ok("ok")
}

async fn forward_signed(addr: &str, signed: &SignedMessage) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = TcpStream::connect(addr).await?;
    let buf = serde_json::to_vec(&signed)?;
    let buf = {
        let len = (buf.len() as u32).to_be_bytes();
        [len.to_vec(), buf].concat()
    };
    stream.write_all(&buf).await?;
    let mut resp = [0u8; 4096];
    let _ = stream.read(&mut resp).await.unwrap_or(0);
    Ok(())
}

async fn post_tx_signed(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SignedReq>,
) -> Result<&'static str, (StatusCode, Json<JsonValue>)> {
    check_auth(&state, &headers)?;
    // Basic validation: ensure payload matches Transaction
    match &req.signed.message.payload {
        NetworkMessage::Transaction(_) => {}
        _ => return Err((StatusCode::BAD_REQUEST, Json(json!({"error":"expected Transaction payload"})))),
    }
    let target = req.peer.unwrap_or_else(|| state.peer_addr.clone());
    forward_signed(&target, &req.signed)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(json!({"error": e.to_string()}))))?;
    Ok("ok")
}

async fn post_event_signed(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SignedReq>,
) -> Result<&'static str, (StatusCode, Json<JsonValue>)> {
    check_auth(&state, &headers)?;
    match &req.signed.message.payload {
        NetworkMessage::AppEvent { .. } => {}
        _ => return Err((StatusCode::BAD_REQUEST, Json(json!({"error":"expected AppEvent payload"})))),
    }
    let target = req.peer.unwrap_or_else(|| state.peer_addr.clone());
    forward_signed(&target, &req.signed)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(json!({"error": e.to_string()}))))?;
    Ok("ok")
}

async fn post_verify_signature(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    Json(req): Json<VerifyReq>,
) -> Result<Json<JsonValue>, (StatusCode, Json<JsonValue>)> {
    // optional auth: only enforce if token configured
    check_auth(&state, &headers)?;
    // Decode pubkey and signature
    use secp256k1::{ecdsa::Signature, PublicKey, Secp256k1, Message};
    let pub_bytes = match hex::decode(&req.pubkey) { Ok(b) => b, Err(_) => return Ok(Json(json!({"valid": false, "error": "invalid pubkey hex"}))) };
    let sig_bytes = match hex::decode(&req.signature) { Ok(b) => b, Err(_) => return Ok(Json(json!({"valid": false, "error": "invalid signature hex"}))) };
    let pubkey = match PublicKey::from_slice(&pub_bytes) { Ok(p) => p, Err(_) => return Ok(Json(json!({"valid": false, "error": "invalid pubkey format"}))) };
    let sig = match Signature::from_compact(&sig_bytes) { Ok(s) => s, Err(_) => return Ok(Json(json!({"valid": false, "error": "invalid signature format"}))) };
    let digest = {
        use sha2::{Sha256, Digest};
        let mut h = Sha256::new();
        h.update(req.message.as_bytes());
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    };
    let msg = match Message::from_slice(&digest) { Ok(m) => m, Err(_) => return Ok(Json(json!({"valid": false, "error": "invalid digest"}))) };
    let secp = Secp256k1::verification_only();
    let ok = secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok();
    Ok(Json(json!({"valid": ok})))
}

async fn get_chain(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Build a temporary local blockchain and fetch the peer chain into it
    let bc = Arc::new(Mutex::new(Blockchain::new(None)));
    {
        // Align local validation difficulty with configured network (testnet uses lighter target)
        if state.network_label.eq_ignore_ascii_case("testnet") {
            if let Ok(mut g) = bc.lock() {
                g.difficulty_prefix = "00".into();
            }
        }
    }
    // Request and reconcile from peer; ignore errors but try
    request_chain_and_reconcile(&state.peer_addr, bc.clone(), "rest_shim", &state.secret).await;
    let chain = {
        let guard = bc.lock().map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "mutex poisoned".to_string()))?;
        serde_json::to_value(&guard.chain).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };
    Ok(Json(chain))
}

async fn get_health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<JsonValue> {
    let (peer_reachable, peer_error) = peer_status(&state).await;
    Json(json!({
        "status": "ok",
        "peer_reachable": peer_reachable,
        "peer_error": peer_error,
    }))
}

async fn get_info(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<JsonValue> {
    let (peer_reachable, _err) = peer_status(&state).await;
    let bc = Arc::new(Mutex::new(Blockchain::new(None)));
    if state.network_label.eq_ignore_ascii_case("testnet") {
        if let Ok(mut g) = bc.lock() { g.difficulty_prefix = "00".into(); }
    }
    // Best-effort height probe
    request_chain_and_reconcile(&state.peer_addr, bc.clone(), "rest_shim", &state.secret).await;
    let (height, last_hash, last_time_ms, next_nonce) = match bc.lock() {
        Ok(g) => {
            let h = g.chain.len();
            let (hh, ts) = g.chain.last().map(|b| (b.hash.clone(), b.timestamp)).unwrap_or_default();
            let nn = g.nonces.get(&state.pubkey_hex).copied().unwrap_or(0);
            (h, hh, ts as u64, nn)
        }
        Err(_) => (0, String::new(), 0, 0),
    };
    Json(json!({
        "pubkey_hex": state.pubkey_hex,
        "peer_addr": state.peer_addr,
        "network": state.network_label,
        "height": height,
        "peer_reachable": peer_reachable,
        "last_block_hash": last_hash,
        "last_block_timestamp_ms": last_time_ms,
        "next_nonce": next_nonce,
        "ephemeral": state.ephemeral,
    }))
}

async fn get_balance(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Path(pubkey): axum::extract::Path<String>,
) -> Result<Json<JsonValue>, (StatusCode, Json<JsonValue>)> {
    let bc = Arc::new(Mutex::new(Blockchain::new(None)));
    if state.network_label.eq_ignore_ascii_case("testnet") {
        if let Ok(mut g) = bc.lock() { g.difficulty_prefix = "00".into(); }
    }
    request_chain_and_reconcile(&state.peer_addr, bc.clone(), "rest_shim", &state.secret).await;
    let res = {
        match bc.lock() {
            Ok(guard) => {
                let bal = guard.balances.get(&pubkey).copied().unwrap_or(0);
                let next_nonce = guard.nonces.get(&pubkey).copied().unwrap_or(0);
                Ok(Json(json!({"pubkey": pubkey, "balance": bal, "height": guard.chain.len(), "next_nonce": next_nonce})))
            }
            Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "mutex poisoned"}))))
        }
    };
    res
}

async fn peer_status(state: &AppState) -> (bool, Option<String>) {
    match timeout(Duration::from_millis(300), TcpStream::connect(&state.peer_addr)).await {
        Ok(Ok(_stream)) => (true, None),
        Ok(Err(e)) => (false, Some(e.to_string())),
        Err(_) => (false, Some("timeout".into())),
    }
}
