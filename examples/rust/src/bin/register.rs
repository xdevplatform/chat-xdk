//! One-time public-key registration for a bot identity.
//!
//! Registering a public key is a rare, rate-limited write (only a few per 24h
//! per user) that establishes the identity every message is signed and
//! encrypted against. This binary does it safely and is re-runnable: if it is
//! interrupted after generating keys but before the server confirms, running it
//! again resumes the same identity instead of minting a new one.
//!
//! Flow:
//!   1. Refuse if this identity is already registered (unless `--force`).
//!   2. Generate the keypair once; persist the private-key blob AND the
//!      (public) registration body to disk BEFORE any network call, so an error
//!      never loses the identity and a retry re-sends the same registration.
//!   3. Before POSTing, check whether this exact public key is already on the
//!      account (a prior POST can apply server-side even after erroring) and
//!      adopt it instead of re-registering — a duplicate POST wastes the budget.
//!   4. POST the registration; stop cleanly on 429 rather than retrying.
//!   5. Record the registered key version and mark the identity registered.
//!
//! This example builds `chat-xdk-core` without the `juicebox` feature, so the
//! identity's durable store is the local private-key blob (the reference
//! Python example additionally offers an optional Juicebox backup, which needs
//! that feature and an async runtime).
//!
//! Run: `cargo run --bin register -- --confirm`

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use chatbot_rs::chat_core::ChatCore;
use chatbot_rs::x_api::{ChatApi, HttpChatApi, RegisterError};
use serde_json::{json, Value};

/// Tiny .env loader so the example has no extra dependencies.
fn load_dotenv() -> HashMap<String, String> {
    let mut env = HashMap::new();
    if let Ok(contents) = fs::read_to_string(".env") {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                env.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    env
}

fn env_or(env: &HashMap<String, String>, key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| env.get(key).cloned().filter(|v| !v.is_empty()))
}

fn state_dir() -> PathBuf {
    PathBuf::from("state")
}

fn read_marker(path: &Path) -> Value {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

fn write_marker(path: &Path, marker: &Value) -> Result<(), String> {
    fs::create_dir_all(state_dir()).map_err(|e| e.to_string())?;
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(marker).unwrap()),
    )
    .map_err(|e| e.to_string())
}

/// Write the exported private keys to disk (owner-only on unix).
fn save_blob(path: &Path, blob: &str) -> Result<(), String> {
    fs::create_dir_all(state_dir()).map_err(|e| e.to_string())?;
    fs::write(path, format!("{blob}\n")).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn main() {
    let env = load_dotenv();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let force = args.iter().any(|a| a == "--force");
    let confirm = args.iter().any(|a| a == "--confirm");
    if !confirm && !force {
        println!("This registers a bot identity (a rate-limited, one-time action).");
        println!("Re-run with --confirm when ready:  cargo run --bin register -- --confirm");
        std::process::exit(1);
    }
    if let Err(e) = register(&env, force) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn register(env: &HashMap<String, String>, force: bool) -> Result<(), String> {
    let token = env_or(env, "X_ACCESS_TOKEN")
        .ok_or("set X_ACCESS_TOKEN (OAuth2 user token) in the environment or .env")?;

    let blob_path = state_dir().join("private_keys.b64");
    let marker_path = state_dir().join("registration.json");

    let marker = read_marker(&marker_path);
    if marker["registered"].as_bool().unwrap_or(false) && !force {
        return Err(format!(
            "Already registered (version {}). Pass --force only if you intend to create a NEW identity.",
            marker["version"].as_str().unwrap_or("?")
        ));
    }

    let api = HttpChatApi::new(token, env_or(env, "X_API_BASE_URL"));
    let user_id = match env_or(env, "CHAT_BOT_USER_ID") {
        Some(id) => id,
        None => api.get_my_user_id()?,
    };

    let mut core = ChatCore::new();

    // Resume an interrupted run with the SAME identity; only generate a fresh
    // one when there is no saved blob. Persisting the blob and the registration
    // body before the network POST is what makes a failed POST safe to retry
    // without wasting the daily registration budget.
    let resuming = blob_path.exists() && marker.get("body").is_some() && !force;
    let (body, mut version) = if resuming {
        let blob = fs::read_to_string(&blob_path).map_err(|e| e.to_string())?;
        core.load_keys(blob.trim(), marker["version"].as_str().unwrap_or("1"))
            .map_err(|e| e.to_string())?;
        println!("Resuming the saved identity ({}).", blob_path.display());
        (
            marker["body"].clone(),
            marker["version"].as_str().unwrap_or("1").to_string(),
        )
    } else {
        let (payload, blob) = core.generate_and_register().map_err(|e| e.to_string())?;
        let version = payload.version.clone().unwrap_or_else(|| "1".to_string());
        // Only public material goes into the body, so it is safe to persist and
        // re-send on a later run.
        let body = json!({
            "public_key": {
                "public_key": payload.public_key.public_key,
                "signing_public_key": payload.public_key.signing_public_key,
                "identity_public_key_signature": payload.public_key.identity_public_key_signature,
                "signing_public_key_signature": payload.public_key.signing_public_key_signature,
                "registration_method": payload.public_key.registration_method,
            },
            "version": version,
            "generate_version": payload.generate_version,
        });
        save_blob(&blob_path, &blob)?;
        write_marker(
            &marker_path,
            &json!({ "registered": false, "user_id": user_id, "version": version, "body": body }),
        )?;
        println!(
            "Generated a new identity; private keys saved to {}.",
            blob_path.display()
        );
        (body, version)
    };

    let our_public_key = body["public_key"]["public_key"].as_str().unwrap_or("");

    // Reconcile: if our exact public key is already on the account, adopt it
    // rather than POSTing again (a prior POST may have applied after erroring).
    let existing = api.get_public_keys(&user_id)?;
    if let Some(found) = existing
        .iter()
        .find(|k| k.identity_public_key == our_public_key)
    {
        if !found.public_key_version.is_empty() {
            version = found.public_key_version.clone();
        }
        println!(
            "Public key already registered on the account (version {version}); skipping POST."
        );
    } else {
        println!("Registering public key version {version} …");
        match api.add_user_public_key(&user_id, &body) {
            Ok(resp) => {
                let data = match &resp["data"] {
                    Value::Array(a) => a.first().cloned().unwrap_or_else(|| json!({})),
                    other => other.clone(),
                };
                if let Some(v) = data["public_key_version"].as_str() {
                    version = v.to_string();
                }
            }
            Err(RegisterError::RateLimited { reset_epoch }) => {
                let when = reset_epoch
                    .map(|e| {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        let mins = (e - now).max(0) / 60;
                        format!("in about {mins} min (unix time {e})")
                    })
                    .unwrap_or_else(|| "the next window".to_string());
                return Err(format!(
                    "Registration is rate limited (429). The daily budget is exhausted; wait until \
                     {when} and re-run — the saved identity resumes, so no budget is wasted."
                ));
            }
            Err(e) => return Err(e.to_string()),
        }
    }

    core.set_registered_version(&version);
    core.set_identity(&user_id);
    write_marker(
        &marker_path,
        &json!({
            "registered": true,
            "user_id": user_id,
            "version": version,
            "registered_at": registered_at_stamp(),
        }),
    )?;

    let blob = fs::read_to_string(&blob_path)
        .map_err(|e| e.to_string())?
        .trim()
        .to_string();
    println!();
    println!("Registration complete.");
    println!("  version:      {version}");
    println!("  private keys: {} (owner-only)", blob_path.display());
    println!("Add these to .env to run the bot:");
    println!("  CHAT_PRIVATE_KEYS_B64={blob}");
    println!("  CHAT_SIGNING_KEY_VERSION={version}");
    Ok(())
}

/// Best-effort timestamp for the marker (seconds since the epoch is enough to
/// record when registration completed; no external date dependency).
fn registered_at_stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch:{secs}")
}
