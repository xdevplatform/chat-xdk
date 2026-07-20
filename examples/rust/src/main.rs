//! Open-source, standalone chat-xdk example bot in Rust.
//!
//! Flow (encrypt on send, decrypt on receive): load keys -> batch-decrypt the backlog ->
//! poll for new events -> decrypt each -> reply -> encrypt + sign -> send.
//!
//! Run it: `cargo run` (needs the default `http` feature).

use std::collections::HashMap;
use std::fs;

use chatbot_rs::chat_core::ChatCore;

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

fn env_or<'a>(env: &'a HashMap<String, String>, key: &str) -> Option<String> {
    std::env::var(key).ok().or_else(|| env.get(key).cloned())
}

fn main() {
    let env = load_dotenv();
    let mut core = ChatCore::new();

    match env_or(&env, "CHAT_PRIVATE_KEYS_B64") {
        Some(blob) if !blob.is_empty() => {
            let version =
                env_or(&env, "CHAT_SIGNING_KEY_VERSION").unwrap_or_else(|| "1".to_string());
            if let Err(e) = core.load_keys(&blob, &version) {
                eprintln!("load_keys failed: {e}");
                std::process::exit(1);
            }
        }
        _ => {
            // First run: generate keys, print the registration payload + blob.
            match core.generate_and_register() {
                Ok((payload, private_blob)) => {
                    println!("No CHAT_PRIVATE_KEYS_B64 set — generated a new identity.\n");
                    println!("1) Register this public key with the X API (one-time provisioning):");
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload.public_key).unwrap_or_default()
                    );
                    println!(
                        "\n2) Save the private key in your .env so the bot reuses the identity:"
                    );
                    println!("CHAT_PRIVATE_KEYS_B64={private_blob}");
                    println!("\nThen re-run.");
                }
                Err(e) => {
                    eprintln!("generate_keypairs failed: {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
    }

    if let Err(e) = run(core, &env) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(feature = "http")]
fn run(core: ChatCore, env: &HashMap<String, String>) -> Result<(), String> {
    use std::time::Duration;

    use chatbot_rs::bot::Bot;
    use chatbot_rs::x_api::{ChatApi, HttpChatApi};

    let access_token = env_or(env, "X_ACCESS_TOKEN").unwrap_or_default();
    let conversation_id = env_or(env, "CHAT_CONVERSATION_ID").unwrap_or_default();
    if access_token.is_empty() || conversation_id.is_empty() {
        println!("Set X_ACCESS_TOKEN and CHAT_CONVERSATION_ID in .env to run the bot.");
        return Ok(());
    }

    let api = HttpChatApi::new(access_token, env_or(env, "X_API_BASE_URL"));
    let bot_user_id = match env_or(env, "CHAT_BOT_USER_ID") {
        Some(id) if !id.is_empty() => id,
        _ => api.get_my_user_id()?,
    };

    let mut bot = Bot::new(core, api, bot_user_id);
    bot.run(&conversation_id, Duration::from_secs(3))
}

#[cfg(not(feature = "http"))]
fn run(_core: ChatCore, _env: &HashMap<String, String>) -> Result<(), String> {
    println!("Built without the `http` feature — rebuild with `--features http` to run the bot.");
    Ok(())
}
