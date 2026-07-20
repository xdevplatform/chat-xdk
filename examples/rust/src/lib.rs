//! Open-source chat-xdk example bot (library crate).
//!
//! Exposes the crypto core, the X API trait + client, and the bot loop so they
//! can be reused and unit-tested. The `main.rs` binary wires them together.

pub mod bot;
pub mod chat_core;
pub mod x_api;
