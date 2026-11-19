//! Open-source chat-xdk example bot (library crate).
//!
//! Exposes the crypto core, the X API trait + client, and the bot loop so they
//! can be reused and unit-tested. The `main.rs` binary wires them together.
//! `multi_user` has the helpers for a process with several signed-in users.

pub mod bot;
pub mod chat_core;
pub mod multi_user;
pub mod x_api;
