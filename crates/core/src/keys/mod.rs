//! Key lifecycle management for the X Chat SDK.
//!
//! This module handles:
//! - Juicebox SDK integration for PIN-protected key storage
//! - In-memory keypair management
//! - Conversation key operations

pub(crate) mod attachment_keys;
pub mod conversation_keys;
pub mod juicebox;
pub mod keypair_manager;
