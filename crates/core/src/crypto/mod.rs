//! Cryptographic primitives for the X Chat SDK.
//!
//! This module provides all low-level cryptographic operations:
//! - Key types and structures
//! - Key generation, ECDH, and digital signatures (P-256)
//! - Hash functions (SHA-256, HKDF, HMAC)
//! - Message encryption/decryption (XSalsa20-Poly1305)

pub mod encryption;
pub mod hash;
pub mod key_factory;
pub mod keys;
