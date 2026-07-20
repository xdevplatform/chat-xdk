//! Fuzz the bounded Thrift parse of decrypted message content
//! (`MessageEntryHolder`), including reply previews carrying embedded raw
//! events: arbitrary bytes must produce `Ok`/`Err`, never a panic or
//! unbounded allocation.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = chat_xdk_core::internals::parse_message_content_bytes(data);
});
