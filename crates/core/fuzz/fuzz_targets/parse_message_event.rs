//! Fuzz the bounded Thrift parse of a raw backend event: arbitrary bytes must
//! produce `Ok`/`Err`, never a panic or unbounded allocation.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = chat_xdk_core::internals::parse_message_event_bytes(data);
});
