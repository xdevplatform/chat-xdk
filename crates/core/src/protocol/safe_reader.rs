//! Bounded Thrift input protocol wrapper.
//!
//! `BoundedProtocol` wraps a `TInputProtocol` and enforces a hard cap on
//! list/set/map element counts before the generated code calls
//! `Vec::with_capacity`.  The patched thrift crate (via `[patch.crates-io]`)
//! handles `read_bytes` size limits and negative length prefixes directly.
//!
//! Two limits apply:
//! - a **per-container** cap ([`MAX_COLLECTION_SIZE`]), and
//! - a **cumulative** cap across the whole deserialization pass
//!   ([`MAX_TOTAL_ELEMENTS`]), so nested containers cannot multiply the
//!   per-container cap (e.g. 10,000 lists of 10,000 elements each).

use thrift::protocol::{
    TFieldIdentifier, TInputProtocol, TListIdentifier, TMapIdentifier, TMessageIdentifier,
    TSetIdentifier, TStructIdentifier,
};

/// Maximum number of elements in a Thrift list, set, or map.
const MAX_COLLECTION_SIZE: i32 = 10_000;

/// Maximum cumulative number of container elements across one full
/// deserialization pass (one `BoundedProtocol` instance == one parsed
/// message). Legitimate chat events carry at most a few hundred elements;
/// 100,000 leaves orders-of-magnitude headroom while bounding the total
/// allocation an attacker can force via nesting.
const MAX_TOTAL_ELEMENTS: u64 = 100_000;

/// A `TInputProtocol` wrapper that rejects oversized collections and strings.
pub struct BoundedProtocol<'a> {
    inner: &'a mut dyn TInputProtocol,
    /// Running total of declared container elements in this pass.
    total_elements: u64,
}

impl<'a> BoundedProtocol<'a> {
    /// Wrap an existing protocol with bounded size checks.
    pub fn new(inner: &'a mut dyn TInputProtocol) -> Self {
        Self {
            inner,
            total_elements: 0,
        }
    }

    fn check_collection_size(&mut self, size: i32, kind: &str) -> thrift::Result<()> {
        if !(0..=MAX_COLLECTION_SIZE).contains(&size) {
            return Err(thrift::Error::Protocol(thrift::ProtocolError {
                kind: thrift::ProtocolErrorKind::SizeLimit,
                message: format!(
                    "{} size {} exceeds maximum {}",
                    kind, size, MAX_COLLECTION_SIZE
                ),
            }));
        }

        // Cumulative cap: bound the total declared elements across all
        // (possibly nested) containers in this deserialization pass.
        self.total_elements = self.total_elements.saturating_add(size as u64);
        if self.total_elements > MAX_TOTAL_ELEMENTS {
            return Err(thrift::Error::Protocol(thrift::ProtocolError {
                kind: thrift::ProtocolErrorKind::SizeLimit,
                message: format!(
                    "cumulative container elements {} exceed maximum {} (last: {} of size {})",
                    self.total_elements, MAX_TOTAL_ELEMENTS, kind, size
                ),
            }));
        }
        Ok(())
    }
}

impl TInputProtocol for BoundedProtocol<'_> {
    fn read_message_begin(&mut self) -> thrift::Result<TMessageIdentifier> {
        self.inner.read_message_begin()
    }
    fn read_message_end(&mut self) -> thrift::Result<()> {
        self.inner.read_message_end()
    }
    fn read_struct_begin(&mut self) -> thrift::Result<Option<TStructIdentifier>> {
        self.inner.read_struct_begin()
    }
    fn read_struct_end(&mut self) -> thrift::Result<()> {
        self.inner.read_struct_end()
    }
    fn read_field_begin(&mut self) -> thrift::Result<TFieldIdentifier> {
        self.inner.read_field_begin()
    }
    fn read_field_end(&mut self) -> thrift::Result<()> {
        self.inner.read_field_end()
    }
    fn read_bool(&mut self) -> thrift::Result<bool> {
        self.inner.read_bool()
    }
    fn read_bytes(&mut self) -> thrift::Result<Vec<u8>> {
        // The patched thrift crate checks negativity and enforces
        // TConfiguration::max_string_size (default 100 MB) before allocating.
        self.inner.read_bytes()
    }
    fn read_i8(&mut self) -> thrift::Result<i8> {
        self.inner.read_i8()
    }
    fn read_i16(&mut self) -> thrift::Result<i16> {
        self.inner.read_i16()
    }
    fn read_i32(&mut self) -> thrift::Result<i32> {
        self.inner.read_i32()
    }
    fn read_i64(&mut self) -> thrift::Result<i64> {
        self.inner.read_i64()
    }
    fn read_double(&mut self) -> thrift::Result<f64> {
        self.inner.read_double()
    }
    fn read_string(&mut self) -> thrift::Result<String> {
        self.inner.read_string()
    }
    fn read_list_begin(&mut self) -> thrift::Result<TListIdentifier> {
        let ident = self.inner.read_list_begin()?;
        self.check_collection_size(ident.size, "list")?;
        Ok(ident)
    }
    fn read_list_end(&mut self) -> thrift::Result<()> {
        self.inner.read_list_end()
    }
    fn read_set_begin(&mut self) -> thrift::Result<TSetIdentifier> {
        let ident = self.inner.read_set_begin()?;
        self.check_collection_size(ident.size, "set")?;
        Ok(ident)
    }
    fn read_set_end(&mut self) -> thrift::Result<()> {
        self.inner.read_set_end()
    }
    fn read_map_begin(&mut self) -> thrift::Result<TMapIdentifier> {
        let ident = self.inner.read_map_begin()?;
        self.check_collection_size(ident.size, "map")?;
        Ok(ident)
    }
    fn read_map_end(&mut self) -> thrift::Result<()> {
        self.inner.read_map_end()
    }
    fn read_byte(&mut self) -> thrift::Result<u8> {
        self.inner.read_byte()
    }

    fn read_uuid(&mut self) -> thrift::Result<uuid::Uuid> {
        self.inner.read_uuid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use thrift::protocol::TBinaryInputProtocol;

    /// Build a minimal Thrift binary list header: element type (1 byte) + size (4 bytes BE).
    fn make_list_header(elem_type: u8, size: i32) -> Vec<u8> {
        let mut buf = vec![elem_type];
        buf.extend_from_slice(&size.to_be_bytes());
        buf
    }

    #[test]
    fn test_reasonable_list_size_accepted() {
        let data = make_list_header(8, 100); // i32 list, 100 elements
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let ident = bounded.read_list_begin().unwrap();
        assert_eq!(ident.size, 100);
    }

    #[test]
    fn test_oversized_list_rejected() {
        let data = make_list_header(8, 1_000_000);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let result = bounded.read_list_begin();
        assert!(result.is_err());
    }

    #[test]
    fn test_negative_list_size_rejected() {
        let data = make_list_header(8, -1);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_list_begin().is_err());
    }

    #[test]
    fn test_max_boundary_accepted() {
        let data = make_list_header(8, MAX_COLLECTION_SIZE);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_list_begin().is_ok());
    }

    #[test]
    fn test_max_boundary_plus_one_rejected() {
        let data = make_list_header(8, MAX_COLLECTION_SIZE + 1);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_list_begin().is_err());
    }

    // Set size checks

    /// Build a Thrift binary set header (same format as list).
    fn make_set_header(elem_type: u8, size: i32) -> Vec<u8> {
        let mut buf = vec![elem_type];
        buf.extend_from_slice(&size.to_be_bytes());
        buf
    }

    #[test]
    fn test_reasonable_set_size_accepted() {
        let data = make_set_header(8, 50);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let ident = bounded.read_set_begin().unwrap();
        assert_eq!(ident.size, 50);
    }

    #[test]
    fn test_oversized_set_rejected() {
        let data = make_set_header(8, 1_000_000);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_set_begin().is_err());
    }

    #[test]
    fn test_negative_set_size_rejected() {
        let data = make_set_header(8, -1);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_set_begin().is_err());
    }

    #[test]
    fn test_set_max_boundary_accepted() {
        let data = make_set_header(8, MAX_COLLECTION_SIZE);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_set_begin().is_ok());
    }

    #[test]
    fn test_set_max_boundary_plus_one_rejected() {
        let data = make_set_header(8, MAX_COLLECTION_SIZE + 1);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_set_begin().is_err());
    }

    // Map size checks

    /// Build a Thrift binary map header: key_type (1B) + val_type (1B) + size (4B BE).
    fn make_map_header(key_type: u8, val_type: u8, size: i32) -> Vec<u8> {
        let mut buf = vec![key_type, val_type];
        buf.extend_from_slice(&size.to_be_bytes());
        buf
    }

    #[test]
    fn test_reasonable_map_size_accepted() {
        let data = make_map_header(11, 8, 200); // string -> i32
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let ident = bounded.read_map_begin().unwrap();
        assert_eq!(ident.size, 200);
    }

    #[test]
    fn test_oversized_map_rejected() {
        let data = make_map_header(11, 8, 1_000_000);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_map_begin().is_err());
    }

    #[test]
    fn test_negative_map_size_rejected() {
        let data = make_map_header(11, 8, -5);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_map_begin().is_err());
    }

    #[test]
    fn test_map_max_boundary_accepted() {
        let data = make_map_header(11, 8, MAX_COLLECTION_SIZE);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_map_begin().is_ok());
    }

    #[test]
    fn test_map_max_boundary_plus_one_rejected() {
        let data = make_map_header(11, 8, MAX_COLLECTION_SIZE + 1);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_map_begin().is_err());
    }

    // Zero-size collections

    #[test]
    fn test_zero_size_list_accepted() {
        let data = make_list_header(8, 0);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let ident = bounded.read_list_begin().unwrap();
        assert_eq!(ident.size, 0);
    }

    #[test]
    fn test_zero_size_set_accepted() {
        let data = make_set_header(8, 0);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let ident = bounded.read_set_begin().unwrap();
        assert_eq!(ident.size, 0);
    }

    #[test]
    fn test_zero_size_map_accepted() {
        let data = make_map_header(11, 8, 0);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let ident = bounded.read_map_begin().unwrap();
        assert_eq!(ident.size, 0);
    }

    // Cumulative element budget

    #[test]
    fn test_cumulative_budget_rejects_repeated_max_lists() {
        // Each header is within the per-container cap, but the running
        // total crosses MAX_TOTAL_ELEMENTS on the 11th container.
        let mut data = Vec::new();
        for _ in 0..11 {
            data.extend_from_slice(&make_list_header(8, MAX_COLLECTION_SIZE));
        }
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);

        for _ in 0..10 {
            assert!(bounded.read_list_begin().is_ok());
        }
        let err = bounded.read_list_begin().unwrap_err();
        match err {
            thrift::Error::Protocol(pe) => {
                assert_eq!(pe.kind, thrift::ProtocolErrorKind::SizeLimit);
                assert!(pe.message.contains("cumulative"), "msg: {}", pe.message);
            }
            other => panic!("expected Protocol error, got: {:?}", other),
        }
    }

    #[test]
    fn test_cumulative_budget_spans_container_kinds() {
        // Lists, sets, and maps all draw from the same budget.
        let mut data = Vec::new();
        for _ in 0..5 {
            data.extend_from_slice(&make_list_header(8, MAX_COLLECTION_SIZE));
        }
        for _ in 0..5 {
            data.extend_from_slice(&make_set_header(8, MAX_COLLECTION_SIZE));
        }
        data.extend_from_slice(&make_map_header(11, 8, 1));

        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);

        for _ in 0..5 {
            assert!(bounded.read_list_begin().is_ok());
        }
        for _ in 0..5 {
            assert!(bounded.read_set_begin().is_ok());
        }
        assert!(bounded.read_map_begin().is_err());
    }

    #[test]
    fn test_cumulative_budget_allows_many_small_containers() {
        let mut data = Vec::new();
        for _ in 0..100 {
            data.extend_from_slice(&make_list_header(8, 10));
        }
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        for _ in 0..100 {
            assert!(bounded.read_list_begin().is_ok());
        }
    }

    #[test]
    fn test_fresh_protocol_resets_budget() {
        // The budget is per BoundedProtocol instance (one parse pass), so a
        // new wrapper starts from zero.
        let mut data = Vec::new();
        for _ in 0..10 {
            data.extend_from_slice(&make_list_header(8, MAX_COLLECTION_SIZE));
        }
        let cursor = Cursor::new(data.clone());
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        {
            let mut bounded = BoundedProtocol::new(&mut inner);
            for _ in 0..10 {
                assert!(bounded.read_list_begin().is_ok());
            }
        }
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_list_begin().is_ok());
    }

    // Error message verification

    #[test]
    fn test_oversized_list_error_details() {
        let data = make_list_header(8, 20_000);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let err = bounded.read_list_begin().unwrap_err();
        match err {
            thrift::Error::Protocol(pe) => {
                assert!(pe.message.contains("20000"), "msg: {}", pe.message);
                assert!(pe.message.contains("list"), "msg: {}", pe.message);
                assert_eq!(pe.kind, thrift::ProtocolErrorKind::SizeLimit);
            }
            other => panic!("expected Protocol error, got: {:?}", other),
        }
    }

    #[test]
    fn test_oversized_set_error_details() {
        let data = make_set_header(8, 50_000);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let err = bounded.read_set_begin().unwrap_err();
        match err {
            thrift::Error::Protocol(pe) => {
                assert!(pe.message.contains("set"), "msg: {}", pe.message);
            }
            other => panic!("expected Protocol error, got: {:?}", other),
        }
    }

    #[test]
    fn test_oversized_map_error_details() {
        let data = make_map_header(11, 8, 99_999);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let err = bounded.read_map_begin().unwrap_err();
        match err {
            thrift::Error::Protocol(pe) => {
                assert!(pe.message.contains("map"), "msg: {}", pe.message);
            }
            other => panic!("expected Protocol error, got: {:?}", other),
        }
    }

    // Scalar type delegation (passthrough)

    #[test]
    fn test_read_bool_true() {
        let data = vec![0x01];
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_bool().unwrap());
    }

    #[test]
    fn test_read_bool_false() {
        let data = vec![0x00];
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(!bounded.read_bool().unwrap());
    }

    #[test]
    fn test_read_byte() {
        let data = vec![0xAB];
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert_eq!(bounded.read_byte().unwrap(), 0xAB);
    }

    #[test]
    fn test_read_i8() {
        let data = vec![0xFE]; // -2 as i8
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert_eq!(bounded.read_i8().unwrap(), -2);
    }

    #[test]
    fn test_read_i16() {
        let data = 1234i16.to_be_bytes().to_vec();
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert_eq!(bounded.read_i16().unwrap(), 1234);
    }

    #[test]
    fn test_read_i32() {
        let data = 42i32.to_be_bytes().to_vec();
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert_eq!(bounded.read_i32().unwrap(), 42);
    }

    #[test]
    fn test_read_i64() {
        let data = 123_456_789i64.to_be_bytes().to_vec();
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert_eq!(bounded.read_i64().unwrap(), 123_456_789);
    }

    #[test]
    fn test_read_double() {
        let test_val = 1.2345_f64;
        let data = test_val.to_be_bytes().to_vec();
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let val = bounded.read_double().unwrap();
        assert!((val - test_val).abs() < f64::EPSILON);
    }

    #[test]
    fn test_read_string() {
        let s = "hello";
        let mut data = (s.len() as i32).to_be_bytes().to_vec();
        data.extend_from_slice(s.as_bytes());
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert_eq!(bounded.read_string().unwrap(), "hello");
    }

    #[test]
    fn test_read_bytes() {
        let payload = vec![0x01, 0x02, 0x03];
        let mut data = (payload.len() as i32).to_be_bytes().to_vec();
        data.extend_from_slice(&payload);
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert_eq!(bounded.read_bytes().unwrap(), vec![0x01, 0x02, 0x03]);
    }

    // Struct / field / message delegation

    #[test]
    fn test_read_struct_begin_end() {
        // Binary protocol struct begin/end read nothing from the wire
        let data = vec![];
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_struct_begin().is_ok());
        assert!(bounded.read_struct_end().is_ok());
    }

    #[test]
    fn test_read_field_begin_stop() {
        // STOP field: single byte 0x00
        let data = vec![0x00];
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let field = bounded.read_field_begin().unwrap();
        assert_eq!(field.field_type, thrift::protocol::TType::Stop);
    }

    #[test]
    fn test_read_field_end() {
        let data = vec![];
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_field_end().is_ok());
    }

    #[test]
    fn test_read_message_begin() {
        let mut data = vec![];
        // Strict-mode version word: 0x80010001 (version 1, type Call=1)
        data.extend_from_slice(&[0x80, 0x01, 0x00, 0x01u8]);
        // Name "test" (length-prefixed string)
        data.extend_from_slice(&4i32.to_be_bytes());
        data.extend_from_slice(b"test");
        // Sequence ID = 42
        data.extend_from_slice(&42i32.to_be_bytes());

        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        let msg = bounded.read_message_begin().unwrap();
        assert_eq!(msg.name, "test");
        assert_eq!(msg.sequence_number, 42);
    }

    #[test]
    fn test_read_message_end() {
        let data = vec![];
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_message_end().is_ok());
    }

    // Collection end delegation

    #[test]
    fn test_read_list_end() {
        let data = vec![];
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_list_end().is_ok());
    }

    #[test]
    fn test_read_set_end() {
        let data = vec![];
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_set_end().is_ok());
    }

    #[test]
    fn test_read_map_end() {
        let data = vec![];
        let cursor = Cursor::new(data);
        let mut inner = TBinaryInputProtocol::new(cursor, true);
        let mut bounded = BoundedProtocol::new(&mut inner);
        assert!(bounded.read_map_end().is_ok());
    }
}
