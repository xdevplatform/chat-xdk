//! Serialization utilities for the X Chat SDK.
//!
//! Handles encoding/decoding of protocol messages.

use crate::error::SerializationError;
use base64::{
    alphabet,
    engine::{general_purpose::STANDARD, DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine,
};

/// A base64 engine that accepts both padded and unpadded input.
///
/// Some producers encode signatures and keys without trailing `=` padding,
/// while other fields may include it. `DecodePaddingMode::Indifferent`
/// accepts both transparently.
const STANDARD_INDIFFERENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Encode bytes to base64 string.
pub fn base64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode base64 string to bytes.
///
/// Accepts both padded and unpadded standard base64.
pub fn base64_decode(data: &str) -> Result<Vec<u8>, SerializationError> {
    STANDARD_INDIFFERENT
        .decode(data)
        .map_err(|e| SerializationError::Base64(e.to_string()))
}

/// Serialize a value to JSON.
pub fn to_json<T: serde::Serialize>(value: &T) -> Result<String, SerializationError> {
    serde_json::to_string(value).map_err(|e| SerializationError::Json(e.to_string()))
}

/// Serialize a value to pretty JSON.
pub fn to_json_pretty<T: serde::Serialize>(value: &T) -> Result<String, SerializationError> {
    serde_json::to_string_pretty(value).map_err(|e| SerializationError::Json(e.to_string()))
}

/// Deserialize a value from JSON.
pub fn from_json<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, SerializationError> {
    serde_json::from_str(json).map_err(|e| SerializationError::Json(e.to_string()))
}

/// Deserialize a value from JSON bytes.
pub fn from_json_bytes<T: serde::de::DeserializeOwned>(
    json: &[u8],
) -> Result<T, SerializationError> {
    serde_json::from_slice(json).map_err(|e| SerializationError::Json(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_empty() {
        let data = b"";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "");
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_invalid() {
        let result = base64_decode("not valid base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_json_roundtrip() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct TestStruct {
            name: String,
            value: i32,
        }

        let original = TestStruct {
            name: "test".to_string(),
            value: 42,
        };

        let json = to_json(&original).unwrap();
        let decoded: TestStruct = from_json(&json).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_json_pretty() {
        let value = serde_json::json!({"key": "value"});
        let pretty = to_json_pretty(&value).unwrap();
        assert!(pretty.contains('\n'));
        assert!(pretty.contains("key"));
    }

    #[test]
    fn test_from_json_invalid() {
        let result = from_json::<serde_json::Value>("not json {{{}}}");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_json_bytes() {
        let bytes = br#"{"key": "value"}"#;
        let result: serde_json::Value = from_json_bytes(bytes).unwrap();
        assert_eq!(result["key"], "value");
    }

    #[test]
    fn test_from_json_bytes_invalid() {
        let result = from_json_bytes::<serde_json::Value>(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_binary_data() {
        let data = vec![0u8, 1, 2, 255, 254, 253];
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    // base64_decode — padded vs. unpadded (STANDARD_INDIFFERENT engine)

    #[test]
    fn test_base64_decode_unpadded() {
        // "Hello" = "SGVsbG8=" with padding, "SGVsbG8" without
        let decoded = base64_decode("SGVsbG8").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_base64_decode_padded() {
        let decoded = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_base64_decode_unpadded_two_pad_chars() {
        // "Hi" = "SGk=" padded, "SGk" unpadded (two missing '=')
        let decoded = base64_decode("SGk").unwrap();
        assert_eq!(decoded, b"Hi");
    }

    // base64_decode — error branch specifics

    #[test]
    fn test_base64_decode_invalid_chars() {
        assert!(base64_decode("!!!@@@###").is_err());
    }

    #[test]
    fn test_base64_decode_error_is_base64_variant() {
        let err = base64_decode("!!!").unwrap_err();
        assert!(matches!(err, SerializationError::Base64(_)));
    }

    #[test]
    fn test_base64_decode_error_display() {
        let err = base64_decode("!!!").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Base64"), "error message: {msg}");
    }

    // from_json / from_json_bytes — extra coverage

    #[test]
    fn test_from_json_bytes_nested() {
        let bytes = br#"{"outer": {"inner": 42}}"#;
        let result: serde_json::Value = from_json_bytes(bytes).unwrap();
        assert_eq!(result["outer"]["inner"], 42);
    }

    #[test]
    fn test_from_json_bytes_array() {
        let bytes = b"[1, 2, 3]";
        let result: serde_json::Value = from_json_bytes(bytes).unwrap();
        assert_eq!(result.as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_from_json_bytes_empty_object() {
        let bytes = b"{}";
        let result: serde_json::Value = from_json_bytes(bytes).unwrap();
        assert!(result.is_object());
        assert_eq!(result.as_object().unwrap().len(), 0);
    }

    #[test]
    fn test_from_json_bytes_invalid_utf8() {
        let bytes: &[u8] = &[0xFF, 0xFE, 0xFD];
        let result = from_json_bytes::<serde_json::Value>(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_json_error_is_json_variant() {
        let err = from_json::<serde_json::Value>("{{invalid}}").unwrap_err();
        assert!(matches!(err, SerializationError::Json(_)));
    }

    #[test]
    fn test_from_json_bytes_error_is_json_variant() {
        let err = from_json_bytes::<serde_json::Value>(b"not json").unwrap_err();
        assert!(matches!(err, SerializationError::Json(_)));
    }

    // to_json / to_json_pretty — extra coverage

    #[test]
    fn test_to_json_escaping() {
        let value = serde_json::json!({"msg": "line1\nline2"});
        let json = to_json(&value).unwrap();
        assert!(json.contains("\\n"));
    }

    #[test]
    fn test_to_json_pretty_indentation() {
        let value = serde_json::json!({"a": 1, "b": 2});
        let pretty = to_json_pretty(&value).unwrap();
        // Pretty output has leading spaces for indentation
        assert!(pretty.contains("  "));
    }
}
