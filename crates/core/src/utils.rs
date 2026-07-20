//! # Utility Functions
//!
//! Common utilities for encoding, MIME detection, and image parsing.
//! These are exposed to reduce boilerplate in SDK consumers.

use base64::{engine::general_purpose::STANDARD, Engine as _};

// Base64 Encoding/Decoding

/// Encode bytes to base64 string.
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode base64 string to bytes.
///
/// Returns `None` if the input is not valid base64.
pub fn base64_to_bytes(b64: &str) -> Option<Vec<u8>> {
    STANDARD.decode(b64).ok()
}

// Hex Encoding/Decoding

/// Encode bytes to lowercase hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex string to bytes.
///
/// Returns `None` if the input is not valid hex.
pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

// MIME Type Detection

/// Detect MIME type from file bytes using magic numbers.
///
/// Returns the MIME type string (e.g., "image/png", "video/mp4") or `None`
/// if the type cannot be determined.
pub fn detect_mime_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 12 {
        return None;
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }

    // JPEG: FF D8 FF
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }

    // GIF: GIF87a or GIF89a
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif");
    }

    // WebP: RIFF....WEBP
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }

    // BMP: BM
    if bytes.starts_with(b"BM") {
        return Some("image/bmp");
    }

    // TIFF: II (little-endian) or MM (big-endian)
    if bytes.starts_with(&[0x49, 0x49, 0x2A, 0x00]) || bytes.starts_with(&[0x4D, 0x4D, 0x00, 0x2A])
    {
        return Some("image/tiff");
    }

    // ICO: 00 00 01 00
    if bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        return Some("image/x-icon");
    }

    // HEIC/HEIF: ftyp followed by heic, heix, mif1, etc.
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        let brand = &bytes[8..12];
        if brand == b"heic" || brand == b"heix" || brand == b"mif1" || brand == b"hevc" {
            return Some("image/heic");
        }
        // AVIF: ftyp avif
        if brand == b"avif" {
            return Some("image/avif");
        }
        // MP4/M4V: ftyp isom, mp41, mp42, M4V, etc.
        if brand == b"isom"
            || brand == b"mp41"
            || brand == b"mp42"
            || brand == b"M4V "
            || brand == b"avc1"
            || brand == b"qt  "
        {
            return Some("video/mp4");
        }
    }

    // WebM/MKV: 1A 45 DF A3
    if bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        // Could be WebM or MKV, assume WebM for common case
        return Some("video/webm");
    }

    // AVI: RIFF....AVI
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"AVI " {
        return Some("video/x-msvideo");
    }

    // MOV: moov or mdat early in file, or ftyp qt
    if bytes.len() >= 8 && &bytes[4..8] == b"moov" {
        return Some("video/quicktime");
    }

    // PDF: %PDF
    if bytes.starts_with(b"%PDF") {
        return Some("application/pdf");
    }

    // ZIP: PK
    if bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return Some("application/zip");
    }

    // MP3: ID3 or FF FB/FA/F3/F2
    if bytes.starts_with(b"ID3") || (bytes[0] == 0xFF && (bytes[1] & 0xE0) == 0xE0) {
        return Some("audio/mpeg");
    }

    // WAV: RIFF....WAVE
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WAVE" {
        return Some("audio/wav");
    }

    // OGG: OggS
    if bytes.starts_with(b"OggS") {
        return Some("audio/ogg");
    }

    // FLAC: fLaC
    if bytes.starts_with(b"fLaC") {
        return Some("audio/flac");
    }

    None
}

// Image Dimensions

/// Image dimensions (width, height).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageDimensions {
    pub width: u32,
    pub height: u32,
}

/// Detect image dimensions from file bytes.
///
/// Supports PNG, JPEG, GIF, WebP, and BMP.
/// Returns `None` if dimensions cannot be determined.
pub fn detect_image_dimensions(bytes: &[u8]) -> Option<ImageDimensions> {
    // PNG: width at offset 16-19, height at offset 20-23 (big-endian)
    if bytes.len() >= 24 && bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        return Some(ImageDimensions { width, height });
    }

    // GIF: width at offset 6-7, height at offset 8-9 (little-endian)
    if bytes.len() >= 10 && (bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        let width = u16::from_le_bytes([bytes[6], bytes[7]]) as u32;
        let height = u16::from_le_bytes([bytes[8], bytes[9]]) as u32;
        return Some(ImageDimensions { width, height });
    }

    // BMP: width at offset 18-21, height at offset 22-25 (little-endian, signed for height)
    if bytes.len() >= 26 && bytes.starts_with(b"BM") {
        let width = u32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]);
        let height_signed = i32::from_le_bytes([bytes[22], bytes[23], bytes[24], bytes[25]]);
        let height = height_signed.unsigned_abs();
        return Some(ImageDimensions { width, height });
    }

    // WebP
    if bytes.len() >= 30 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        // VP8 lossy: signature at offset 12-15 is "VP8 "
        if bytes.len() >= 30 && &bytes[12..16] == b"VP8 " {
            // Frame tag at offset 23-25, then width/height
            if bytes.len() >= 30 {
                let width = (u16::from_le_bytes([bytes[26], bytes[27]]) & 0x3FFF) as u32;
                let height = (u16::from_le_bytes([bytes[28], bytes[29]]) & 0x3FFF) as u32;
                return Some(ImageDimensions { width, height });
            }
        }
        // VP8L lossless: signature at offset 12-15 is "VP8L"
        if bytes.len() >= 25 && &bytes[12..16] == b"VP8L" {
            // Dimensions encoded in bits 0-13 (width-1) and 14-27 (height-1) at offset 21
            let b = u32::from_le_bytes([bytes[21], bytes[22], bytes[23], bytes[24]]);
            let width = (b & 0x3FFF) + 1;
            let height = ((b >> 14) & 0x3FFF) + 1;
            return Some(ImageDimensions { width, height });
        }
        // VP8X extended: width at offset 24-26, height at offset 27-29 (24-bit LE, minus 1)
        if bytes.len() >= 30 && &bytes[12..16] == b"VP8X" {
            let width = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], 0]) + 1;
            let height = u32::from_le_bytes([bytes[27], bytes[28], bytes[29], 0]) + 1;
            return Some(ImageDimensions { width, height });
        }
    }

    // JPEG: Need to parse segments to find SOF marker
    if bytes.len() >= 4 && bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return parse_jpeg_dimensions(bytes);
    }

    None
}

/// Parse JPEG dimensions by finding SOF marker.
fn parse_jpeg_dimensions(bytes: &[u8]) -> Option<ImageDimensions> {
    let mut i = 2; // Skip FF D8

    while i + 4 < bytes.len() {
        // Each segment starts with FF xx
        if bytes[i] != 0xFF {
            i += 1;
            continue;
        }

        let marker = bytes[i + 1];

        // Skip padding FF bytes
        if marker == 0xFF {
            i += 1;
            continue;
        }

        // SOF markers: C0-C3, C5-C7, C9-CB, CD-CF (except C4, C8, CC)
        let is_sof = matches!(
            marker,
            0xC0 | 0xC1
                | 0xC2
                | 0xC3
                | 0xC5
                | 0xC6
                | 0xC7
                | 0xC9
                | 0xCA
                | 0xCB
                | 0xCD
                | 0xCE
                | 0xCF
        );

        if is_sof && i + 9 < bytes.len() {
            // SOF segment: length (2), precision (1), height (2), width (2)
            let height = u16::from_be_bytes([bytes[i + 5], bytes[i + 6]]) as u32;
            let width = u16::from_be_bytes([bytes[i + 7], bytes[i + 8]]) as u32;
            return Some(ImageDimensions { width, height });
        }

        // Markers without length: D0-D9 (RST, SOI, EOI)
        if (0xD0..=0xD9).contains(&marker) {
            i += 2;
            continue;
        }

        // Read segment length and skip
        if i + 4 <= bytes.len() {
            let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
            i += 2 + len;
        } else {
            break;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = bytes_to_base64(data);
        let decoded = base64_to_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = bytes_to_hex(&data);
        assert_eq!(encoded, "deadbeef");
        let decoded = hex_to_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_invalid() {
        assert!(hex_to_bytes("xyz").is_none());
        assert!(hex_to_bytes("abc").is_none()); // odd length
    }

    #[test]
    fn test_detect_mime_png() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0];
        assert_eq!(detect_mime_type(&png), Some("image/png"));
    }

    #[test]
    fn test_detect_mime_jpeg() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(detect_mime_type(&jpeg), Some("image/jpeg"));
    }

    #[test]
    fn test_detect_mime_gif() {
        let gif = b"GIF89a      ";
        assert_eq!(detect_mime_type(gif), Some("image/gif"));
    }

    #[test]
    fn test_detect_mime_webp() {
        let mut webp = vec![0u8; 16];
        webp[..4].copy_from_slice(b"RIFF");
        webp[8..12].copy_from_slice(b"WEBP");
        assert_eq!(detect_mime_type(&webp), Some("image/webp"));
    }

    #[test]
    fn test_png_dimensions() {
        // Minimal valid PNG header with 100x200 dimensions
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(&[0, 0, 0, 13]); // IHDR length
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&100u32.to_be_bytes()); // width
        png.extend_from_slice(&200u32.to_be_bytes()); // height

        let dims = detect_image_dimensions(&png);
        assert_eq!(
            dims,
            Some(ImageDimensions {
                width: 100,
                height: 200
            })
        );
    }

    #[test]
    fn test_gif_dimensions() {
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&320u16.to_le_bytes()); // width
        gif.extend_from_slice(&240u16.to_le_bytes()); // height

        let dims = detect_image_dimensions(&gif);
        assert_eq!(
            dims,
            Some(ImageDimensions {
                width: 320,
                height: 240
            })
        );
    }

    // Base64 / Hex edge cases

    #[test]
    fn test_base64_invalid_input() {
        assert!(base64_to_bytes("not valid base64!!!").is_none());
    }

    #[test]
    fn test_base64_empty() {
        assert_eq!(bytes_to_base64(b""), "");
        assert_eq!(base64_to_bytes(""), Some(vec![]));
    }

    #[test]
    fn test_hex_empty() {
        assert_eq!(bytes_to_hex(&[]), "");
        assert_eq!(hex_to_bytes(""), Some(vec![]));
    }

    #[test]
    fn test_hex_uppercase() {
        assert_eq!(hex_to_bytes("DEADBEEF"), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn test_hex_single_byte() {
        assert_eq!(hex_to_bytes("ff"), Some(vec![0xFF]));
    }

    // MIME type detection — edge cases

    #[test]
    fn test_detect_mime_empty() {
        assert_eq!(detect_mime_type(&[]), None);
    }

    #[test]
    fn test_detect_mime_too_short() {
        // 11 bytes — under the 12-byte minimum
        assert_eq!(
            detect_mime_type(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0, 0, 0, 0]),
            None
        );
    }

    #[test]
    fn test_detect_mime_unknown_format() {
        assert_eq!(detect_mime_type(&[0x01; 16]), None);
    }

    // MIME type detection — every format

    #[test]
    fn test_detect_mime_bmp() {
        let mut bmp = vec![0u8; 14];
        bmp[0..2].copy_from_slice(b"BM");
        assert_eq!(detect_mime_type(&bmp), Some("image/bmp"));
    }

    #[test]
    fn test_detect_mime_tiff_little_endian() {
        let mut tiff = vec![0u8; 12];
        tiff[0..4].copy_from_slice(&[0x49, 0x49, 0x2A, 0x00]);
        assert_eq!(detect_mime_type(&tiff), Some("image/tiff"));
    }

    #[test]
    fn test_detect_mime_tiff_big_endian() {
        let mut tiff = vec![0u8; 12];
        tiff[0..4].copy_from_slice(&[0x4D, 0x4D, 0x00, 0x2A]);
        assert_eq!(detect_mime_type(&tiff), Some("image/tiff"));
    }

    #[test]
    fn test_detect_mime_ico() {
        let mut ico = vec![0u8; 12];
        ico[0..4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);
        assert_eq!(detect_mime_type(&ico), Some("image/x-icon"));
    }

    #[test]
    fn test_detect_mime_heic() {
        let mut heic = vec![0u8; 12];
        heic[4..8].copy_from_slice(b"ftyp");
        heic[8..12].copy_from_slice(b"heic");
        assert_eq!(detect_mime_type(&heic), Some("image/heic"));
    }

    #[test]
    fn test_detect_mime_heic_variants() {
        for brand in &[b"heix", b"mif1", b"hevc"] {
            let mut buf = vec![0u8; 12];
            buf[4..8].copy_from_slice(b"ftyp");
            buf[8..12].copy_from_slice(*brand);
            assert_eq!(
                detect_mime_type(&buf),
                Some("image/heic"),
                "failed for brand {:?}",
                std::str::from_utf8(*brand).unwrap()
            );
        }
    }

    #[test]
    fn test_detect_mime_avif() {
        let mut avif = vec![0u8; 12];
        avif[4..8].copy_from_slice(b"ftyp");
        avif[8..12].copy_from_slice(b"avif");
        assert_eq!(detect_mime_type(&avif), Some("image/avif"));
    }

    #[test]
    fn test_detect_mime_mp4_variants() {
        for brand in &[b"isom", b"mp41", b"mp42", b"M4V ", b"avc1"] {
            let mut buf = vec![0u8; 12];
            buf[4..8].copy_from_slice(b"ftyp");
            buf[8..12].copy_from_slice(*brand);
            assert_eq!(
                detect_mime_type(&buf),
                Some("video/mp4"),
                "failed for brand {:?}",
                std::str::from_utf8(*brand).unwrap()
            );
        }
    }

    #[test]
    fn test_detect_mime_mp4_qt() {
        let mut buf = vec![0u8; 12];
        buf[4..8].copy_from_slice(b"ftyp");
        buf[8..12].copy_from_slice(b"qt  ");
        assert_eq!(detect_mime_type(&buf), Some("video/mp4"));
    }

    #[test]
    fn test_detect_mime_ftyp_unknown_brand() {
        let mut buf = vec![0u8; 12];
        buf[4..8].copy_from_slice(b"ftyp");
        buf[8..12].copy_from_slice(b"xxxx");
        // Unknown ftyp brand falls through all checks
        assert_eq!(detect_mime_type(&buf), None);
    }

    #[test]
    fn test_detect_mime_webm() {
        let mut webm = vec![0u8; 12];
        webm[0..4].copy_from_slice(&[0x1A, 0x45, 0xDF, 0xA3]);
        assert_eq!(detect_mime_type(&webm), Some("video/webm"));
    }

    #[test]
    fn test_detect_mime_avi() {
        let mut avi = vec![0u8; 12];
        avi[0..4].copy_from_slice(b"RIFF");
        avi[8..12].copy_from_slice(b"AVI ");
        assert_eq!(detect_mime_type(&avi), Some("video/x-msvideo"));
    }

    #[test]
    fn test_detect_mime_mov() {
        let mut mov = vec![0u8; 12];
        mov[4..8].copy_from_slice(b"moov");
        assert_eq!(detect_mime_type(&mov), Some("video/quicktime"));
    }

    #[test]
    fn test_detect_mime_pdf() {
        let pdf = b"%PDF-1.4xxxx";
        assert_eq!(detect_mime_type(pdf), Some("application/pdf"));
    }

    #[test]
    fn test_detect_mime_zip() {
        let mut zip = vec![0u8; 12];
        zip[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        assert_eq!(detect_mime_type(&zip), Some("application/zip"));
    }

    #[test]
    fn test_detect_mime_mp3_id3() {
        let mp3 = b"ID3v2.3.0xxx";
        assert_eq!(detect_mime_type(mp3), Some("audio/mpeg"));
    }

    #[test]
    fn test_detect_mime_mp3_sync() {
        let mp3 = vec![0xFF, 0xFB, 0x90, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(detect_mime_type(&mp3), Some("audio/mpeg"));
    }

    #[test]
    fn test_detect_mime_wav() {
        let mut wav = vec![0u8; 12];
        wav[0..4].copy_from_slice(b"RIFF");
        wav[8..12].copy_from_slice(b"WAVE");
        assert_eq!(detect_mime_type(&wav), Some("audio/wav"));
    }

    #[test]
    fn test_detect_mime_ogg() {
        let ogg = b"OggS00000000";
        assert_eq!(detect_mime_type(ogg), Some("audio/ogg"));
    }

    #[test]
    fn test_detect_mime_flac() {
        let flac = b"fLaC00000000";
        assert_eq!(detect_mime_type(flac), Some("audio/flac"));
    }

    #[test]
    fn test_detect_mime_gif87a() {
        let gif = b"GIF87a      ";
        assert_eq!(detect_mime_type(gif), Some("image/gif"));
    }

    // Image dimensions — JPEG

    #[test]
    fn test_jpeg_dimensions_sof0() {
        // Minimal JPEG: SOI + SOF0 with 256x200
        #[rustfmt::skip]
        let jpeg = vec![
            0xFF, 0xD8,             // SOI
            0xFF, 0xC0,             // SOF0
            0x00, 0x11,             // segment length
            0x08,                   // precision
            0x00, 0xC8,             // height = 200
            0x01, 0x00,             // width  = 256
            0x03,                   // pad to satisfy i+9 < len
        ];
        assert_eq!(
            detect_image_dimensions(&jpeg),
            Some(ImageDimensions {
                width: 256,
                height: 200
            })
        );
    }

    #[test]
    fn test_jpeg_dimensions_with_app0_before_sof() {
        // APP0 segment (length=4) precedes the SOF0
        #[rustfmt::skip]
        let jpeg = vec![
            0xFF, 0xD8,             // SOI
            0xFF, 0xE0,             // APP0
            0x00, 0x04,             // segment length (4)
            0x00, 0x00,             // data bytes
            0xFF, 0xC0,             // SOF0
            0x00, 0x11,             // segment length
            0x08,                   // precision
            0x00, 0xC8,             // height = 200
            0x01, 0x90,             // width  = 400
            0x03,                   // pad
        ];
        assert_eq!(
            detect_image_dimensions(&jpeg),
            Some(ImageDimensions {
                width: 400,
                height: 200
            })
        );
    }

    #[test]
    fn test_jpeg_sof2_progressive() {
        #[rustfmt::skip]
        let jpeg = vec![
            0xFF, 0xD8,
            0xFF, 0xC2,             // SOF2 (progressive)
            0x00, 0x11, 0x08,
            0x03, 0x00,             // height = 768
            0x04, 0x00,             // width  = 1024
            0x03,
        ];
        assert_eq!(
            detect_image_dimensions(&jpeg),
            Some(ImageDimensions {
                width: 1024,
                height: 768
            })
        );
    }

    #[test]
    fn test_jpeg_with_rst_marker_before_sof() {
        // RST0 (D0) has no length — parser skips with i+=2
        #[rustfmt::skip]
        let jpeg = vec![
            0xFF, 0xD8,
            0xFF, 0xD0,             // RST0
            0xFF, 0xC0,             // SOF0
            0x00, 0x11, 0x08,
            0x00, 0xC8,             // height = 200
            0x01, 0x00,             // width  = 256
            0x03,
        ];
        assert_eq!(
            detect_image_dimensions(&jpeg),
            Some(ImageDimensions {
                width: 256,
                height: 200
            })
        );
    }

    #[test]
    fn test_jpeg_with_ff_padding() {
        // Consecutive FF bytes are treated as padding
        #[rustfmt::skip]
        let jpeg = vec![
            0xFF, 0xD8,
            0xFF, 0xFF,             // padding FF
            0xC0,                   // SOF0 (paired with prior 0xFF)
            0x00, 0x11, 0x08,
            0x01, 0x00,             // height = 256
            0x00, 0xC8,             // width  = 200
            0x03,
        ];
        assert_eq!(
            detect_image_dimensions(&jpeg),
            Some(ImageDimensions {
                width: 200,
                height: 256
            })
        );
    }

    #[test]
    fn test_jpeg_with_non_marker_byte() {
        // APP0 segment followed by a stray non-0xFF byte before SOF0.
        // The parser skips stray bytes via the `bytes[i] != 0xFF` branch.
        #[rustfmt::skip]
        let jpeg = vec![
            0xFF, 0xD8,             // SOI
            0xFF, 0xE0,             // APP0
            0x00, 0x04,             // segment length (4)
            0x00, 0x00,             // data
            0x00,                   // stray non-marker byte at pos 8
            0xFF, 0xC0,             // SOF0 at pos 9
            0x00, 0x11, 0x08,
            0x00, 0xC8,             // height = 200
            0x01, 0x00,             // width  = 256
            0x03,
        ];
        assert_eq!(
            detect_image_dimensions(&jpeg),
            Some(ImageDimensions {
                width: 256,
                height: 200
            })
        );
    }

    #[test]
    fn test_jpeg_dimensions_truncated_no_sof() {
        // Only APP0 segment, no SOF — returns None
        let jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00];
        assert_eq!(detect_image_dimensions(&jpeg), None);
    }

    #[test]
    fn test_jpeg_sof_found_but_truncated() {
        // SOF0 marker exists but not enough bytes for dimensions
        let jpeg = vec![0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0x08];
        assert_eq!(detect_image_dimensions(&jpeg), None);
    }

    // Image dimensions — WebP variants

    #[test]
    fn test_webp_vp8_lossy_dimensions() {
        let mut webp = vec![0u8; 30];
        webp[0..4].copy_from_slice(b"RIFF");
        webp[8..12].copy_from_slice(b"WEBP");
        webp[12..16].copy_from_slice(b"VP8 ");
        // Width 640, Height 480 (LE, masked with 0x3FFF)
        webp[26..28].copy_from_slice(&640u16.to_le_bytes());
        webp[28..30].copy_from_slice(&480u16.to_le_bytes());
        assert_eq!(
            detect_image_dimensions(&webp),
            Some(ImageDimensions {
                width: 640,
                height: 480
            })
        );
    }

    #[test]
    fn test_webp_vp8l_lossless_dimensions() {
        let mut webp = vec![0u8; 30];
        webp[0..4].copy_from_slice(b"RIFF");
        webp[8..12].copy_from_slice(b"WEBP");
        webp[12..16].copy_from_slice(b"VP8L");
        webp[20] = 0x2F; // VP8L signature byte
                         // Packed bits: (width-1) in bits 0-13, (height-1) in bits 14-27
                         // 800x600 -> width-1=799, height-1=599
        let packed: u32 = 799 | (599 << 14);
        webp[21..25].copy_from_slice(&packed.to_le_bytes());
        assert_eq!(
            detect_image_dimensions(&webp),
            Some(ImageDimensions {
                width: 800,
                height: 600
            })
        );
    }

    #[test]
    fn test_webp_vp8x_extended_dimensions() {
        let mut webp = vec![0u8; 30];
        webp[0..4].copy_from_slice(b"RIFF");
        webp[8..12].copy_from_slice(b"WEBP");
        webp[12..16].copy_from_slice(b"VP8X");
        // Width-1 at offset 24-26 (3 bytes LE)
        let w_bytes = 1919u32.to_le_bytes(); // 1920-1
        webp[24] = w_bytes[0];
        webp[25] = w_bytes[1];
        webp[26] = w_bytes[2];
        // Height-1 at offset 27-29 (3 bytes LE)
        let h_bytes = 1079u32.to_le_bytes(); // 1080-1
        webp[27] = h_bytes[0];
        webp[28] = h_bytes[1];
        webp[29] = h_bytes[2];
        assert_eq!(
            detect_image_dimensions(&webp),
            Some(ImageDimensions {
                width: 1920,
                height: 1080
            })
        );
    }

    // Image dimensions — BMP

    #[test]
    fn test_bmp_dimensions_positive_height() {
        let mut bmp = vec![0u8; 26];
        bmp[0..2].copy_from_slice(b"BM");
        bmp[18..22].copy_from_slice(&640u32.to_le_bytes());
        bmp[22..26].copy_from_slice(&480i32.to_le_bytes());
        assert_eq!(
            detect_image_dimensions(&bmp),
            Some(ImageDimensions {
                width: 640,
                height: 480
            })
        );
    }

    #[test]
    fn test_bmp_dimensions_negative_height() {
        // Top-down BMP uses negative height; unsigned_abs gives the real value
        let mut bmp = vec![0u8; 26];
        bmp[0..2].copy_from_slice(b"BM");
        bmp[18..22].copy_from_slice(&640u32.to_le_bytes());
        bmp[22..26].copy_from_slice(&(-480i32).to_le_bytes());
        assert_eq!(
            detect_image_dimensions(&bmp),
            Some(ImageDimensions {
                width: 640,
                height: 480
            })
        );
    }

    // Image dimensions — GIF87a variant

    #[test]
    fn test_gif87a_dimensions() {
        let mut gif = b"GIF87a".to_vec();
        gif.extend_from_slice(&160u16.to_le_bytes());
        gif.extend_from_slice(&120u16.to_le_bytes());
        assert_eq!(
            detect_image_dimensions(&gif),
            Some(ImageDimensions {
                width: 160,
                height: 120
            })
        );
    }

    // Image dimensions — edge cases

    #[test]
    fn test_png_dimensions_truncated() {
        // Valid PNG magic but only 16 bytes (need 24 for dimensions)
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(&[0; 8]);
        assert_eq!(detect_image_dimensions(&png), None);
    }

    #[test]
    fn test_unknown_format_dimensions() {
        assert_eq!(detect_image_dimensions(&[0x01; 30]), None);
    }

    #[test]
    fn test_empty_bytes_dimensions() {
        assert_eq!(detect_image_dimensions(&[]), None);
    }

    #[test]
    fn test_too_short_for_any_format() {
        assert_eq!(detect_image_dimensions(&[0x89]), None);
        assert_eq!(detect_image_dimensions(&[0xFF, 0xD8]), None);
    }
}
