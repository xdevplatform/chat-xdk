package chatxdk

import (
	"encoding/base64"
	"encoding/json"
)

// ImageDimensions is returned by [DetectImageDimensions] when a supported image header is recognized.
type ImageDimensions struct {
	Width  uint32 `json:"width"`
	Height uint32 `json:"height"`
}

// BytesToBase64 encodes bytes to standard base64.
func BytesToBase64(data []byte) (string, error) {
	return ffiBytesToBase64(data)
}

// Base64ToBytes decodes a standard base64 string to bytes.
func Base64ToBytes(b64 string) ([]byte, error) {
	inner, err := ffiBase64ToBytes(b64)
	if err != nil {
		return nil, err
	}
	out, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BytesToHex encodes bytes to a lowercase hex string.
func BytesToHex(data []byte) (string, error) {
	return ffiBytesToHex(data)
}

// HexToBytes decodes a hex string (even length, lowercase or uppercase digits) to bytes.
func HexToBytes(hex string) ([]byte, error) {
	inner, err := ffiHexToBytes(hex)
	if err != nil {
		return nil, err
	}
	out, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DetectMimeType returns a MIME type guessed from magic bytes (e.g. "image/png"), or ("", nil) if unknown.
func DetectMimeType(data []byte) (string, error) {
	mime, err := ffiDetectMimeType(data)
	if err != nil {
		return "", err
	}
	if mime == "" {
		return "", nil
	}
	return mime, nil
}

// DetectImageDimensions returns width and height when the format is supported, or (nil, nil) if unknown.
func DetectImageDimensions(data []byte) (*ImageDimensions, error) {
	s, err := ffiDetectImageDimensions(data)
	if err != nil {
		return nil, err
	}
	if s == "null" {
		return nil, nil
	}
	var d ImageDimensions
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		return nil, err
	}
	return &d, nil
}
