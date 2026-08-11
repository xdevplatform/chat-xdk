package chatxdk

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type sdkVectors struct {
	IdentityPrivateB64            string `json:"identity_private_b64"`
	SigningPrivateB64             string `json:"signing_private_b64"`
	PrivateKeysConcatB64          string `json:"private_keys_concat_b64"`
	MessageUTF8                   string `json:"message_utf8"`
	ConversationKeyB64            string `json:"conversation_key_b64"`
	PlaintextB64                  string `json:"plaintext_b64"`
	IdentityPublicB64             string `json:"identity_public_b64"`
	SigningPublicB64              string `json:"signing_public_b64"`
	SignatureB64                  string `json:"signature_b64"`
	IdentityPublicKeySignatureB64 string `json:"identity_public_key_signature_b64"`
	EventFailureB64               string `json:"event_failure_b64"`
	EventKeyChangeB64             string `json:"event_key_change_b64"`
	EventMessageB64               string `json:"event_message_b64"`
	EventReplyValidB64            string `json:"event_reply_valid_b64"`
	EventReplyForgedB64           string `json:"event_reply_forged_b64"`
	EventGarbageB64               string `json:"event_garbage_b64"`
	EventSenderID                 string `json:"event_sender_id"`
	EventConversationID           string `json:"event_conversation_id"`
	EventConversationKeyVersion   string `json:"event_conversation_key_version"`
	EventSigningKeyVersion        string `json:"event_signing_key_version"`
	EventRecipientKeyVersion      string `json:"event_recipient_key_version"`
	EventMessageText              string `json:"event_message_text"`
	EventReplyText                string `json:"event_reply_text"`
}

// eventSigningKeys builds the SigningKeyEntry list matching the fixture's
// event vectors (sender id, key version, and identity binding).
func (v sdkVectors) eventSigningKeys() []SigningKeyEntry {
	return []SigningKeyEntry{{
		UserID:                     v.EventSenderID,
		PublicKeyVersion:           v.EventSigningKeyVersion,
		PublicKey:                  v.SigningPublicB64,
		IdentityPublicKey:          v.IdentityPublicB64,
		IdentityPublicKeySignature: v.IdentityPublicKeySignatureB64,
	}}
}

func loadVectors(t *testing.T) sdkVectors {
	t.Helper()
	// This file: go/chatxdk/chatxdk_test.go
	// Vectors:   tests/fixtures/sdk_vectors.json (2 directories up)
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	path := filepath.Join(root, "tests", "fixtures", "sdk_vectors.json")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to load sdk_vectors.json: %v", err)
	}
	var v sdkVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("failed to parse sdk_vectors.json: %v", err)
	}
	return v
}

// conversationKey decodes the fixture's base64 conversation key into the raw
// 32 bytes the SDK's key-typed APIs take.
func (v sdkVectors) conversationKey(t *testing.T) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(v.ConversationKeyB64)
	if err != nil {
		t.Fatalf("failed to decode conversation_key_b64: %v", err)
	}
	return key
}

// privateKeys decodes the fixture's base64 private-key blob into the raw
// bytes ImportKeys takes.
func (v sdkVectors) privateKeys(t *testing.T) []byte {
	t.Helper()
	keys, err := base64.StdEncoding.DecodeString(v.PrivateKeysConcatB64)
	if err != nil {
		t.Fatalf("failed to decode private_keys_concat_b64: %v", err)
	}
	return keys
}

func TestPublicKeysAndSignature(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	if chat == nil {
		t.Fatal("New() returned nil")
	}
	defer chat.Close()

	// Import keys
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}
	if !chat.IsUnlocked() {
		t.Fatal("expected IsUnlocked() == true after ImportKeys")
	}

	// Public keys must match fixture
	keys, err := chat.GetPublicKeys()
	if err != nil {
		t.Fatalf("GetPublicKeys failed: %v", err)
	}
	if keys.Identity != v.IdentityPublicB64 {
		t.Errorf("identity key mismatch:\ngot  %s\nwant %s", keys.Identity, v.IdentityPublicB64)
	}
	if keys.Signing != v.SigningPublicB64 {
		t.Errorf("signing key mismatch:\ngot  %s\nwant %s", keys.Signing, v.SigningPublicB64)
	}

	// Deterministic signature must match fixture (raw bytes out, fixture is base64)
	sig, err := chat.Sign([]byte(v.MessageUTF8))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if base64.StdEncoding.EncodeToString(sig) != v.SignatureB64 {
		t.Errorf("signature mismatch:\ngot  %s\nwant %s", base64.StdEncoding.EncodeToString(sig), v.SignatureB64)
	}

	// Verify: valid
	valid, err := chat.Verify(v.SigningPublicB64, sig, []byte(v.MessageUTF8))
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("expected valid signature, got invalid")
	}

	// Verify: tampered data
	valid, err = chat.Verify(v.SigningPublicB64, sig, []byte(v.MessageUTF8+"!"))
	if err != nil {
		t.Fatalf("Verify (tampered) failed: %v", err)
	}
	if valid {
		t.Error("expected invalid signature for tampered data, got valid")
	}
}

func TestECIESConversationKeyRoundtrip(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Prepare a key change for ourselves, then decrypt our own participant key.
	publicKeys := []PublicKeyInput{{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"}}
	prep, err := chat.PrepareConversationKeyChange(ConversationKeyChangeParams{
		SenderID:          "me",
		SigningKeyVersion: "1",
		PublicKeys:        publicKeys,
		ConversationID:    "conv-1",
	})
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange failed: %v", err)
	}
	if len(prep.ParticipantKeys) != 1 {
		t.Fatalf("expected 1 participant key, got %d", len(prep.ParticipantKeys))
	}

	decrypted, err := chat.DecryptConversationKey(prep.ParticipantKeys[0].EncryptedKey)
	if err != nil {
		t.Fatalf("DecryptConversationKey failed: %v", err)
	}
	if !bytes.Equal(decrypted, prep.ConversationKey) {
		t.Errorf("decrypted key mismatch:\ngot  %x\nwant %x", decrypted, prep.ConversationKey)
	}
}

func TestEncryptMessageSmokeAndInvalidImport(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()

	// Invalid import (1 byte, not 32 or 64)
	err := chat.ImportKeys([]byte{0x00})
	if err == nil {
		t.Error("expected error for invalid key import, got nil")
	}

	// Import valid keys
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Encrypt a message using the raw conversation key directly.
	// The fixture key is the pre-decrypted 32-byte key — pass it straight
	// to EncryptMessage without going through ECIES.
	payload, err := chat.EncryptMessage(EncryptMessageParams{
		SenderID:               "me",
		ConversationID:         "conv-1",
		ConversationKey:        v.conversationKey(t),
		Text:                   "hello from Go",
		ConversationKeyVersion: "1",
		SigningKeyVersion:      "1",
	})
	if err != nil {
		t.Fatalf("EncryptMessage failed: %v", err)
	}
	if payload.EncryptedContent == "" {
		t.Error("expected non-empty encrypted_content")
	}
	if payload.Signature == "" {
		t.Error("expected non-empty signature")
	}
	// The SDK generates and returns the message id.
	if payload.MessageID == "" {
		t.Error("expected non-empty message_id")
	}
}

func TestLockAndUnlockState(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()

	if chat.IsUnlocked() {
		t.Error("expected locked initially")
	}

	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}
	if !chat.IsUnlocked() {
		t.Error("expected unlocked after import")
	}

	chat.Lock()
	if chat.IsUnlocked() {
		t.Error("expected locked after Lock()")
	}
}

func TestUtilityHelpers(t *testing.T) {
	// Base64 / hex roundtrip (parity with core utils tests)
	b64, err := BytesToBase64([]byte("Hello, World!"))
	if err != nil {
		t.Fatalf("BytesToBase64: %v", err)
	}
	raw, err := Base64ToBytes(b64)
	if err != nil {
		t.Fatalf("Base64ToBytes: %v", err)
	}
	if string(raw) != "Hello, World!" {
		t.Fatalf("base64 roundtrip: got %q", raw)
	}

	hexStr, err := BytesToHex([]byte{0xde, 0xad, 0xbe, 0xef})
	if err != nil {
		t.Fatalf("BytesToHex: %v", err)
	}
	if hexStr != "deadbeef" {
		t.Fatalf("BytesToHex: got %q", hexStr)
	}
	back, err := HexToBytes(hexStr)
	if err != nil {
		t.Fatalf("HexToBytes: %v", err)
	}
	if !bytes.Equal(back, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("hex roundtrip: got %v", back)
	}
	if _, err := HexToBytes("xyz"); err == nil {
		t.Fatal("expected error for invalid hex")
	}

	// MIME: PNG magic (needs >= 12 bytes for this detector)
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0}
	mime, err := DetectMimeType(pngMagic)
	if err != nil {
		t.Fatalf("DetectMimeType: %v", err)
	}
	if mime != "image/png" {
		t.Fatalf("DetectMimeType: got %q want image/png", mime)
	}

	// Dimensions: minimal IHDR-style header (same construction as core tests)
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	png = append(png, 0, 0, 0, 13)
	png = append(png, []byte("IHDR")...)
	var wh [8]byte
	binary.BigEndian.PutUint32(wh[0:4], 100)
	binary.BigEndian.PutUint32(wh[4:8], 200)
	png = append(png, wh[:]...)
	dims, err := DetectImageDimensions(png)
	if err != nil {
		t.Fatalf("DetectImageDimensions: %v", err)
	}
	if dims == nil || dims.Width != 100 || dims.Height != 200 {
		t.Fatalf("DetectImageDimensions: got %+v", dims)
	}
}

func TestExportImportRoundtrip(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()

	// Locked: ExportKeys returns nil without an error.
	locked, err := chat.ExportKeys()
	if err != nil {
		t.Fatalf("ExportKeys (locked) failed: %v", err)
	}
	if locked != nil {
		t.Fatal("expected nil exported keys while locked")
	}

	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Export: raw private key bytes
	exported, err := chat.ExportKeys()
	if err != nil {
		t.Fatalf("ExportKeys failed: %v", err)
	}
	if len(exported) == 0 {
		t.Fatal("expected non-empty exported keys")
	}
	if base64.StdEncoding.EncodeToString(exported) != v.PrivateKeysConcatB64 {
		t.Error("exported key bytes do not match the imported fixture keys")
	}

	// Lock and re-import
	chat.Lock()
	if err := chat.ImportKeys(exported); err != nil {
		t.Fatalf("ImportKeys (re-import) failed: %v", err)
	}

	// Keys should still match
	keys, err := chat.GetPublicKeys()
	if err != nil {
		t.Fatalf("GetPublicKeys failed: %v", err)
	}
	if keys.Identity != v.IdentityPublicB64 {
		t.Error("identity key mismatch after re-import")
	}
}

func TestPrepareConversationKeyChangeGeneratesRandomKey(t *testing.T) {
	v := loadVectors(t)
	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	publicKeys := []PublicKeyInput{{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"}}
	prep, err := chat.PrepareConversationKeyChange(ConversationKeyChangeParams{
		SenderID:          "me",
		SigningKeyVersion: "1",
		PublicKeys:        publicKeys,
		ConversationID:    "conv-1",
	})
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange failed: %v", err)
	}

	if len(prep.ConversationKey) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(prep.ConversationKey))
	}

	// Two prepared changes must produce different keys (random).
	prep2, err := chat.PrepareConversationKeyChange(ConversationKeyChangeParams{
		SenderID:          "me",
		SigningKeyVersion: "1",
		PublicKeys:        publicKeys,
		ConversationID:    "conv-1",
	})
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange (2nd) failed: %v", err)
	}
	if bytes.Equal(prep.ConversationKey, prep2.ConversationKey) {
		t.Error("two prepared conversation keys should not be identical")
	}
}

func TestGenerateKeypairs(t *testing.T) {
	chat := New()
	defer chat.Close()

	payload, err := chat.GenerateKeypairs()
	if err != nil {
		t.Fatalf("GenerateKeypairs failed: %v", err)
	}
	if payload == nil {
		t.Fatal("expected non-nil payload")
	}
	if payload.PublicKey.PublicKey == "" {
		t.Error("expected non-empty public_key")
	}
	if payload.PublicKey.SigningPublicKey == "" {
		t.Error("expected non-empty signing_public_key")
	}
	if payload.PublicKey.IdentityPublicKeySignature == "" {
		t.Error("expected non-empty identity_public_key_signature")
	}
	if payload.PublicKey.RegistrationMethod == "" {
		t.Error("expected non-empty registration_method")
	}

	// After GenerateKeypairs the SDK should be unlocked
	if !chat.IsUnlocked() {
		t.Error("expected IsUnlocked() == true after GenerateKeypairs")
	}
}

func TestGetPublicKeyFingerprint(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()

	// Before import: should error
	_, err := chat.GetPublicKeyFingerprint()
	if err == nil {
		t.Error("expected error before importing keys")
	}

	// Import keys, then get fingerprint
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	fp, err := chat.GetPublicKeyFingerprint()
	if err != nil {
		t.Fatalf("GetPublicKeyFingerprint failed: %v", err)
	}
	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}

	// Fingerprint should be deterministic for the same key
	fp2, err := chat.GetPublicKeyFingerprint()
	if err != nil {
		t.Fatalf("GetPublicKeyFingerprint (2nd) failed: %v", err)
	}
	if fp != fp2 {
		t.Errorf("fingerprint not deterministic: %q vs %q", fp, fp2)
	}
}

func TestHasIdentityKey(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()

	// Before import
	if chat.HasIdentityKey() {
		t.Error("expected HasIdentityKey() == false before import")
	}

	// After import
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}
	if !chat.HasIdentityKey() {
		t.Error("expected HasIdentityKey() == true after import")
	}

	// After lock
	chat.Lock()
	if chat.HasIdentityKey() {
		t.Error("expected HasIdentityKey() == false after Lock()")
	}
}

func TestSetRejectUnverified(t *testing.T) {
	chat := New()
	defer chat.Close()

	// FFI plumbing smoke only: the flag crosses the boundary without a crash.
	// The policy's behavior is pinned by TestDecryptEventsFixtureVectors
	// (default reject) and the Rust core suite.
	chat.SetRejectUnverified(true)
	chat.SetRejectUnverified(false)
	chat.SetRejectUnverified(true)
}

func TestVerifyKeyBinding(t *testing.T) {
	chat := New()
	defer chat.Close()

	reg, err := chat.GenerateKeypairs()
	if err != nil {
		t.Fatalf("GenerateKeypairs failed: %v", err)
	}

	ok, err := chat.VerifyKeyBinding(
		reg.PublicKey.PublicKey,
		reg.PublicKey.SigningPublicKey,
		reg.PublicKey.IdentityPublicKeySignature,
	)
	if err != nil {
		t.Fatalf("VerifyKeyBinding failed: %v", err)
	}
	if !ok {
		t.Error("expected a freshly generated key binding to verify")
	}
}

func TestMatchesRegisteredKey(t *testing.T) {
	chat := New()
	defer chat.Close()

	reg, err := chat.GenerateKeypairs()
	if err != nil {
		t.Fatalf("GenerateKeypairs failed: %v", err)
	}

	// SPKI/DER form from the registration payload.
	ok, err := chat.MatchesRegisteredKey(reg.PublicKey.PublicKey)
	if err != nil {
		t.Fatalf("MatchesRegisteredKey (SPKI) failed: %v", err)
	}
	if !ok {
		t.Error("expected the registered SPKI key to match")
	}

	// Raw SEC1 form from GetPublicKeys.
	keys, err := chat.GetPublicKeys()
	if err != nil {
		t.Fatalf("GetPublicKeys failed: %v", err)
	}
	ok, err = chat.MatchesRegisteredKey(keys.Identity)
	if err != nil {
		t.Fatalf("MatchesRegisteredKey (raw) failed: %v", err)
	}
	if !ok {
		t.Error("expected the raw identity key to match")
	}

	// A different identity's key must not match.
	other := New()
	defer other.Close()
	otherReg, err := other.GenerateKeypairs()
	if err != nil {
		t.Fatalf("GenerateKeypairs failed: %v", err)
	}
	ok, err = chat.MatchesRegisteredKey(otherReg.PublicKey.PublicKey)
	if err != nil {
		t.Fatalf("MatchesRegisteredKey (other) failed: %v", err)
	}
	if ok {
		t.Error("expected a different identity's key not to match")
	}

	// No identity loaded and invalid base64 are errors, not false.
	locked := New()
	defer locked.Close()
	if _, err := locked.MatchesRegisteredKey(reg.PublicKey.PublicKey); err == nil {
		t.Error("expected an error with no identity keypair loaded")
	}
	if _, err := chat.MatchesRegisteredKey("not base64!!"); err == nil {
		t.Error("expected an error for invalid base64 input")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	plaintext := "Hello, encryption roundtrip!"
	ciphertextB64, err := chat.Encrypt(plaintext, v.conversationKey(t))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if ciphertextB64 == "" {
		t.Fatal("expected non-empty ciphertext")
	}

	// Decrypt back
	decrypted, err := chat.Decrypt(ciphertextB64, v.conversationKey(t))
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("decrypt mismatch:\ngot  %q\nwant %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptEmptyString(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Encrypt empty string
	ciphertextB64, err := chat.Encrypt("", v.conversationKey(t))
	if err != nil {
		t.Fatalf("Encrypt (empty) failed: %v", err)
	}

	decrypted, err := chat.Decrypt(ciphertextB64, v.conversationKey(t))
	if err != nil {
		t.Fatalf("Decrypt (empty) failed: %v", err)
	}
	if decrypted != "" {
		t.Errorf("expected empty string, got %q", decrypted)
	}
}

func TestEncryptStreamDecryptStreamRoundtrip(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// The fixture stores the payload base64-encoded; the API takes raw bytes.
	plaintext, err := base64.StdEncoding.DecodeString(v.PlaintextB64)
	if err != nil {
		t.Fatalf("failed to decode plaintext_b64: %v", err)
	}

	encrypted, err := chat.EncryptStream(plaintext, v.conversationKey(t))
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}
	if len(encrypted) == 0 {
		t.Fatal("expected non-empty encrypted stream")
	}

	// Decrypt back
	decrypted, err := chat.DecryptStream(encrypted, v.conversationKey(t))
	if err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("stream roundtrip mismatch:\ngot  %x\nwant %x", decrypted, plaintext)
	}
}

func TestStreamEncryptorDecryptorRoundtrip(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// A multi-frame payload so chunking and re-framing are exercised.
	plaintext := bytes.Repeat([]byte{0xAB}, 5000)

	enc, err := chat.StreamEncryptor(v.conversationKey(t))
	if err != nil {
		t.Fatalf("StreamEncryptor failed: %v", err)
	}
	var ciphertext []byte
	for i := 0; i < len(plaintext); i += 700 {
		end := i + 700
		if end > len(plaintext) {
			end = len(plaintext)
		}
		out, err := enc.Push(plaintext[i:end])
		if err != nil {
			enc.Close()
			t.Fatalf("encryptor Push failed: %v", err)
		}
		ciphertext = append(ciphertext, out...)
	}
	final, err := enc.Finish()
	if err != nil {
		enc.Close()
		t.Fatalf("encryptor Finish failed: %v", err)
	}
	ciphertext = append(ciphertext, final...)
	enc.Close()

	dec, err := chat.StreamDecryptor(v.conversationKey(t))
	if err != nil {
		t.Fatalf("StreamDecryptor failed: %v", err)
	}
	var got []byte
	for i := 0; i < len(ciphertext); i += 333 {
		end := i + 333
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		out, err := dec.Push(ciphertext[i:end])
		if err != nil {
			dec.Close()
			t.Fatalf("decryptor Push failed: %v", err)
		}
		got = append(got, out...)
	}
	final, err = dec.Finish()
	if err != nil {
		dec.Close()
		t.Fatalf("decryptor Finish failed: %v", err)
	}
	got = append(got, final...)
	dec.Close()

	if !bytes.Equal(got, plaintext) {
		t.Errorf("incremental stream roundtrip mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}

	// Truncating the ciphertext must surface an error at Finish.
	dec2, err := chat.StreamDecryptor(v.conversationKey(t))
	if err != nil {
		t.Fatalf("StreamDecryptor failed: %v", err)
	}
	defer dec2.Close()
	truncated := ciphertext[:len(ciphertext)-1]
	if _, err := dec2.Push(truncated); err != nil {
		return // an early error is also acceptable
	}
	if _, err := dec2.Finish(); err == nil {
		t.Error("expected truncation error on Finish, got nil")
	}
}

func TestEncryptReply(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	replyText := "quoted reply text"
	payload, err := chat.EncryptReply(EncryptReplyParams{
		SenderID:               "me",
		ConversationID:         "conv-1",
		ConversationKey:        v.conversationKey(t),
		Text:                   "this is my reply",
		ConversationKeyVersion: "1",
		SigningKeyVersion:      "1",
		ReplyToSequenceID:      "seq-42",
		ReplyToText:            &replyText,
	})
	if err != nil {
		t.Fatalf("EncryptReply failed: %v", err)
	}
	if payload.EncryptedContent == "" {
		t.Error("expected non-empty encrypted_content")
	}
	if payload.Signature == "" {
		t.Error("expected non-empty signature")
	}
	if payload.EncodedEventSignature == "" {
		t.Error("expected non-empty encoded_event_signature")
	}
	if payload.ConversationKeyVersion != "1" {
		t.Errorf("expected conversation_key_version '1', got %q", payload.ConversationKeyVersion)
	}
}

func TestEncryptAddReaction(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	payload, err := chat.EncryptAddReaction(EncryptReactionParams{
		SenderID:                "me",
		ConversationID:          "conv-1",
		ConversationKey:         v.conversationKey(t),
		TargetMessageSequenceID: "seq-99",
		Emoji:                   "\U0001F44D",
		ConversationKeyVersion:  "1",
		SigningKeyVersion:       "1",
	})
	if err != nil {
		t.Fatalf("EncryptAddReaction failed: %v", err)
	}
	if payload.EncryptedContent == "" {
		t.Error("expected non-empty encrypted_content")
	}
	if payload.Signature == "" {
		t.Error("expected non-empty signature")
	}
}

func TestEncryptRemoveReaction(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	payload, err := chat.EncryptRemoveReaction(EncryptReactionParams{
		SenderID:                "me",
		ConversationID:          "conv-1",
		ConversationKey:         v.conversationKey(t),
		TargetMessageSequenceID: "seq-99",
		Emoji:                   "\U0001F44D",
		ConversationKeyVersion:  "1",
		SigningKeyVersion:       "1",
	})
	if err != nil {
		t.Fatalf("EncryptRemoveReaction failed: %v", err)
	}
	if payload.EncryptedContent == "" {
		t.Error("expected non-empty encrypted_content")
	}
	if payload.Signature == "" {
		t.Error("expected non-empty signature")
	}
}

func TestEncryptEdit(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	payload, err := chat.EncryptEdit(EncryptEditParams{
		SenderID:                "111",
		ConversationID:          "conv-1",
		ConversationKey:         v.conversationKey(t),
		TargetMessageSequenceID: "seq-99",
		UpdatedText:             "see https://example.com",
		Entities:                []EntityTuple{NewEntity(4, 23, "url")},
		ConversationKeyVersion:  "1",
		SigningKeyVersion:       "1",
	})
	if err != nil {
		t.Fatalf("EncryptEdit failed: %v", err)
	}
	if payload.EncryptedContent == "" {
		t.Error("expected non-empty encrypted_content")
	}
	if payload.Signature == "" {
		t.Error("expected non-empty signature")
	}
	if payload.EncodedEventSignature == "" {
		t.Error("expected non-empty encoded_event_signature")
	}
	if payload.MessageID == "" {
		t.Error("expected non-empty message_id")
	}
}

func TestPrepareMessageDelete(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// A 1:1 id is signed in its canonical colon form; delete-for-all signs
	// the wire action 2.
	sig, err := chat.PrepareMessageDelete(MessageDeleteParams{
		SenderID:          "111",
		SigningKeyVersion: "1",
		ConversationID:    "222-111",
		SequenceIDs:       []string{"seq-10", "seq-11"},
		DeleteForAll:      true,
	})
	if err != nil {
		t.Fatalf("PrepareMessageDelete failed: %v", err)
	}
	if sig.MessageID == "" {
		t.Error("expected non-empty message_id")
	}
	if sig.EncodedMessageEventDetail == "" {
		t.Error("expected non-empty encoded_message_event_detail")
	}
	if sig.Signature == "" {
		t.Error("expected non-empty signature")
	}
	want := fmt.Sprintf("MessageDeleteEvent,%s,111,111:222,2,seq-10,seq-11", sig.MessageID)
	if sig.SignaturePayload != want {
		t.Errorf("expected signature_payload %q, got %q", want, sig.SignaturePayload)
	}

	// Group ids pass through unchanged; delete-for-self signs the wire
	// action 1.
	selfSig, err := chat.PrepareMessageDelete(MessageDeleteParams{
		SenderID:          "111",
		SigningKeyVersion: "1",
		ConversationID:    "g999",
		SequenceIDs:       []string{"seq-1"},
		DeleteForAll:      false,
	})
	if err != nil {
		t.Fatalf("PrepareMessageDelete (delete-for-self) failed: %v", err)
	}
	want = fmt.Sprintf("MessageDeleteEvent,%s,111,g999,1,seq-1", selfSig.MessageID)
	if selfSig.SignaturePayload != want {
		t.Errorf("expected signature_payload %q, got %q", want, selfSig.SignaturePayload)
	}
}

func TestPrepareConversationKeyChange(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	publicKeys := []PublicKeyInput{
		{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"},
	}
	prepared, err := chat.PrepareConversationKeyChange(ConversationKeyChangeParams{
		SenderID:          "me",
		SigningKeyVersion: "1",
		PublicKeys:        publicKeys,
		ConversationID:    "conv-1",
	})
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange failed: %v", err)
	}
	if prepared == nil {
		t.Fatal("expected non-nil result")
	}
	if prepared.ConversationID != "conv-1" {
		t.Errorf("expected conversation_id 'conv-1', got %q", prepared.ConversationID)
	}
	if len(prepared.ConversationKey) == 0 {
		t.Error("expected non-empty conversation_key")
	}
	if prepared.ConversationKeyVersion == "" {
		t.Error("expected non-empty conversation_key_version")
	}
	if len(prepared.ParticipantKeys) != 1 {
		t.Fatalf("expected 1 participant key, got %d", len(prepared.ParticipantKeys))
	}
	if prepared.ParticipantKeys[0].UserID != "me" {
		t.Errorf("expected user_id 'me', got %q", prepared.ParticipantKeys[0].UserID)
	}
	if len(prepared.ActionSignatures) != 1 {
		t.Fatalf("expected 1 action signature, got %d", len(prepared.ActionSignatures))
	}
	// Empty: the payload embeds the plaintext conversation key and is withheld.
	if prepared.ActionSignatures[0].SignaturePayload != "" {
		t.Errorf("unexpected signature payload: %q", prepared.ActionSignatures[0].SignaturePayload)
	}

	// The encrypted key should be decryptable back to the conversation key.
	decryptedKey, err := chat.DecryptConversationKey(prepared.ParticipantKeys[0].EncryptedKey)
	if err != nil {
		t.Fatalf("DecryptConversationKey (prepared) failed: %v", err)
	}
	if !bytes.Equal(decryptedKey, prepared.ConversationKey) {
		t.Error("decrypted key doesn't match prepared conversation key")
	}
}

func TestPrepareConversationKeyChangeDerivesOneToOneID(t *testing.T) {
	v := loadVectors(t)

	chat1 := New()
	defer chat1.Close()
	if err := chat1.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys (chat1) failed: %v", err)
	}

	chat2 := New()
	defer chat2.Close()
	payload2, err := chat2.GenerateKeypairs()
	if err != nil {
		t.Fatalf("GenerateKeypairs (chat2) failed: %v", err)
	}

	// Numeric ids sort numerically; omitting conversation_id derives "min:max".
	publicKeys := []PublicKeyInput{
		{UserID: "1491585161162473473", PublicKey: v.IdentityPublicB64, KeyVersion: "1"},
		{UserID: "17380288", PublicKey: payload2.PublicKey.PublicKey, KeyVersion: "1"},
	}

	prepared, err := chat1.PrepareConversationKeyChange(ConversationKeyChangeParams{
		SenderID:          "1491585161162473473",
		SigningKeyVersion: "1",
		PublicKeys:        publicKeys,
	})
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange failed: %v", err)
	}
	if prepared.ConversationID != "17380288:1491585161162473473" {
		t.Errorf("unexpected derived conversation_id: %q", prepared.ConversationID)
	}
	if len(prepared.ParticipantKeys) != 2 {
		t.Fatalf("expected 2 participant keys, got %d", len(prepared.ParticipantKeys))
	}
}

func TestConversationKeyChangeParamsDeriveAndDecryptRoundTrip(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// No ConversationID set: the canonical one-to-one id is derived from the
	// two participants. Both entries reuse our identity key so every
	// participant key decrypts locally.
	publicKeys := []PublicKeyInput{
		{UserID: "17380288", PublicKey: v.IdentityPublicB64, KeyVersion: "1"},
		{UserID: "1491585161162473473", PublicKey: v.IdentityPublicB64, KeyVersion: "1"},
	}
	prepared, err := chat.PrepareConversationKeyChange(ConversationKeyChangeParams{
		SenderID:          "17380288",
		SigningKeyVersion: "1",
		PublicKeys:        publicKeys,
	})
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange failed: %v", err)
	}
	if prepared.ConversationID != "17380288:1491585161162473473" {
		t.Errorf("unexpected derived conversation_id: %q", prepared.ConversationID)
	}
	if len(prepared.ParticipantKeys) != 2 {
		t.Fatalf("expected 2 participant keys, got %d", len(prepared.ParticipantKeys))
	}

	for _, pk := range prepared.ParticipantKeys {
		decrypted, err := chat.DecryptConversationKey(pk.EncryptedKey)
		if err != nil {
			t.Fatalf("DecryptConversationKey (%s) failed: %v", pk.UserID, err)
		}
		if !bytes.Equal(decrypted, prepared.ConversationKey) {
			t.Errorf("decrypted key for %s doesn't match prepared conversation key", pk.UserID)
		}
	}
}

func TestPrepareGroupMembersChange(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	publicKeys := []PublicKeyInput{
		{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"},
	}
	prepared, err := chat.PrepareGroupMembersChange(GroupMembersChangeParams{
		SenderID:          "me",
		SigningKeyVersion: "1",
		PublicKeys:        publicKeys,
		ConversationID:    "g123",
		NewMemberIDs:      []string{"new-user"},
		CurrentMemberIDs:  []string{"me"},
		CurrentAdminIDs:   []string{"me"},
		CurrentTitle:      "Team",
	})
	if err != nil {
		t.Fatalf("PrepareGroupMembersChange failed: %v", err)
	}
	if prepared.ConversationID != "g123" {
		t.Errorf("expected conversation_id 'g123', got %q", prepared.ConversationID)
	}
	// A member add emits two signed actions: the key change and the add.
	if len(prepared.ActionSignatures) != 2 {
		t.Fatalf("expected 2 action signatures, got %d", len(prepared.ActionSignatures))
	}
	// Empty: the payload embeds the plaintext conversation key and is withheld.
	if prepared.ActionSignatures[0].SignaturePayload != "" {
		t.Errorf("unexpected CKCE signature payload: %q", prepared.ActionSignatures[0].SignaturePayload)
	}
	if prepared.ActionSignatures[0].EncodedMessageEventDetail == "" {
		t.Error("expected non-empty CKCE encoded event detail")
	}
	if !strings.HasPrefix(prepared.ActionSignatures[1].SignaturePayload, "GroupChangeEvent.GroupMemberAddChange,") {
		t.Errorf("unexpected member-add signature payload: %q", prepared.ActionSignatures[1].SignaturePayload)
	}
	if prepared.ActionSignatures[1].EncodedMessageEventDetail == "" {
		t.Error("expected non-empty member-add encoded event detail")
	}
}

func TestPrepareGroupCreate(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	publicKeys := []PublicKeyInput{
		{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"},
	}
	prepared, err := chat.PrepareGroupCreate(GroupCreateParams{
		SenderID:          "me",
		SigningKeyVersion: "1",
		PublicKeys:        publicKeys,
		ConversationID:    "g123",
		MemberIDs:         []string{"me", "friend"},
		AdminIDs:          []string{"me"},
		Title:             "Team",
	})
	if err != nil {
		t.Fatalf("PrepareGroupCreate failed: %v", err)
	}
	if prepared.ConversationID != "g123" {
		t.Errorf("expected conversation_id 'g123', got %q", prepared.ConversationID)
	}
	// A group create emits two signed actions: the key change and the create.
	if len(prepared.ActionSignatures) != 2 {
		t.Fatalf("expected 2 action signatures, got %d", len(prepared.ActionSignatures))
	}
	// Empty: the payload embeds the plaintext conversation key and is withheld.
	if prepared.ActionSignatures[0].SignaturePayload != "" {
		t.Errorf("unexpected CKCE signature payload: %q", prepared.ActionSignatures[0].SignaturePayload)
	}
	if prepared.ActionSignatures[0].EncodedMessageEventDetail == "" {
		t.Error("expected non-empty CKCE encoded event detail")
	}
	if !strings.HasPrefix(prepared.ActionSignatures[1].SignaturePayload, "GroupChangeEvent.GroupCreate,") {
		t.Errorf("unexpected group-create signature payload: %q", prepared.ActionSignatures[1].SignaturePayload)
	}
	if prepared.ActionSignatures[1].EncodedMessageEventDetail == "" {
		t.Error("expected non-empty group-create encoded event detail")
	}
}

// TestPrepareGroupCreateEmptyTitleSignsNullSentinel pins absent-value
// normalization across the FFI: an empty (Go zero-value) title/avatar is
// "not set" and must sign the null sentinel, not an empty string.
func TestPrepareGroupCreateEmptyTitleSignsNullSentinel(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	prepared, err := chat.PrepareGroupCreate(GroupCreateParams{
		SenderID:          "me",
		SigningKeyVersion: "1",
		PublicKeys:        []PublicKeyInput{{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"}},
		ConversationID:    "g123",
		MemberIDs:         []string{"me", "friend"},
		AdminIDs:          []string{"me"},
		// Title and AvatarURL left as the zero value.
	})
	if err != nil {
		t.Fatalf("PrepareGroupCreate failed: %v", err)
	}
	payload := prepared.ActionSignatures[1].SignaturePayload
	// Trailing slots: title, avatar_url, ttl — all unset → null sentinels.
	if !strings.HasSuffix(payload, ",null,null,null") {
		t.Errorf("title/avatar must sign as the null sentinel, got: %q", payload)
	}
}

// TestPrepareGroupCreateCommaTitleErrors pins comma-injection rejection
// propagating through the FFI: the signature payload is comma-joined with no
// escaping, so a comma in the title must fail instead of signing ambiguously.
func TestPrepareGroupCreateCommaTitleErrors(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	_, err := chat.PrepareGroupCreate(GroupCreateParams{
		SenderID:          "me",
		SigningKeyVersion: "1",
		PublicKeys:        []PublicKeyInput{{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"}},
		ConversationID:    "g123",
		MemberIDs:         []string{"me", "friend"},
		AdminIDs:          []string{"me"},
		Title:             "Team, the sequel",
	})
	if err == nil {
		t.Fatal("expected an error for a comma-containing title")
	}
}

func TestDecryptEventInvalidInput(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Invalid base64 event should error
	_, err := chat.DecryptEvent("not-valid-base64!!!", nil, nil)
	if err == nil {
		t.Error("expected error for invalid base64 event input")
	}
}

func TestDecryptEventsEmptyList(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Empty events list should return an empty result, not an error
	result, err := chat.DecryptEvents([]string{}, nil)
	if err != nil {
		t.Fatalf("DecryptEvents (empty) failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for empty events list")
	}
}

func TestDecryptEventsInvalidEvent(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// The batch API never throws for a bad event: it must return a result
	// with exactly one per-event error keyed by the event's index.
	result, err := chat.DecryptEvents([]string{"not-valid-base64!!!"}, nil)
	if err != nil {
		t.Fatalf("DecryptEvents must collect per-event errors, got top-level error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(result.Messages))
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected exactly 1 error, got %v", result.Errors)
	}
	if msg, ok := result.Errors["0"]; !ok || msg == "" {
		t.Errorf(`expected a non-empty error keyed "0", got %v`, result.Errors)
	}
}

// TestDecryptEventsFixtureVectors drives the batch and single-event decrypt
// contracts over the committed event vectors: a signed KeyChange carrying the
// fixture conversation key, a signed message under it, and a garbage entry.
func TestDecryptEventsFixtureVectors(t *testing.T) {
	v := loadVectors(t)

	chat := New() // default reject-unverified policy
	defer chat.Close()
	// Import + registered key version in one call.
	if err := chat.ImportKeysWithVersion(v.privateKeys(t), v.EventRecipientKeyVersion); err != nil {
		t.Fatalf("ImportKeysWithVersion failed: %v", err)
	}
	signingKeys := v.eventSigningKeys()

	result, err := chat.DecryptEvents(
		[]string{v.EventKeyChangeB64, v.EventMessageB64, v.EventGarbageB64},
		signingKeys,
	)
	if err != nil {
		t.Fatalf("DecryptEvents failed: %v", err)
	}

	// The garbage event is the only error, keyed by its index.
	if len(result.Errors) != 1 {
		t.Fatalf("expected exactly 1 error, got %v", result.Errors)
	}
	if _, ok := result.Errors["2"]; !ok {
		t.Errorf(`expected the error keyed "2", got %v`, result.Errors)
	}

	// The signed KeyChange's key is adopted with the fixture bytes/version.
	if result.ConversationKeys.LatestVersion == nil ||
		*result.ConversationKeys.LatestVersion != v.EventConversationKeyVersion {
		t.Errorf("unexpected latest_version: %v", result.ConversationKeys.LatestVersion)
	}
	adopted, ok := result.ConversationKeys.Keys[v.EventConversationKeyVersion]
	if !ok {
		t.Fatalf("conversation key %q not adopted", v.EventConversationKeyVersion)
	}
	if !bytes.Equal(adopted, v.conversationKey(t)) {
		t.Errorf("adopted key mismatch:\ngot  %x\nwant %x", adopted, v.conversationKey(t))
	}

	// Exactly one verified KeyChange and one verified message with the
	// fixture text.
	var keyChanges []*KeyChangeEvent
	var messages []*Message
	for i := range result.Messages {
		if kc := result.Messages[i].Event.AsKeyChange(); kc != nil {
			keyChanges = append(keyChanges, kc)
		}
		if msg := result.Messages[i].Event.AsMessage(); msg != nil {
			messages = append(messages, msg)
		}
	}
	if len(keyChanges) != 1 {
		t.Fatalf("expected 1 KeyChange, got %d", len(keyChanges))
	}
	if !keyChanges[0].Verified {
		t.Error("expected the fixture KeyChange to verify")
	}
	if keyChanges[0].KeyVersion != v.EventConversationKeyVersion {
		t.Errorf("unexpected KeyChange key_version: %q", keyChanges[0].KeyVersion)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	if messages[0].Text() != v.EventMessageText {
		t.Errorf("message text mismatch:\ngot  %q\nwant %q", messages[0].Text(), v.EventMessageText)
	}
	if !messages[0].Verified {
		t.Error("expected the fixture message to verify")
	}

	// Single-event path with pre-cached keys verifies the same message …
	cached := map[string][]byte{v.EventConversationKeyVersion: adopted}
	event, err := chat.DecryptEvent(v.EventMessageB64, cached, signingKeys)
	if err != nil {
		t.Fatalf("DecryptEvent failed: %v", err)
	}
	single := event.AsMessage()
	if single == nil {
		t.Fatalf("expected a Message event, got type %q", event.Type)
	}
	if single.Text() != v.EventMessageText || !single.Verified {
		t.Errorf("unexpected single-event result: text=%q verified=%v", single.Text(), single.Verified)
	}

	// … and errors on the garbage event.
	if _, err := chat.DecryptEvent(v.EventGarbageB64, nil, signingKeys); err == nil {
		t.Error("expected DecryptEvent to error on the garbage event")
	}
}

// TestFailureEventFixtureVector pins the decoded failure metadata: failure
// events are unsigned by protocol, so the vector decodes with no conversation
// or signing keys, and the JSON carries the PascalCase discriminator values.
func TestFailureEventFixtureVector(t *testing.T) {
	v := loadVectors(t)

	chat := New() // default reject-unverified policy
	defer chat.Close()

	event, err := chat.DecryptEvent(v.EventFailureB64, nil, nil)
	if err != nil {
		t.Fatalf("DecryptEvent failed: %v", err)
	}
	if event.Type != "Failure" {
		t.Fatalf("expected a Failure event, got type %q", event.Type)
	}
	var failure struct {
		EventMeta
		Failure       string `json:"failure"`
		RateLimitTier string `json:"rate_limit_tier"`
	}
	if err := json.Unmarshal(event.Raw(), &failure); err != nil {
		t.Fatalf("decode failure event: %v", err)
	}
	if failure.Failure != "RateLimitUpsell" {
		t.Errorf("unexpected failure type: %q", failure.Failure)
	}
	if failure.RateLimitTier != "Premium" {
		t.Errorf("unexpected rate limit tier: %q", failure.RateLimitTier)
	}
	if failure.SenderID == nil || *failure.SenderID != v.EventSenderID {
		t.Errorf("unexpected sender_id: %v", failure.SenderID)
	}
}

// TestSigningKeyEntryJSONShape guards that SigningKeyEntry serializes the full
// 5-field shape the native core requires. The signing-key payload must include
// identity_public_key and identity_public_key_signature; the parser requires the
// full 5-field shape.
func TestSigningKeyEntryJSONShape(t *testing.T) {
	entry := SigningKeyEntry{
		UserID:                     "111",
		PublicKeyVersion:           "v1",
		PublicKey:                  "SIGNING_B64",
		IdentityPublicKey:          "IDENTITY_B64",
		IdentityPublicKeySignature: "BINDING_SIG_B64",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	for _, key := range []string{
		`"user_id"`, `"public_key_version"`, `"public_key"`,
		`"identity_public_key"`, `"identity_public_key_signature"`,
	} {
		if !bytes.Contains(data, []byte(key)) {
			t.Errorf("SigningKeyEntry JSON missing %s: %s", key, data)
		}
	}
}

// TestDecryptEventsMalformedSigningKeysError verifies the FFI surfaces an error
// for a structurally invalid signing-keys payload rather than silently skipping
// verification. A well-formed entry must be accepted.
func TestDecryptEventsMalformedSigningKeysError(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// The typed Go API always serializes the full 5-field entry (see
	// TestSigningKeyEntryJSONShape), so the malformed payload goes through
	// the raw FFI seam: an entry missing identity_public_key /
	// identity_public_key_signature must be rejected, not skipped.
	malformed := `[{"user_id":"111","public_key_version":"v1","public_key":"SIGNING_B64"}]`
	if _, err := ffiDecryptEvents(chat.h, `[]`, malformed); err == nil {
		t.Error("expected an error for a signing-keys payload missing the identity binding fields")
	} else if !strings.Contains(err.Error(), "Invalid signing keys JSON") {
		t.Errorf("unexpected error for malformed signing keys: %v", err)
	}

	// A well-formed (if unused) signing key must be accepted.
	goodKeys := []SigningKeyEntry{{
		UserID:                     "111",
		PublicKeyVersion:           "v1",
		PublicKey:                  "SIGNING_B64",
		IdentityPublicKey:          "IDENTITY_B64",
		IdentityPublicKeySignature: "BINDING_SIG_B64",
	}}
	if _, err := chat.DecryptEvents([]string{}, goodKeys); err != nil {
		t.Fatalf("DecryptEvents with well-formed signing keys failed: %v", err)
	}
}

func TestUpdateConfigInvalid(t *testing.T) {
	chat := New()
	defer chat.Close()

	// UpdateConfig with invalid JSON should error
	err := chat.UpdateConfig("not-valid-json")
	if err == nil {
		t.Error("expected error for invalid JSON config")
	}
}

// TestGuessesRemaining pins the parsing of the stable "guesses_remaining=N"
// token the core emits on invalid-PIN unlock failures; 0 means the guess
// budget is exhausted. Errors without the token report ok=false.
func TestGuessesRemaining(t *testing.T) {
	if n, ok := GuessesRemaining(errors.New("Juicebox error: Invalid PIN: guesses_remaining=3")); !ok || n != 3 {
		t.Errorf("expected (3, true), got (%d, %v)", n, ok)
	}
	if n, ok := GuessesRemaining(errors.New("Juicebox error: Invalid PIN: guesses_remaining=0")); !ok || n != 0 {
		t.Errorf("expected (0, true), got (%d, %v)", n, ok)
	}
	if _, ok := GuessesRemaining(errors.New("Juicebox error: Invalid PIN")); ok {
		t.Error("expected ok=false without the token")
	}
	if _, ok := GuessesRemaining(nil); ok {
		t.Error("expected ok=false for nil error")
	}

	// A real error from the binding's own path carries no count.
	chat := New()
	defer chat.Close()
	err := chat.UpdateConfig("not-valid-json")
	if err == nil {
		t.Fatal("expected error for invalid JSON config")
	}
	if _, ok := GuessesRemaining(err); ok {
		t.Error("expected ok=false for a non-PIN error")
	}
}

func TestUpdateConfigXAPIJuiceboxConfigShape(t *testing.T) {
	chat := New()
	defer chat.Close()

	// The X API juicebox_config object (key_store_token_map_json + token_map)
	// must be accepted as-is; the embedded config carries realm public keys
	// and server thresholds that the realms require.
	xAPIConfig := `{
		"key_store_token_map_json": "{\"realms\":[{\"id\":\"aa11\",\"address\":\"https://realm-b.example/\"},{\"id\":\"bb22\",\"address\":\"https://realm-east.example/\",\"public_key\":\"e8b2\"}],\"register_threshold\":2,\"recover_threshold\":2,\"pin_hashing_mode\":\"Standard2019\"}",
		"max_guess_count": 20,
		"token_map": [
			{"key": "aa11", "value": {"address": "https://realm-b.example/", "token": "t1"}},
			{"key": "bb22", "value": {"address": "https://realm-east.example/", "token": "t2"}}
		]
	}`
	if err := chat.UpdateConfig(xAPIConfig); err != nil {
		t.Fatalf("UpdateConfig with X API juicebox_config shape failed: %v", err)
	}

	// A malformed embedded config must error, not silently fall back to the
	// lossy token_map derivation.
	badConfig := `{
		"key_store_token_map_json": "not json",
		"token_map": [
			{"key": "aa11", "value": {"address": "https://realm-b.example/", "token": "t1"}}
		]
	}`
	err := chat.UpdateConfig(badConfig)
	if err == nil {
		t.Fatal("expected error for malformed key_store_token_map_json")
	}
	if !strings.Contains(err.Error(), "Invalid key_store_token_map_json") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEncryptDecryptWithGeneratedKey(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Get a fresh conversation key from a prepared key change and use it for encryption.
	publicKeys := []PublicKeyInput{{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"}}
	prep, err := chat.PrepareConversationKeyChange(ConversationKeyChangeParams{
		SenderID:          "me",
		SigningKeyVersion: "1",
		PublicKeys:        publicKeys,
		ConversationID:    "conv-1",
	})
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange failed: %v", err)
	}
	key := prep.ConversationKey

	plaintext := "encrypted with a generated key"
	ciphertextB64, err := chat.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt (generated key) failed: %v", err)
	}
	decrypted, err := chat.Decrypt(ciphertextB64, key)
	if err != nil {
		t.Fatalf("Decrypt (generated key) failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("roundtrip mismatch: got %q want %q", decrypted, plaintext)
	}
}

func TestEncryptMessageWithEntitiesAndAttachments(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	payload, err := chat.EncryptMessage(EncryptMessageParams{
		SenderID:               "me",
		ConversationID:         "conv-1",
		ConversationKey:        v.conversationKey(t),
		Text:                   "hello @user check this link",
		ConversationKeyVersion: "1",
		SigningKeyVersion:      "1",
		Entities:               []EntityTuple{NewEntity(6, 11, "mention")},
		Attachments: []AttachmentDescriptor{
			{
				AttachmentType: "url",
				URL:            "https://example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("EncryptMessage (entities+attachments) failed: %v", err)
	}
	if payload.EncryptedContent == "" {
		t.Error("expected non-empty encrypted_content")
	}
	if payload.Signature == "" {
		t.Error("expected non-empty signature")
	}
}

func TestEncryptMessageMixedAttachmentTypesRejected(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Only image/gif/video media may appear in multiples; any other
	// attachment type must be the message's only attachment.
	_, err := chat.EncryptMessage(EncryptMessageParams{
		SenderID:               "me",
		ConversationID:         "conv-1",
		ConversationKey:        v.conversationKey(t),
		Text:                   "mixed attachments",
		ConversationKeyVersion: "1",
		SigningKeyVersion:      "1",
		Attachments: []AttachmentDescriptor{
			{
				AttachmentType: "media",
				MediaHashKey:   "h",
				Width:          100,
				Height:         100,
				FilesizeBytes:  1000,
				Filename:       "pic.jpg",
			},
			{
				AttachmentType: "url",
				URL:            "https://example.com",
			},
		},
	})
	if err == nil {
		t.Fatal("expected mixed attachment types to be rejected")
	}
	if !strings.Contains(err.Error(), "attachment combination") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEncryptMessageURLAttachmentWithBannerImage(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	width := int64(1200)
	height := int64(630)
	title := "Example Product"
	attachment := AttachmentDescriptor{
		AttachmentType: "url",
		URL:            "https://example.com/product",
		DisplayTitle:   &title,
		BannerImage: &URLAttachmentImageDescriptor{
			MediaHashKey:  "banner-hash",
			FilesizeBytes: 24000,
			Filename:      "banner.jpg",
			Width:         &width,
			Height:        &height,
		},
		FaviconImage: &URLAttachmentImageDescriptor{
			MediaHashKey:  "favicon-hash",
			FilesizeBytes: 1200,
			Filename:      "favicon.ico",
		},
	}

	// The FFI marshals params with encoding/json, so serialize the same way
	// and confirm the banner reaches core under the snake_case keys core
	// deserializes: a JSON-tag typo would silently drop the image (core
	// ignores unknown keys) yet still encrypt successfully.
	marshaled, err := json.Marshal(attachment)
	if err != nil {
		t.Fatalf("marshal attachment: %v", err)
	}
	for _, key := range []string{
		`"banner_image"`, `"favicon_image"`, `"media_hash_key"`,
		`"filesize_bytes"`, `"filename"`,
	} {
		if !strings.Contains(string(marshaled), key) {
			t.Errorf("attachment JSON missing %s: %s", key, marshaled)
		}
	}

	payload, err := chat.EncryptMessage(EncryptMessageParams{
		SenderID:               "me",
		ConversationID:         "conv-1",
		ConversationKey:        v.conversationKey(t),
		Text:                   "check this out",
		ConversationKeyVersion: "1",
		SigningKeyVersion:      "1",
		Attachments:            []AttachmentDescriptor{attachment},
	})
	if err != nil {
		t.Fatalf("EncryptMessage (url attachment with banner) failed: %v", err)
	}
	if payload.EncryptedContent == "" {
		t.Error("expected non-empty encrypted_content")
	}
	if payload.Signature == "" {
		t.Error("expected non-empty signature")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Encrypt with fixture key
	ciphertextB64, err := chat.Encrypt("secret", v.conversationKey(t))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with a different key should fail
	publicKeys := []PublicKeyInput{{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"}}
	wrong, err := chat.PrepareConversationKeyChange(ConversationKeyChangeParams{
		SenderID:          "me",
		SigningKeyVersion: "1",
		PublicKeys:        publicKeys,
		ConversationID:    "conv-1",
	})
	if err != nil {
		t.Fatalf("PrepareConversationKeyChange failed: %v", err)
	}
	_, err = chat.Decrypt(ciphertextB64, wrong.ConversationKey)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestGenerateKeypairsProducesDifferentKeys(t *testing.T) {
	chat1 := New()
	defer chat1.Close()
	p1, err := chat1.GenerateKeypairs()
	if err != nil {
		t.Fatalf("GenerateKeypairs (1) failed: %v", err)
	}

	chat2 := New()
	defer chat2.Close()
	p2, err := chat2.GenerateKeypairs()
	if err != nil {
		t.Fatalf("GenerateKeypairs (2) failed: %v", err)
	}

	if p1.PublicKey.PublicKey == p2.PublicKey.PublicKey {
		t.Error("two GenerateKeypairs calls should produce different identity keys")
	}
	if p1.PublicKey.SigningPublicKey == p2.PublicKey.SigningPublicKey {
		t.Error("two GenerateKeypairs calls should produce different signing keys")
	}
}

func TestEncryptReplyWithAttachments(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	replyText := "original message"
	senderID := int64(12345)
	payload, err := chat.EncryptReply(EncryptReplyParams{
		SenderID:               "me",
		ConversationID:         "conv-1",
		ConversationKey:        v.conversationKey(t),
		Text:                   "replying with media",
		ConversationKeyVersion: "1",
		SigningKeyVersion:      "1",
		ReplyToSequenceID:      "seq-100",
		ReplyToSenderID:        &senderID,
		ReplyToText:            &replyText,
		Attachments: []AttachmentDescriptor{
			{
				AttachmentType: "media",
				MediaHashKey:   "abc123hash",
				Width:          640,
				Height:         480,
				FilesizeBytes:  102400,
				Filename:       "photo.jpg",
			},
		},
	})
	if err != nil {
		t.Fatalf("EncryptReply (with attachments) failed: %v", err)
	}
	if payload.EncryptedContent == "" {
		t.Error("expected non-empty encrypted_content")
	}
}

func TestEncryptMessageMediaAttachmentZeroDimensions(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Zero-valued media dimensions are valid (e.g. audio or file media) and
	// must be transmitted rather than dropped by omitempty: core requires
	// the fields and would reject an attachment missing them.
	payload, err := chat.EncryptMessage(EncryptMessageParams{
		SenderID:               "me",
		ConversationID:         "conv-1",
		ConversationKey:        v.conversationKey(t),
		Text:                   "attachment with zero dimensions",
		ConversationKeyVersion: "1",
		SigningKeyVersion:      "1",
		Attachments: []AttachmentDescriptor{
			{
				AttachmentType: "media",
				MediaHashKey:   "zerohash",
				Width:          0,
				Height:         0,
				FilesizeBytes:  0,
				Filename:       "voice.ogg",
			},
		},
	})
	if err != nil {
		t.Fatalf("EncryptMessage (zero-dimension media) failed: %v", err)
	}
	if payload.EncryptedContent == "" {
		t.Error("expected non-empty encrypted_content")
	}
}

func TestExportKeysIdentityOnly(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	identityOnly := v.privateKeys(t)[:32]
	if err := chat.ImportKeys(identityOnly); err != nil {
		t.Fatalf("ImportKeys (identity only) failed: %v", err)
	}

	// Identity-only sessions can export (32 bytes), matching core; only a
	// session with no identity key at all returns nil.
	exported, err := chat.ExportKeys()
	if err != nil {
		t.Fatalf("ExportKeys failed: %v", err)
	}
	if len(exported) != 32 {
		t.Fatalf("expected 32 exported bytes, got %d", len(exported))
	}
}

func TestPrepareGroupMembersChangeWithOptionalFields(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	ttl := int64(86400000)
	publicKeys := []PublicKeyInput{{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"}}
	prepared, err := chat.PrepareGroupMembersChange(GroupMembersChangeParams{
		SenderID:                "me",
		SigningKeyVersion:       "1",
		PublicKeys:              publicKeys,
		ConversationID:          "g123",
		NewMemberIDs:            []string{"user-new"},
		CurrentMemberIDs:        []string{"me"},
		CurrentAdminIDs:         []string{"me"},
		CurrentPendingMemberIDs: []string{"user-pending"},
		CurrentTitle:            "My Group Chat",
		CurrentAvatarURL:        "https://example.com/avatar.png",
		CurrentTTLMsec:          &ttl,
	})
	if err != nil {
		t.Fatalf("PrepareGroupMembersChange (optional fields) failed: %v", err)
	}
	// Two signed actions: the key change and the member add. The title lives
	// in the member-add payload (index 1).
	if len(prepared.ActionSignatures) != 2 || prepared.ActionSignatures[1].Signature == "" {
		t.Fatalf("expected 2 action signatures with a non-empty member-add signature, got %d", len(prepared.ActionSignatures))
	}
	if !strings.Contains(prepared.ActionSignatures[1].SignaturePayload, "My Group Chat") {
		t.Error("expected the title in the member-add signature payload")
	}
	// Unset screen-capture blocking signs as the trailing null sentinel.
	if !strings.HasSuffix(prepared.ActionSignatures[1].SignaturePayload, ",null") {
		t.Errorf("expected a trailing null screen-capture slot, got %q", prepared.ActionSignatures[1].SignaturePayload)
	}
}

func TestPrepareGroupMembersChangeScreenCaptureBlocking(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	enabled := true
	publicKeys := []PublicKeyInput{{UserID: "me", PublicKey: v.IdentityPublicB64, KeyVersion: "1"}}
	prepared, err := chat.PrepareGroupMembersChange(GroupMembersChangeParams{
		SenderID:                            "me",
		SigningKeyVersion:                   "1",
		PublicKeys:                          publicKeys,
		ConversationID:                      "g123",
		NewMemberIDs:                        []string{"user-new"},
		CurrentMemberIDs:                    []string{"me"},
		CurrentAdminIDs:                     []string{"me"},
		CurrentScreenCaptureBlockingEnabled: &enabled,
	})
	if err != nil {
		t.Fatalf("PrepareGroupMembersChange (screen capture) failed: %v", err)
	}
	// The group's screen-capture-blocking state fills the trailing signed slot.
	if !strings.HasSuffix(prepared.ActionSignatures[1].SignaturePayload, ",true") {
		t.Errorf("expected the signed payload to end with the screen-capture flag, got %q", prepared.ActionSignatures[1].SignaturePayload)
	}
	if prepared.ActionSignatures[1].EncodedMessageEventDetail == "" {
		t.Error("expected non-empty member-add encoded event detail")
	}
}

func TestStreamEncryptDecryptLargerPayload(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Create a larger payload (1KB of 'A's) to test streaming encryption
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = 'A'
	}

	encrypted, err := chat.EncryptStream(payload, v.conversationKey(t))
	if err != nil {
		t.Fatalf("EncryptStream (large) failed: %v", err)
	}

	decrypted, err := chat.DecryptStream(encrypted, v.conversationKey(t))
	if err != nil {
		t.Fatalf("DecryptStream (large) failed: %v", err)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Error("large stream roundtrip mismatch")
	}
}

func TestDecryptEventsWithSigningKeys(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Pass signing keys with empty events; should succeed
	signingKeys := []SigningKeyEntry{
		{
			UserID:           "me",
			PublicKeyVersion: "1",
			PublicKey:        v.SigningPublicB64,
		},
	}
	result, err := chat.DecryptEvents([]string{}, signingKeys)
	if err != nil {
		t.Fatalf("DecryptEvents (with signing keys) failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestEncryptMessageThenVerifySignature(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	payload, err := chat.EncryptMessage(EncryptMessageParams{
		SenderID:               "me",
		ConversationID:         "conv-1",
		ConversationKey:        v.conversationKey(t),
		Text:                   "verifiable message",
		ConversationKeyVersion: "1",
		SigningKeyVersion:      "1",
	})
	if err != nil {
		t.Fatalf("EncryptMessage failed: %v", err)
	}

	// SignatureInfo should have the versions we passed
	if payload.SignatureInfo.PublicKeyVersion == "" {
		t.Error("expected non-empty public_key_version in signature_info")
	}
	if payload.SignatureInfo.SignatureVersion == "" {
		t.Error("expected non-empty signature_version in signature_info")
	}
	if payload.EncodedEventSignature == "" {
		t.Error("expected non-empty encoded_event_signature")
	}
}

func TestEventUnmarshalAndTypeAccessors(t *testing.T) {
	// Test Event.UnmarshalJSON and AsMessage
	msgJSON := `{
		"type": "Message",
		"content": {
			"content_type": "Text",
			"text": "hello world"
		},
		"verified": true,
		"sender_id": "123",
		"conversation_id": "conv-1"
	}`
	var event Event
	if err := json.Unmarshal([]byte(msgJSON), &event); err != nil {
		t.Fatalf("Event.UnmarshalJSON failed: %v", err)
	}
	if event.Type != "Message" {
		t.Errorf("expected type 'Message', got %q", event.Type)
	}
	if event.Raw() == nil {
		t.Error("expected non-nil Raw()")
	}

	// AsMessage should work
	msg := event.AsMessage()
	if msg == nil {
		t.Fatal("AsMessage() returned nil for Message event")
	}
	if msg.Text() != "hello world" {
		t.Errorf("expected text 'hello world', got %q", msg.Text())
	}

	// AsKeyChange should return nil for a Message event
	if event.AsKeyChange() != nil {
		t.Error("AsKeyChange() should return nil for Message event")
	}
	// AsGroupChange should return nil for a Message event
	if event.AsGroupChange() != nil {
		t.Error("AsGroupChange() should return nil for Message event")
	}
}

func TestEventAsKeyChange(t *testing.T) {
	kcJSON := `{
		"type": "KeyChange",
		"key_version": "2",
		"sender_id": "user-1",
		"verified": true,
		"participant_keys": [
			{"user_id": "user-1", "encrypted_key": "abc123", "public_key_version": "1"},
			{"user_id": "user-2", "encrypted_key": "def456", "public_key_version": "1"}
		]
	}`
	var event Event
	if err := json.Unmarshal([]byte(kcJSON), &event); err != nil {
		t.Fatalf("Event.UnmarshalJSON (KeyChange) failed: %v", err)
	}
	if event.Type != "KeyChange" {
		t.Errorf("expected type 'KeyChange', got %q", event.Type)
	}

	kc := event.AsKeyChange()
	if kc == nil {
		t.Fatal("AsKeyChange() returned nil")
	}
	if kc.KeyVersion != "2" {
		t.Errorf("expected key_version '2', got %q", kc.KeyVersion)
	}
	if !kc.Verified {
		t.Error("expected verified == true on the typed KeyChangeEvent")
	}
	if len(kc.ParticipantKeys) != 2 {
		t.Fatalf("expected 2 participant keys, got %d", len(kc.ParticipantKeys))
	}

	// AsMessage should return nil for a KeyChange event
	if event.AsMessage() != nil {
		t.Error("AsMessage() should return nil for KeyChange event")
	}
}

func TestEventAsGroupChange(t *testing.T) {
	gcJSON := `{
		"type": "GroupChange",
		"sender_id": "admin-1",
		"verified": true,
		"change": {"action": "member_added", "user_id": "new-user"}
	}`
	var event Event
	if err := json.Unmarshal([]byte(gcJSON), &event); err != nil {
		t.Fatalf("Event.UnmarshalJSON (GroupChange) failed: %v", err)
	}
	if event.Type != "GroupChange" {
		t.Errorf("expected type 'GroupChange', got %q", event.Type)
	}

	gc := event.AsGroupChange()
	if gc == nil {
		t.Fatal("AsGroupChange() returned nil")
	}
	if gc.Change == nil {
		t.Error("expected non-nil Change")
	}
	if !gc.Verified {
		t.Error("expected verified == true on the typed GroupChangeEvent")
	}
}

func TestReadReceiptEventVerified(t *testing.T) {
	rrJSON := `{
		"type": "ReadReceipt",
		"sender_id": "user-1",
		"seen_until_id": "seq-77",
		"verified": true
	}`
	var rr ReadReceiptEvent
	if err := json.Unmarshal([]byte(rrJSON), &rr); err != nil {
		t.Fatalf("ReadReceiptEvent unmarshal failed: %v", err)
	}
	if !rr.Verified {
		t.Error("expected verified == true on the typed ReadReceiptEvent")
	}
	if rr.SeenUntilID == nil || *rr.SeenUntilID != "seq-77" {
		t.Errorf("unexpected seen_until_id: %v", rr.SeenUntilID)
	}
}

// TestDecryptEventsResultTypedMessages drives the same JSON decode path
// DecryptEvents uses and asserts batch messages carry the typed Event (with
// working accessors and raw JSON retained), matching DecryptEvent's shape.
func TestDecryptEventsResultTypedMessages(t *testing.T) {
	resultJSON := `{
		"messages": [
			{
				"event": {
					"type": "Message",
					"content": {"content_type": "Text", "text": "typed batch"},
					"verified": true
				},
				"original_b64": "b3JpZ2luYWw="
			}
		],
		"conversation_keys": {"keys": {}, "latest_version": null},
		"errors": {}
	}`
	var result DecryptEventsResult
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		t.Fatalf("DecryptEventsResult unmarshal failed: %v", err)
	}
	if len(result.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(result.Messages))
	}
	event := result.Messages[0].Event
	if event.Type != "Message" {
		t.Errorf("expected type 'Message', got %q", event.Type)
	}
	msg := event.AsMessage()
	if msg == nil {
		t.Fatal("AsMessage() returned nil for a batch-decrypted Message event")
	}
	if msg.Text() != "typed batch" {
		t.Errorf("expected text 'typed batch', got %q", msg.Text())
	}
	if !msg.Verified {
		t.Error("expected verified == true on the batch message")
	}
	if event.Raw() == nil {
		t.Error("expected the batch event to retain its raw JSON")
	}
	if result.Messages[0].OriginalB64 != "b3JpZ2luYWw=" {
		t.Errorf("unexpected original_b64: %q", result.Messages[0].OriginalB64)
	}
}

func TestMessageContentReaction(t *testing.T) {
	reactionJSON := `{
		"type": "Message",
		"content": {
			"content_type": "Reaction",
			"emoji": "\ud83d\udc4d",
			"target_message_id": "msg-42"
		},
		"verified": false
	}`
	var event Event
	if err := json.Unmarshal([]byte(reactionJSON), &event); err != nil {
		t.Fatalf("Event.UnmarshalJSON (Reaction) failed: %v", err)
	}
	msg := event.AsMessage()
	if msg == nil {
		t.Fatal("AsMessage() returned nil for Reaction event")
	}
	if msg.Content.ContentType != "Reaction" {
		t.Errorf("expected content_type 'Reaction', got %q", msg.Content.ContentType)
	}
	if msg.Content.ReactionContent == nil {
		t.Fatal("expected non-nil ReactionContent")
	}
	if msg.Content.ReactionContent.Emoji != "\U0001F44D" {
		t.Errorf("expected thumbs up emoji, got %q", msg.Content.ReactionContent.Emoji)
	}
	if msg.Content.ReactionContent.TargetMessageID != "msg-42" {
		t.Errorf("expected target_message_id 'msg-42', got %q", msg.Content.ReactionContent.TargetMessageID)
	}
	// Text() should return empty for a Reaction
	if msg.Text() != "" {
		t.Errorf("expected empty text for Reaction, got %q", msg.Text())
	}
}

func TestMessageContentReactionRemoved(t *testing.T) {
	rrJSON := `{
		"type": "Message",
		"content": {
			"content_type": "ReactionRemoved",
			"emoji": "\ud83d\udc4e",
			"target_message_id": "msg-99"
		},
		"verified": false
	}`
	var event Event
	if err := json.Unmarshal([]byte(rrJSON), &event); err != nil {
		t.Fatalf("Event.UnmarshalJSON (ReactionRemoved) failed: %v", err)
	}
	msg := event.AsMessage()
	if msg == nil {
		t.Fatal("AsMessage() returned nil")
	}
	if msg.Content.ContentType != "ReactionRemoved" {
		t.Errorf("expected content_type 'ReactionRemoved', got %q", msg.Content.ContentType)
	}
	if msg.Content.ReactionContent == nil {
		t.Fatal("expected non-nil ReactionContent for ReactionRemoved")
	}
}

func TestFindKeyForUser(t *testing.T) {
	kc := &KeyChangeEvent{
		KeyVersion: "3",
		ParticipantKeys: []ParticipantKey{
			{UserID: "user-a", EncryptedKey: "key-a", PublicKeyVersion: "1"},
			{UserID: "user-b", EncryptedKey: "key-b", PublicKeyVersion: "2"},
			{UserID: "user-c", EncryptedKey: "key-c", PublicKeyVersion: "1"},
		},
	}

	// Found
	pk := kc.FindKeyForUser("user-b")
	if pk == nil {
		t.Fatal("FindKeyForUser('user-b') returned nil")
	}
	if pk.EncryptedKey != "key-b" {
		t.Errorf("expected encrypted_key 'key-b', got %q", pk.EncryptedKey)
	}
	if pk.PublicKeyVersion != "2" {
		t.Errorf("expected public_key_version '2', got %q", pk.PublicKeyVersion)
	}

	// Not found
	pk = kc.FindKeyForUser("nonexistent")
	if pk != nil {
		t.Error("FindKeyForUser('nonexistent') should return nil")
	}
}

func TestExtractConversationKeysEmpty(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Extract from empty events list
	bundle, err := chat.ExtractConversationKeys([]string{})
	if err != nil {
		t.Fatalf("ExtractConversationKeys (empty) failed: %v", err)
	}
	if bundle == nil {
		t.Fatal("expected non-nil bundle")
	}
}

func TestExtractConversationKeysInvalid(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Malformed base64 events are skipped, not errored: the contract is a
	// non-nil bundle with no keys and no latest version.
	result, err := chat.ExtractConversationKeys([]string{"not-valid!!!"})
	if err != nil {
		t.Fatalf("ExtractConversationKeys must skip malformed events, got error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Keys) != 0 {
		t.Errorf("expected 0 keys for malformed input, got %d", len(result.Keys))
	}
	if result.LatestVersion != nil {
		t.Errorf("expected nil latest_version for malformed input, got %q", *result.LatestVersion)
	}
}

func TestNewEntityHelper(t *testing.T) {
	e := NewEntity(0, 5, "bold")
	if e[0] != 0 || e[1] != 5 || e[2] != "bold" {
		t.Errorf("NewEntity mismatch: got %v", e)
	}
}

func TestEventUnknownType(t *testing.T) {
	// An unknown event type should unmarshal without error
	unknownJSON := `{"type": "FutureEvent", "data": "something"}`
	var event Event
	if err := json.Unmarshal([]byte(unknownJSON), &event); err != nil {
		t.Fatalf("Event.UnmarshalJSON (unknown type) failed: %v", err)
	}
	if event.Type != "FutureEvent" {
		t.Errorf("expected type 'FutureEvent', got %q", event.Type)
	}
	// All typed accessors should return nil
	if event.AsMessage() != nil {
		t.Error("AsMessage should return nil for unknown type")
	}
	if event.AsKeyChange() != nil {
		t.Error("AsKeyChange should return nil for unknown type")
	}
	if event.AsGroupChange() != nil {
		t.Error("AsGroupChange should return nil for unknown type")
	}
	// Raw should still be available
	if event.Raw() == nil {
		t.Error("Raw() should be non-nil")
	}
}

// TestEncryptMessageSignatureVersionAndRoundtrip exercises the encrypt side of
// an end-to-end flow and pins the wire signature_version to "7".
//
// A full EncryptMessage -> DecryptEvent roundtrip is NOT feasible from the Go
// API: EncryptMessage returns a SendPayload (encrypted_content, signature,
// encoded_event_signature, signature_info, ...), but DecryptEvent consumes an
// opaque base64-encoded webhook event that the server frames around that
// payload. The Go binding exposes no constructor to assemble such an event from
// a SendPayload, so we assert the encrypt output shape instead and rely on
// Encrypt/Decrypt (see TestEncryptDecryptRoundtrip) for symmetric coverage.
func TestEncryptMessageSignatureVersionAndRoundtrip(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	payload, err := chat.EncryptMessage(EncryptMessageParams{
		SenderID:               "me",
		ConversationID:         "conv-1",
		ConversationKey:        v.conversationKey(t),
		Text:                   "version seven please",
		ConversationKeyVersion: "1",
		SigningKeyVersion:      "1",
	})
	if err != nil {
		t.Fatalf("EncryptMessage failed: %v", err)
	}
	if payload.EncryptedContent == "" {
		t.Error("expected non-empty encrypted_content")
	}
	if payload.Signature == "" {
		t.Error("expected non-empty signature")
	}
	if payload.EncodedEventSignature == "" {
		t.Error("expected non-empty encoded_event_signature")
	}
	if payload.ConversationKeyVersion != "1" {
		t.Errorf("expected conversation_key_version '1', got %q", payload.ConversationKeyVersion)
	}
	if payload.SignatureInfo.PublicKeyVersion != "1" {
		t.Errorf("expected signature_info.public_key_version '1', got %q", payload.SignatureInfo.PublicKeyVersion)
	}
	// signature_version is pinned to the current wire format.
	if payload.SignatureInfo.SignatureVersion != "7" {
		t.Errorf("expected signature_version '7', got %q", payload.SignatureInfo.SignatureVersion)
	}
}

// TestExtractConversationKeysEmptyResultShape verifies that ExtractConversationKeys
// returns a non-nil bundle with an empty key set for both an empty list and an
// unparseable event.
func TestExtractConversationKeysEmptyResultShape(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// Empty input: must yield a non-nil bundle carrying no keys.
	bundle, err := chat.ExtractConversationKeys([]string{})
	if err != nil {
		t.Fatalf("ExtractConversationKeys (empty) failed: %v", err)
	}
	if bundle == nil {
		t.Fatal("expected non-nil bundle for empty input")
	}
	if len(bundle.Keys) != 0 {
		t.Errorf("expected 0 keys for empty input, got %d", len(bundle.Keys))
	}
	if bundle.LatestVersion != nil {
		t.Errorf("expected nil latest_version for empty input, got %q", *bundle.LatestVersion)
	}

	// Garbage input: malformed events are skipped, yielding the same empty
	// bundle with no error.
	garbage, err := chat.ExtractConversationKeys([]string{"not-valid-base64!!!"})
	if err != nil {
		t.Fatalf("ExtractConversationKeys must skip malformed events, got error: %v", err)
	}
	if garbage == nil {
		t.Fatal("expected non-nil bundle for garbage input")
	}
	if len(garbage.Keys) != 0 {
		t.Errorf("expected 0 keys for garbage input, got %d", len(garbage.Keys))
	}
	if garbage.LatestVersion != nil {
		t.Errorf("expected nil latest_version for garbage input, got %q", *garbage.LatestVersion)
	}
}

// TestVerifyWithKeyFromGetPublicKeys signs bytes with the loaded key, fetches
// the signing public key via GetPublicKeys (rather than the fixture), and
// asserts Verify succeeds. A tampered signature must verify as false.
func TestVerifyWithKeyFromGetPublicKeys(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	keys, err := chat.GetPublicKeys()
	if err != nil {
		t.Fatalf("GetPublicKeys failed: %v", err)
	}
	if keys.Signing == "" {
		t.Fatal("expected non-empty signing public key")
	}

	data := []byte("verify me with the public key from GetPublicKeys")
	sig, err := chat.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty raw signature")
	}

	// Happy path: signature must verify against the reported signing key.
	valid, err := chat.Verify(keys.Signing, sig, data)
	if err != nil {
		t.Fatalf("Verify (valid) failed: %v", err)
	}
	if !valid {
		t.Error("expected valid signature to verify as true")
	}

	// Tampered signature: flip one byte of the raw signature, keeping the
	// same length, so verification must report false.
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xFF

	valid, err = chat.Verify(keys.Signing, tampered, data)
	if err != nil {
		t.Fatalf("Verify (tampered) failed: %v", err)
	}
	if valid {
		t.Error("expected tampered signature to verify as false")
	}
}

// TestDetectMimeTypeAndDimensionsJPEG covers the JPEG branch of the detectors
// (FF D8 FF magic + a minimal SOF0 header describing a 256x200 image).
func TestDetectMimeTypeAndDimensionsJPEG(t *testing.T) {
	// Minimal JPEG: SOI + SOF0 with width=256, height=200. >= 12 bytes so the
	// MIME detector (which needs >= 12 bytes) also accepts it.
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xC0, // SOF0
		0x00, 0x11, // segment length
		0x08,       // precision
		0x00, 0xC8, // height = 200
		0x01, 0x00, // width = 256
		0x03, // pad to satisfy parser bounds
	}

	mime, err := DetectMimeType(jpeg)
	if err != nil {
		t.Fatalf("DetectMimeType (jpeg): %v", err)
	}
	if mime != "image/jpeg" {
		t.Fatalf("DetectMimeType: got %q want image/jpeg", mime)
	}

	dims, err := DetectImageDimensions(jpeg)
	if err != nil {
		t.Fatalf("DetectImageDimensions (jpeg): %v", err)
	}
	if dims == nil || dims.Width != 256 || dims.Height != 200 {
		t.Fatalf("DetectImageDimensions (jpeg): got %+v want 256x200", dims)
	}

	// Hex roundtrip on a distinct byte sequence (parity with util coverage).
	hexStr, err := BytesToHex([]byte{0x00, 0x7f, 0x80, 0xff})
	if err != nil {
		t.Fatalf("BytesToHex: %v", err)
	}
	if hexStr != "007f80ff" {
		t.Fatalf("BytesToHex: got %q want 007f80ff", hexStr)
	}
	back, err := HexToBytes(hexStr)
	if err != nil {
		t.Fatalf("HexToBytes: %v", err)
	}
	if !bytes.Equal(back, []byte{0x00, 0x7f, 0x80, 0xff}) {
		t.Fatalf("hex roundtrip: got %v", back)
	}
}

// TestImportKeysWithVersion pins the one-call import + key-version path: the
// imported keys must match the fixture and invalid key material must error.
func TestImportKeysWithVersion(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()

	if err := chat.ImportKeysWithVersion([]byte{0x00}, "1"); err == nil {
		t.Error("expected an error for invalid key material")
	}

	if err := chat.ImportKeysWithVersion(v.privateKeys(t), v.EventRecipientKeyVersion); err != nil {
		t.Fatalf("ImportKeysWithVersion failed: %v", err)
	}
	if !chat.IsUnlocked() {
		t.Fatal("expected IsUnlocked() == true after ImportKeysWithVersion")
	}
	keys, err := chat.GetPublicKeys()
	if err != nil {
		t.Fatalf("GetPublicKeys failed: %v", err)
	}
	if keys.Identity != v.IdentityPublicB64 {
		t.Error("identity key mismatch after ImportKeysWithVersion")
	}
}

// TestSetIdentityResolvesEncryptDefaults drives the session-identity path:
// with SetIdentity, EncryptMessage needs no SenderID/SigningKeyVersion and
// signs with the session values; without any identity it must fail with an
// error naming the missing sender_id.
func TestSetIdentityResolvesEncryptDefaults(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeys(v.privateKeys(t)); err != nil {
		t.Fatalf("ImportKeys failed: %v", err)
	}

	// No session identity and no explicit sender: the error names the field.
	_, err := chat.EncryptMessage(EncryptMessageParams{
		ConversationID:         "conv-1",
		Text:                   "no identity",
		ConversationKey:        v.conversationKey(t),
		ConversationKeyVersion: "1",
	})
	if err == nil {
		t.Fatal("expected an error without a session identity")
	}
	if !strings.Contains(err.Error(), "sender_id") {
		t.Fatalf("expected the error to mention sender_id, got: %v", err)
	}

	if err := chat.SetIdentity(v.EventSenderID, v.EventSigningKeyVersion); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}
	payload, err := chat.EncryptMessage(EncryptMessageParams{
		ConversationID:         "conv-1",
		Text:                   "session identity",
		ConversationKey:        v.conversationKey(t),
		ConversationKeyVersion: "1",
	})
	if err != nil {
		t.Fatalf("EncryptMessage with session identity failed: %v", err)
	}
	if payload.SignatureInfo.PublicKeyVersion != v.EventSigningKeyVersion {
		t.Errorf("expected signature_info.public_key_version %q, got %q",
			v.EventSigningKeyVersion, payload.SignatureInfo.PublicKeyVersion)
	}
	if payload.MessageID == "" {
		t.Error("expected non-empty message_id")
	}
}

// TestSetCacheKeysResolvesConversationKey drives the opt-in key cache: after
// batch-decrypting the fixture key change, EncryptMessage needs no explicit
// conversation key and encrypts under the cached version; with the cache off
// the same call errors.
func TestSetCacheKeysResolvesConversationKey(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeysWithVersion(v.privateKeys(t), v.EventRecipientKeyVersion); err != nil {
		t.Fatalf("ImportKeysWithVersion failed: %v", err)
	}
	if err := chat.SetIdentity(v.EventSenderID, v.EventSigningKeyVersion); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}

	// Cache off (the default): omitting the key pair is an error.
	if _, err := chat.EncryptMessage(EncryptMessageParams{
		ConversationID: v.EventConversationID,
		Text:           "no key, cache off",
	}); err == nil {
		t.Fatal("expected an error with the key cache disabled")
	}

	chat.SetCacheKeys(true)
	result, err := chat.DecryptEvents([]string{v.EventKeyChangeB64}, v.eventSigningKeys())
	if err != nil {
		t.Fatalf("DecryptEvents failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected decrypt errors: %v", result.Errors)
	}

	payload, err := chat.EncryptMessage(EncryptMessageParams{
		ConversationID: v.EventConversationID,
		Text:           "cached key",
	})
	if err != nil {
		t.Fatalf("EncryptMessage with cached key failed: %v", err)
	}
	if payload.ConversationKeyVersion != v.EventConversationKeyVersion {
		t.Errorf("expected conversation_key_version %q, got %q",
			v.EventConversationKeyVersion, payload.ConversationKeyVersion)
	}

	// Disabling the cache clears it; the omitted key errors again.
	chat.SetCacheKeys(false)
	if _, err := chat.EncryptMessage(EncryptMessageParams{
		ConversationID: v.EventConversationID,
		Text:           "cache cleared",
	}); err == nil {
		t.Error("expected an error after disabling the key cache")
	}
}

// TestSetSigningKeysFallback drives the stored-signing-keys path: with keys
// stored via SetSigningKeys, both decrypt paths verify the fixture message
// with nil signing keys (and, for the single-event path, a nil conversation
// key map resolved from the opt-in cache).
func TestSetSigningKeysFallback(t *testing.T) {
	v := loadVectors(t)

	chat := New() // default reject-unverified policy
	defer chat.Close()
	if err := chat.ImportKeysWithVersion(v.privateKeys(t), v.EventRecipientKeyVersion); err != nil {
		t.Fatalf("ImportKeysWithVersion failed: %v", err)
	}
	chat.SetCacheKeys(true)
	if err := chat.SetSigningKeys(v.eventSigningKeys()); err != nil {
		t.Fatalf("SetSigningKeys failed: %v", err)
	}

	// Batch path: nil signing keys fall back to the stored set, so the
	// signed key change verifies and its key is adopted (and cached).
	result, err := chat.DecryptEvents([]string{v.EventKeyChangeB64}, nil)
	if err != nil {
		t.Fatalf("DecryptEvents failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected decrypt errors: %v", result.Errors)
	}

	// Single-event path: nil maps resolve from the session stores.
	event, err := chat.DecryptEvent(v.EventMessageB64, nil, nil)
	if err != nil {
		t.Fatalf("DecryptEvent failed: %v", err)
	}
	msg := event.AsMessage()
	if msg == nil {
		t.Fatalf("expected a Message event, got type %q", event.Type)
	}
	if msg.Text() != v.EventMessageText || !msg.Verified {
		t.Errorf("unexpected result: text=%q verified=%v", msg.Text(), msg.Verified)
	}
}

// TestReplyPreviewValidationFixtureVectors drives the reply-preview contract
// over the committed vectors: the honestly derived reply validates as
// "Valid" and the reply carrying a forged preview text as "Invalid".
func TestReplyPreviewValidationFixtureVectors(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeysWithVersion(v.privateKeys(t), v.EventRecipientKeyVersion); err != nil {
		t.Fatalf("ImportKeysWithVersion failed: %v", err)
	}

	result, err := chat.DecryptEvents(
		[]string{v.EventKeyChangeB64, v.EventReplyValidB64, v.EventReplyForgedB64},
		v.eventSigningKeys(),
	)
	if err != nil {
		t.Fatalf("DecryptEvents failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected decrypt errors: %v", result.Errors)
	}

	var replies []*Message
	for i := range result.Messages {
		if msg := result.Messages[i].Event.AsMessage(); msg != nil {
			replies = append(replies, msg)
		}
	}
	if len(replies) != 2 {
		t.Fatalf("expected 2 reply messages, got %d", len(replies))
	}
	// Batch results preserve input order: valid reply first, forged second.
	if replies[0].ReplyPreviewValidation != "Valid" {
		t.Errorf("expected the honest reply preview to be Valid, got %q", replies[0].ReplyPreviewValidation)
	}
	if replies[0].Text() != v.EventReplyText {
		t.Errorf("reply text mismatch:\ngot  %q\nwant %q", replies[0].Text(), v.EventReplyText)
	}
	if replies[1].ReplyPreviewValidation != "Invalid" {
		t.Errorf("expected the forged reply preview to be Invalid, got %q", replies[1].ReplyPreviewValidation)
	}
}

// TestEncryptReplyByEvent drives the preferred reply form: the raw signed
// original event is passed as ReplyToEvent and the SDK derives the preview
// from it (session identity, explicit fixture key).
func TestEncryptReplyByEvent(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeysWithVersion(v.privateKeys(t), v.EventRecipientKeyVersion); err != nil {
		t.Fatalf("ImportKeysWithVersion failed: %v", err)
	}
	if err := chat.SetIdentity(v.EventSenderID, v.EventSigningKeyVersion); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}

	payload, err := chat.EncryptReply(EncryptReplyParams{
		ConversationID:         v.EventConversationID,
		Text:                   "replying by raw event",
		ReplyToEvent:           v.EventMessageB64,
		ConversationKey:        v.conversationKey(t),
		ConversationKeyVersion: v.EventConversationKeyVersion,
	})
	if err != nil {
		t.Fatalf("EncryptReply by event failed: %v", err)
	}
	if payload.EncryptedContent == "" || payload.Signature == "" || payload.MessageID == "" {
		t.Errorf("incomplete payload: %+v", payload)
	}
}

// TestEncryptReactionByTargetEvent drives the preferred reaction form: the
// raw event is passed as TargetEvent and the SDK derives the conversation id
// and target sequence id from it. Neither the reply target nor the reaction
// target may be entirely absent.
func TestEncryptReactionByTargetEvent(t *testing.T) {
	v := loadVectors(t)

	chat := New()
	defer chat.Close()
	if err := chat.ImportKeysWithVersion(v.privateKeys(t), v.EventRecipientKeyVersion); err != nil {
		t.Fatalf("ImportKeysWithVersion failed: %v", err)
	}
	if err := chat.SetIdentity(v.EventSenderID, v.EventSigningKeyVersion); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}

	params := EncryptReactionParams{
		TargetEvent:            v.EventMessageB64,
		Emoji:                  "\U0001F44D",
		ConversationKey:        v.conversationKey(t),
		ConversationKeyVersion: v.EventConversationKeyVersion,
	}
	add, err := chat.EncryptAddReaction(params)
	if err != nil {
		t.Fatalf("EncryptAddReaction by target event failed: %v", err)
	}
	if add.EncryptedContent == "" || add.MessageID == "" {
		t.Errorf("incomplete add payload: %+v", add)
	}
	// The same params value serves the matching remove.
	if _, err := chat.EncryptRemoveReaction(params); err != nil {
		t.Fatalf("EncryptRemoveReaction by target event failed: %v", err)
	}

	// No target at all is an error naming the missing field.
	params.TargetEvent = ""
	if _, err := chat.EncryptAddReaction(params); err == nil {
		t.Error("expected an error without a reaction target")
	}
}
