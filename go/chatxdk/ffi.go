package chatxdk

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation -framework SystemConfiguration -lresolv
#include "chat_xdk.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

// helpers

func ffiResult(r C.struct_FfiResult) (string, error) {
	if r.error != nil {
		msg := C.GoString(r.error)
		C.chat_xdk_free_string(r.error)
		if r.data != nil {
			C.chat_xdk_free_string(r.data)
		}
		return "", errors.New(msg)
	}
	if r.data == nil {
		return "", nil
	}
	s := C.GoString(r.data)
	C.chat_xdk_free_string(r.data)
	return s, nil
}

// handle wraps the opaque C pointer so chat.go never references C directly.
type handle = *C.struct_ChatHandle

// utilities (stateless; no Chat handle)

func ffiBytesToBase64(data []byte) (string, error) {
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	return ffiResult(C.chat_xdk_bytes_to_base64(ptr, C.uintptr_t(len(data))))
}

func ffiBase64ToBytes(b64 string) (string, error) {
	c := C.CString(b64)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_base64_to_bytes(c))
}

func ffiBytesToHex(data []byte) (string, error) {
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	return ffiResult(C.chat_xdk_bytes_to_hex(ptr, C.uintptr_t(len(data))))
}

func ffiHexToBytes(hex string) (string, error) {
	c := C.CString(hex)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_hex_to_bytes(c))
}

func ffiDetectMimeType(data []byte) (string, error) {
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	return ffiResult(C.chat_xdk_detect_mime_type(ptr, C.uintptr_t(len(data))))
}

func ffiDetectImageDimensions(data []byte) (string, error) {
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	return ffiResult(C.chat_xdk_detect_image_dimensions(ptr, C.uintptr_t(len(data))))
}

// lifecycle / state

func ffiNew() handle {
	return C.chat_xdk_new()
}

func ffiFree(h handle) {
	C.chat_xdk_free(h)
}

func ffiIsUnlocked(h handle) int {
	return int(C.chat_xdk_is_unlocked(h))
}

func ffiHasIdentityKey(h handle) int {
	return int(C.chat_xdk_has_identity_key(h))
}

func ffiSetRejectUnverified(h handle, reject bool) {
	v := C.int(0)
	if reject {
		v = 1
	}
	C.chat_xdk_set_reject_unverified(h, v)
}

func ffiSetIdentity(h handle, userID, signingKeyVersion string) error {
	cU := C.CString(userID)
	defer C.free(unsafe.Pointer(cU))
	cV := C.CString(signingKeyVersion)
	defer C.free(unsafe.Pointer(cV))
	_, err := ffiResult(C.chat_xdk_set_identity(h, cU, cV))
	return err
}

func ffiSetCacheKeys(h handle, enabled bool) {
	v := C.int(0)
	if enabled {
		v = 1
	}
	C.chat_xdk_set_cache_keys(h, v)
}

func ffiSetSigningKeys(h handle, signingKeysJSON string) error {
	c := C.CString(signingKeysJSON)
	defer C.free(unsafe.Pointer(c))
	_, err := ffiResult(C.chat_xdk_set_signing_keys(h, c))
	return err
}

func ffiLock(h handle) {
	C.chat_xdk_lock(h)
}

// key management

func ffiGenerateKeypairs(h handle) (string, error) {
	return ffiResult(C.chat_xdk_generate_keypairs(h))
}

func ffiGetPublicKeys(h handle) (string, error) {
	return ffiResult(C.chat_xdk_get_public_keys(h))
}

func ffiGetPublicKeyFingerprint(h handle) (string, error) {
	return ffiResult(C.chat_xdk_get_public_key_fingerprint(h))
}

func ffiExportKeys(h handle) (string, error) {
	return ffiResult(C.chat_xdk_export_keys(h))
}

// ffiImportKeys takes the base64 key material as a NUL-terminated byte buffer
// and passes its pointer straight to C (cgo pins it for the call), instead of
// C.CString, so the caller can wipe the only transport copy of the secret.
func ffiImportKeys(h handle, keysB64z []byte) (string, error) {
	return ffiResult(C.chat_xdk_import_keys(h, (*C.char)(unsafe.Pointer(&keysB64z[0]))))
}

// ffiImportKeysWithVersion passes the raw private key bytes straight to C
// (cgo pins them for the call) — no base64 transport copy, so the caller's
// slice remains the only copy to wipe.
func ffiImportKeysWithVersion(h handle, keys []byte, version string) (string, error) {
	var ptr *C.uint8_t
	if len(keys) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&keys[0]))
	}
	cV := C.CString(version)
	defer C.free(unsafe.Pointer(cV))
	return ffiResult(C.chat_xdk_import_keys_with_version(h, ptr, C.uintptr_t(len(keys)), cV))
}

// conversation keys

func ffiDecryptConversationKey(h handle, encKeyB64 string) (string, error) {
	c := C.CString(encKeyB64)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_decrypt_conversation_key(h, c))
}

func ffiExtractConversationKeys(h handle, eventsJSON string) (string, error) {
	c := C.CString(eventsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_extract_conversation_keys(h, c))
}

func ffiDecryptEvents(h handle, eventsJSON, signingKeysJSON string) (string, error) {
	c1 := C.CString(eventsJSON)
	defer C.free(unsafe.Pointer(c1))
	c2 := C.CString(signingKeysJSON)
	defer C.free(unsafe.Pointer(c2))
	return ffiResult(C.chat_xdk_decrypt_events(h, c1, c2))
}

func ffiPrepareConversationKeyChange(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_conversation_key_change(h, c))
}

func ffiPrepareGroupMembersChange(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_members_change(h, c))
}

func ffiPrepareGroupCreate(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_create(h, c))
}

func ffiPrepareMessageDelete(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_message_delete(h, c))
}

// decrypt

func ffiDecryptEvent(h handle, eventB64, convKeysJSON, signingKeysJSON string) (string, error) {
	cEv := C.CString(eventB64)
	defer C.free(unsafe.Pointer(cEv))
	cConvKeys := C.CString(convKeysJSON)
	defer C.free(unsafe.Pointer(cConvKeys))
	cSigningKeys := C.CString(signingKeysJSON)
	defer C.free(unsafe.Pointer(cSigningKeys))
	return ffiResult(C.chat_xdk_decrypt_event(h, cEv, cConvKeys, cSigningKeys))
}

func ffiDecryptStream(h handle, encB64, ckeyB64 string) (string, error) {
	cEnc := C.CString(encB64)
	defer C.free(unsafe.Pointer(cEnc))
	cKey := C.CString(ckeyB64)
	defer C.free(unsafe.Pointer(cKey))
	return ffiResult(C.chat_xdk_decrypt_stream(h, cEnc, cKey))
}

// encrypt

func ffiEncryptMessage(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_encrypt_message(h, c))
}

func ffiEncryptReply(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_encrypt_reply(h, c))
}

func ffiEncryptAddReaction(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_encrypt_add_reaction(h, c))
}

func ffiEncryptRemoveReaction(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_encrypt_remove_reaction(h, c))
}

func ffiEncryptEdit(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_encrypt_edit(h, c))
}

func ffiEncryptStream(h handle, plaintextB64, ckeyB64 string) (string, error) {
	cPT := C.CString(plaintextB64)
	defer C.free(unsafe.Pointer(cPT))
	cKey := C.CString(ckeyB64)
	defer C.free(unsafe.Pointer(cKey))
	return ffiResult(C.chat_xdk_encrypt_stream(h, cPT, cKey))
}

// incremental streaming

type streamEncryptorHandle = *C.struct_StreamEncryptorHandle
type streamDecryptorHandle = *C.struct_StreamDecryptorHandle

func ffiStreamEncryptorNew(ckeyB64 string) streamEncryptorHandle {
	c := C.CString(ckeyB64)
	defer C.free(unsafe.Pointer(c))
	return C.chat_xdk_stream_encryptor_new(c)
}

func ffiStreamEncryptorPush(h streamEncryptorHandle, plaintextB64 string) (string, error) {
	c := C.CString(plaintextB64)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_stream_encryptor_push(h, c))
}

func ffiStreamEncryptorFinish(h streamEncryptorHandle) (string, error) {
	return ffiResult(C.chat_xdk_stream_encryptor_finish(h))
}

func ffiStreamEncryptorFree(h streamEncryptorHandle) {
	C.chat_xdk_stream_encryptor_free(h)
}

func ffiStreamDecryptorNew(ckeyB64 string) streamDecryptorHandle {
	c := C.CString(ckeyB64)
	defer C.free(unsafe.Pointer(c))
	return C.chat_xdk_stream_decryptor_new(c)
}

func ffiStreamDecryptorPush(h streamDecryptorHandle, ciphertextB64 string) (string, error) {
	c := C.CString(ciphertextB64)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_stream_decryptor_push(h, c))
}

func ffiStreamDecryptorFinish(h streamDecryptorHandle) (string, error) {
	return ffiResult(C.chat_xdk_stream_decryptor_finish(h))
}

func ffiStreamDecryptorFree(h streamDecryptorHandle) {
	C.chat_xdk_stream_decryptor_free(h)
}

func ffiEncrypt(h handle, plaintext, ckeyB64 string) (string, error) {
	cPlain := C.CString(plaintext)
	defer C.free(unsafe.Pointer(cPlain))
	cKey := C.CString(ckeyB64)
	defer C.free(unsafe.Pointer(cKey))
	return ffiResult(C.chat_xdk_encrypt(h, cPlain, cKey))
}

func ffiDecrypt(h handle, ciphertextB64, ckeyB64 string) (string, error) {
	cCipher := C.CString(ciphertextB64)
	defer C.free(unsafe.Pointer(cCipher))
	cKey := C.CString(ckeyB64)
	defer C.free(unsafe.Pointer(cKey))
	return ffiResult(C.chat_xdk_decrypt(h, cCipher, cKey))
}

// sign / verify

func ffiSign(h handle, data []byte) (string, error) {
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	return ffiResult(C.chat_xdk_sign(h, ptr, C.uintptr_t(len(data))))
}

func ffiVerify(h handle, pkB64, sigB64 string, data []byte) (int, error) {
	cPK := C.CString(pkB64)
	defer C.free(unsafe.Pointer(cPK))
	cSig := C.CString(sigB64)
	defer C.free(unsafe.Pointer(cSig))
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	rc := int(C.chat_xdk_verify(h, cPK, cSig, ptr, C.uintptr_t(len(data))))
	return rc, nil
}

func ffiVerifyKeyBinding(h handle, identityB64, signingB64, signatureB64 string) int {
	cIdentity := C.CString(identityB64)
	defer C.free(unsafe.Pointer(cIdentity))
	cSigning := C.CString(signingB64)
	defer C.free(unsafe.Pointer(cSigning))
	cSig := C.CString(signatureB64)
	defer C.free(unsafe.Pointer(cSig))
	return int(C.chat_xdk_verify_key_binding(h, cIdentity, cSigning, cSig))
}

func ffiMatchesRegisteredKey(h handle, publicKeyB64 string) int {
	cPK := C.CString(publicKeyB64)
	defer C.free(unsafe.Pointer(cPK))
	return int(C.chat_xdk_matches_registered_key(h, cPK))
}
