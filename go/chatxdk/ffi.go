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

func ffiEncryptedFileSize(plaintextSize uint64) (string, error) {
	return ffiResult(C.chat_xdk_encrypted_file_size(C.uint64_t(plaintextSize)))
}

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

func ffiDecryptEvents(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_decrypt_events(h, c))
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

func ffiPrepareMarkConversationRead(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_mark_conversation_read(h, c))
}

// decrypt

func ffiDecryptEvent(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_decrypt_event(h, c))
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

// files

func ffiEncryptFile(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_encrypt_file(h, c))
}

func ffiDecryptFile(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_decrypt_file(h, c))
}

type fileEncryptorHandle = *C.struct_FileEncryptorHandle
type fileDecryptorHandle = *C.struct_FileDecryptorHandle

func ffiFileEncryptorNew(h handle, paramsJSON string) (fileEncryptorHandle, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	var out fileEncryptorHandle
	if _, err := ffiResult(C.chat_xdk_file_encryptor_new(h, c, &out)); err != nil {
		return nil, err
	}
	return out, nil
}

func ffiFileEncryptorPush(h fileEncryptorHandle, plaintextB64 string) (string, error) {
	c := C.CString(plaintextB64)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_file_encryptor_push(h, c))
}

func ffiFileEncryptorFinish(h fileEncryptorHandle) (string, error) {
	return ffiResult(C.chat_xdk_file_encryptor_finish(h))
}

func ffiFileEncryptorFree(h fileEncryptorHandle) {
	C.chat_xdk_file_encryptor_free(h)
}

func ffiFileDecryptorNew(h handle, paramsJSON string) (fileDecryptorHandle, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	var out fileDecryptorHandle
	if _, err := ffiResult(C.chat_xdk_file_decryptor_new(h, c, &out)); err != nil {
		return nil, err
	}
	return out, nil
}

func ffiFileDecryptorPush(h fileDecryptorHandle, ciphertextB64 string) (string, error) {
	c := C.CString(ciphertextB64)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_file_decryptor_push(h, c))
}

func ffiFileDecryptorFinish(h fileDecryptorHandle) (string, error) {
	return ffiResult(C.chat_xdk_file_decryptor_finish(h))
}

func ffiFileDecryptorFree(h fileDecryptorHandle) {
	C.chat_xdk_file_decryptor_free(h)
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
