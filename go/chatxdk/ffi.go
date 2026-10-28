package chatxdk

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation -framework SystemConfiguration -lresolv
#include "chat_xdk.h"
#include <stdlib.h>

// Internal entry points for this package's feature switches. They are left
// out of chat_xdk.h because they are not part of the C API.
struct FfiResult chat_xdk_internal_feature_start(const struct ChatHandle *handle);
void chat_xdk_internal_feature_complete(uint64_t id,
                                        int32_t status,
                                        const uint8_t *body,
                                        uintptr_t body_len);
struct FfiResult chat_xdk_internal_feature_configure(const struct ChatHandle *handle,
                                                     const char *endpoint,
                                                     uint64_t timeout_ms);
struct FfiResult chat_xdk_internal_feature_set_default_endpoint(const char *endpoint);
*/
import "C"
import (
	"time"
	"unsafe"
)

// helpers

func ffiResult(r C.struct_FfiResult) (string, error) {
	if r.error != nil {
		document := C.GoString(r.error)
		C.chat_xdk_free_string(r.error)
		if r.data != nil {
			C.chat_xdk_free_string(r.data)
		}
		return "", errorFromDocument(document)
	}
	if r.data == nil {
		return "", nil
	}
	s := C.GoString(r.data)
	C.chat_xdk_free_string(r.data)
	return s, nil
}

// ffiBool reads a result whose data is `true` or `false`.
func ffiBool(r C.struct_FfiResult) (bool, error) {
	data, err := ffiResult(r)
	return data == "true", err
}

// bytesPtr points C at a slice's bytes (cgo pins them for the call), or is
// NULL for an empty slice.
func bytesPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
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

func ffiNew(juiceboxConfigJSON *string) (handle, error) {
	var cfg *C.char
	if juiceboxConfigJSON != nil {
		cfg = C.CString(*juiceboxConfigJSON)
		defer C.free(unsafe.Pointer(cfg))
	}
	var out handle
	if _, err := ffiResult(C.chat_xdk_new(cfg, &out)); err != nil {
		return nil, err
	}
	return out, nil
}

func ffiFree(h handle) {
	C.chat_xdk_free(h)
}

func ffiIsUnlocked(h handle) (bool, error) {
	return ffiBool(C.chat_xdk_is_unlocked(h))
}

func ffiHasIdentityKey(h handle) (bool, error) {
	return ffiBool(C.chat_xdk_has_identity_key(h))
}

func ffiSetRejectUnverified(h handle, reject bool) error {
	v := C.int32_t(0)
	if reject {
		v = 1
	}
	_, err := ffiResult(C.chat_xdk_set_reject_unverified(h, v))
	return err
}

func ffiSetIdentity(h handle, paramsJSON string) error {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	_, err := ffiResult(C.chat_xdk_set_identity(h, c))
	return err
}

func ffiSetCacheKeys(h handle, enabled bool) error {
	v := C.int32_t(0)
	if enabled {
		v = 1
	}
	_, err := ffiResult(C.chat_xdk_set_cache_keys(h, v))
	return err
}

// ffiFeatureStart starts the chat's one read of the feature switches and
// returns the GET to perform as JSON, or "" when there is none to perform.
func ffiFeatureStart(h handle) (string, error) {
	return ffiResult(C.chat_xdk_internal_feature_start(h))
}

func ffiFeatureComplete(id uint64, status int, body []byte) {
	var p *C.uint8_t
	if len(body) > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&body[0]))
	}
	C.chat_xdk_internal_feature_complete(C.uint64_t(id), C.int32_t(status), p, C.uintptr_t(len(body)))
}

func ffiFeatureConfigure(h handle, endpoint string, timeout time.Duration) error {
	c := C.CString(endpoint)
	defer C.free(unsafe.Pointer(c))
	_, err := ffiResult(C.chat_xdk_internal_feature_configure(h, c, C.uint64_t(timeout.Milliseconds())))
	return err
}

// ffiFeatureSetDefaultEndpoint sets the endpoint of every chat that does not
// set its own; "" for the X API's.
func ffiFeatureSetDefaultEndpoint(endpoint string) error {
	if endpoint == "" {
		_, err := ffiResult(C.chat_xdk_internal_feature_set_default_endpoint(nil))
		return err
	}
	c := C.CString(endpoint)
	defer C.free(unsafe.Pointer(c))
	_, err := ffiResult(C.chat_xdk_internal_feature_set_default_endpoint(c))
	return err
}

func ffiSetSigningKeys(h handle, signingKeysJSON string) error {
	c := C.CString(signingKeysJSON)
	defer C.free(unsafe.Pointer(c))
	_, err := ffiResult(C.chat_xdk_set_signing_keys(h, c))
	return err
}

func ffiLock(h handle) error {
	_, err := ffiResult(C.chat_xdk_lock(h))
	return err
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

// ffiImportKeys passes the raw private key bytes straight to C (cgo pins
// them for the call), so the caller's slice remains the only copy to wipe;
// only the signing-key version travels as JSON.
func ffiImportKeys(h handle, keys []byte, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_import_keys(h, bytesPtr(keys), C.uintptr_t(len(keys)), c))
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

func ffiPrepareGroupMembersRemove(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_members_remove(h, c))
}

func ffiPrepareGroupLeave(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_leave(h, c))
}

func ffiPrepareGroupTitleChange(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_title_change(h, c))
}

func ffiPrepareGroupAvatarChange(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_avatar_change(h, c))
}

func ffiPrepareGroupDescriptionChange(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_description_change(h, c))
}

func ffiPrepareGroupAdminsAdd(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_admins_add(h, c))
}

func ffiPrepareGroupAdminsRemove(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_admins_remove(h, c))
}

func ffiPrepareGroupInviteEnable(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_invite_enable(h, c))
}

func ffiPrepareGroupInviteDisable(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_invite_disable(h, c))
}

func ffiPrepareGroupJoinRequest(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_join_request(h, c))
}

func ffiPrepareGroupJoinReject(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_group_join_reject(h, c))
}

func ffiPrepareMessageTtlChange(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_message_ttl_change(h, c))
}

func ffiPrepareMessageTtlRemove(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_message_ttl_remove(h, c))
}

func ffiPrepareScreenCapture(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_prepare_screen_capture(h, c))
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

func ffiEncryptFileWithKey(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_encrypt_file_with_key(h, c))
}

func ffiDecryptFileWithKey(h handle, paramsJSON string) (string, error) {
	c := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(c))
	return ffiResult(C.chat_xdk_decrypt_file_with_key(h, c))
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

func ffiVerify(h handle, pkB64, sigB64 string, data []byte) (bool, error) {
	cPK := C.CString(pkB64)
	defer C.free(unsafe.Pointer(cPK))
	cSig := C.CString(sigB64)
	defer C.free(unsafe.Pointer(cSig))
	return ffiBool(C.chat_xdk_verify(h, cPK, cSig, bytesPtr(data), C.uintptr_t(len(data))))
}

func ffiVerifyKeyBinding(h handle, identityB64, signingB64, signatureB64 string) (bool, error) {
	cIdentity := C.CString(identityB64)
	defer C.free(unsafe.Pointer(cIdentity))
	cSigning := C.CString(signingB64)
	defer C.free(unsafe.Pointer(cSigning))
	cSig := C.CString(signatureB64)
	defer C.free(unsafe.Pointer(cSig))
	return ffiBool(C.chat_xdk_verify_key_binding(h, cIdentity, cSigning, cSig))
}

func ffiMatchesRegisteredKey(h handle, publicKeyB64 string) (bool, error) {
	cPK := C.CString(publicKeyB64)
	defer C.free(unsafe.Pointer(cPK))
	return ffiBool(C.chat_xdk_matches_registered_key(h, cPK))
}
