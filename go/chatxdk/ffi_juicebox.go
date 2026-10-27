//go:build !nojuicebox

package chatxdk

/*
#cgo CFLAGS: -DCHAT_XDK_JUICEBOX
#include "chat_xdk.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

func ffiUpdateConfig(h handle, configJSON string) (string, error) {
	cCfg := C.CString(configJSON)
	defer C.free(unsafe.Pointer(cCfg))
	return ffiResult(C.chat_xdk_update_config(h, cCfg))
}

// The PINs go to C as pointers into the caller's slices (cgo pins them for
// the call), so no copy of a PIN is left on the C heap.

func ffiSetup(h handle, pin []byte) (string, error) {
	return ffiResult(C.chat_xdk_setup(h, bytesPtr(pin), C.uintptr_t(len(pin))))
}

func ffiUnlock(h handle, pin []byte) (string, error) {
	return ffiResult(C.chat_xdk_unlock(h, bytesPtr(pin), C.uintptr_t(len(pin))))
}

func ffiDelete(h handle) (string, error) {
	return ffiResult(C.chat_xdk_delete(h))
}

func ffiChangePin(h handle, oldPin, newPin []byte) (string, error) {
	return ffiResult(C.chat_xdk_change_pin(
		h,
		bytesPtr(oldPin), C.uintptr_t(len(oldPin)),
		bytesPtr(newPin), C.uintptr_t(len(newPin)),
	))
}
