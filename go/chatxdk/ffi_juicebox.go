//go:build !nojuicebox

package chatxdk

/*
#include "chat_xdk.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"
import "unsafe"

// cPin copies PIN bytes into a NUL-terminated C buffer. The buffer holds
// secret material: release it with freePin, which wipes it before freeing,
// so the transient C copy does not linger on the heap.
func cPin(pin []byte) *C.char {
	buf := C.malloc(C.size_t(len(pin) + 1))
	if buf == nil {
		panic("chatxdk: C.malloc failed")
	}
	if len(pin) > 0 {
		C.memcpy(buf, unsafe.Pointer(&pin[0]), C.size_t(len(pin)))
	}
	*(*C.char)(unsafe.Pointer(uintptr(buf) + uintptr(len(pin)))) = 0
	return (*C.char)(buf)
}

func freePin(p *C.char, n int) {
	C.memset(unsafe.Pointer(p), 0, C.size_t(n))
	C.free(unsafe.Pointer(p))
}

func ffiUpdateConfig(h handle, configJSON string) (string, error) {
	cCfg := C.CString(configJSON)
	defer C.free(unsafe.Pointer(cCfg))
	return ffiResult(C.chat_xdk_update_config(h, cCfg))
}

func ffiSetup(h handle, pin []byte, configJSON string) (string, error) {
	cPinBuf := cPin(pin)
	defer freePin(cPinBuf, len(pin))
	cCfg := C.CString(configJSON)
	defer C.free(unsafe.Pointer(cCfg))
	return ffiResult(C.chat_xdk_setup(h, cPinBuf, cCfg))
}

func ffiUnlock(h handle, pin []byte, configJSON string) (string, error) {
	cPinBuf := cPin(pin)
	defer freePin(cPinBuf, len(pin))
	cCfg := C.CString(configJSON)
	defer C.free(unsafe.Pointer(cCfg))
	return ffiResult(C.chat_xdk_unlock(h, cPinBuf, cCfg))
}

func ffiDelete(h handle) (string, error) {
	return ffiResult(C.chat_xdk_delete(h))
}

func ffiChangePin(h handle, oldPin, newPin []byte) (string, error) {
	cOld := cPin(oldPin)
	defer freePin(cOld, len(oldPin))
	cNew := cPin(newPin)
	defer freePin(cNew, len(newPin))
	return ffiResult(C.chat_xdk_change_pin(h, cOld, cNew))
}
