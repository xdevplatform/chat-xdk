//go:build !nojuicebox

package chatxdk

import (
	"encoding/json"
	"runtime"
)

// UpdateConfig updates the Juicebox configuration (e.g., to refresh auth tokens).
func (c *Chat) UpdateConfig(configJSON string) error {
	defer runtime.KeepAlive(c)
	_, err := ffiUpdateConfig(c.h, configJSON)
	return err
}

// Setup registers existing keys with Juicebox (first-time setup).
// The PIN is passed as bytes so callers can zero their own buffer after the
// call; the copy handed to the native layer is wiped internally.
func (c *Chat) Setup(pin []byte, configJSON string) (*PublicKeys, error) {
	defer runtime.KeepAlive(c)
	data, err := ffiSetup(c.h, pin, configJSON)
	if err != nil {
		return nil, err
	}
	var keys PublicKeys
	if err := json.Unmarshal([]byte(data), &keys); err != nil {
		return nil, err
	}
	return &keys, nil
}

// Unlock recovers keys from Juicebox using the user's PIN.
// The PIN is passed as bytes so callers can zero their own buffer after the
// call; the copy handed to the native layer is wiped internally.
func (c *Chat) Unlock(pin []byte, configJSON string) error {
	defer runtime.KeepAlive(c)
	_, err := ffiUnlock(c.h, pin, configJSON)
	return err
}

// Delete removes keys from Juicebox and clears them from memory.
// Warning: This is irreversible. The user will lose access to their encrypted messages.
func (c *Chat) Delete() error {
	defer runtime.KeepAlive(c)
	_, err := ffiDelete(c.h)
	return err
}

// ChangePin changes the PIN protecting keys in Juicebox.
// Must be unlocked first with the old PIN. Both PINs are passed as bytes so
// callers can zero their own buffers after the call.
func (c *Chat) ChangePin(oldPin, newPin []byte) error {
	defer runtime.KeepAlive(c)
	_, err := ffiChangePin(c.h, oldPin, newPin)
	return err
}
