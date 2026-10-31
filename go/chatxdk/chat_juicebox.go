//go:build !nojuicebox

package chatxdk

import (
	"encoding/json"
	"runtime"
)

// NewWithJuiceboxConfig creates a Chat that keeps its keys in Juicebox, with
// the Juicebox configuration JSON the X API returns. Setup, Unlock,
// ChangePin and Delete use it; UpdateConfig replaces it. An empty or blank
// configJSON returns the ErrorKindInvalidState error a chat without a config
// gives those calls; New creates a chat without one. Like New, it reads the
// X API's feature switches in the background and keeps them current.
//
// The returned Chat must be freed with Close() when no longer needed.
func NewWithJuiceboxConfig(configJSON string) (*Chat, error) {
	c, err := newChat(&configJSON)
	if err != nil {
		return nil, err
	}
	c.startFeatures()
	return c, nil
}

// UpdateConfig sets or replaces the Juicebox configuration: on first boot,
// for a chat created with New, or to refresh its auth tokens. Until a chat
// has one, Setup, Unlock, ChangePin and Delete return an error of kind
// ErrorKindInvalidState.
func (c *Chat) UpdateConfig(configJSON string) error {
	defer runtime.KeepAlive(c)
	_, err := ffiUpdateConfig(c.h, configJSON)
	return err
}

// Setup registers the loaded keys with Juicebox under pin (first-time
// setup). The PIN is passed as bytes, which the SDK never copies to a
// string, so callers can zero their buffer after the call.
func (c *Chat) Setup(pin []byte) (*PublicKeys, error) {
	defer runtime.KeepAlive(c)
	data, err := ffiSetup(c.h, pin)
	if err != nil {
		return nil, err
	}
	var keys PublicKeys
	if err := json.Unmarshal([]byte(data), &keys); err != nil {
		return nil, err
	}
	return &keys, nil
}

// Unlock recovers keys from Juicebox using the user's PIN. The PIN is
// passed as bytes, which the SDK never copies to a string, so callers can
// zero their buffer after the call. A wrong PIN fails with an *Error of
// kind ErrorKindInvalidPin.
func (c *Chat) Unlock(pin []byte) error {
	defer runtime.KeepAlive(c)
	_, err := ffiUnlock(c.h, pin)
	return err
}

// Delete removes keys from Juicebox and clears them from memory.
// Warning: This is irreversible. The user will lose access to their encrypted messages.
func (c *Chat) Delete() error {
	defer runtime.KeepAlive(c)
	_, err := ffiDelete(c.h)
	return err
}

// ChangePin changes the PIN protecting keys in Juicebox, unlocking with the
// old PIN first. Both PINs are passed as bytes so callers can zero their
// buffers after the call.
func (c *Chat) ChangePin(oldPin, newPin []byte) error {
	defer runtime.KeepAlive(c)
	_, err := ffiChangePin(c.h, oldPin, newPin)
	return err
}
