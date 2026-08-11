//go:build !nojuicebox

package chatxdk

import (
	"encoding/json"
	"regexp"
	"runtime"
	"strconv"
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

// Stable invalid-PIN message form the core emits
// ("Invalid PIN: guesses_remaining=N"). Anchored on the full form so a count
// embedded in an unrelated pass-through message is not misread.
var guessesRemainingPattern = regexp.MustCompile(`\bInvalid PIN: guesses_remaining=(\d+)`)

// GuessesRemaining extracts the remaining PIN-attempt count Juicebox reports
// on an invalid-PIN [Chat.Unlock] / [Chat.ChangePin] failure. It returns
// ok=false when the error carries no count (any non-PIN failure). A count of
// 0 means the guess budget is exhausted and the stored keys are locked.
func GuessesRemaining(err error) (n int, ok bool) {
	if err == nil {
		return 0, false
	}
	m := guessesRemainingPattern.FindStringSubmatch(err.Error())
	if m == nil {
		return 0, false
	}
	n, convErr := strconv.Atoi(m[1])
	if convErr != nil {
		return 0, false
	}
	return n, true
}
