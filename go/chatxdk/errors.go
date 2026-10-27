package chatxdk

import "encoding/json"

// ErrorKind says what kind of failure an *Error is. Every binding reports
// the same kind for the same failure.
type ErrorKind string

const (
	// ErrorKindInvalidInput: a parameter is missing or invalid; the message
	// names it.
	ErrorKindInvalidInput ErrorKind = "invalid_input"
	// ErrorKindInvalidState: a value was neither passed nor available from
	// the chat's state, such as no keys loaded or no session identity.
	ErrorKindInvalidState ErrorKind = "invalid_state"
	// ErrorKindParse: event or other wire data is malformed.
	ErrorKindParse ErrorKind = "parse"
	// ErrorKindDecryption: ciphertext did not decrypt, or no key for it was
	// available.
	ErrorKindDecryption ErrorKind = "decryption"
	// ErrorKindVerification: a signature did not verify, or could not be
	// verified while unverified events are rejected.
	ErrorKindVerification ErrorKind = "verification"
	// ErrorKindInvalidPin: Juicebox rejected the PIN; GuessesRemaining
	// holds the attempts left when Juicebox reports them.
	ErrorKindInvalidPin ErrorKind = "invalid_pin"
	// ErrorKindJuicebox: another Juicebox key-storage failure.
	ErrorKindJuicebox ErrorKind = "juicebox"
	// ErrorKindInternal: a failure inside the SDK.
	ErrorKindInternal ErrorKind = "internal"
)

// Error is the error the SDK returns. Match it with errors.As:
//
//	var chatErr *chatxdk.Error
//	if errors.As(err, &chatErr) && chatErr.Kind == chatxdk.ErrorKindInvalidPin {
//	    // chatErr.GuessesRemaining
//	}
type Error struct {
	Kind    ErrorKind
	Message string
	// GuessesRemaining is the PIN attempts left after an ErrorKindInvalidPin
	// failure, when Juicebox reports them; 0 means the guess budget is
	// exhausted and the stored keys are locked. Nil for every other failure.
	GuessesRemaining *int
}

func (e *Error) Error() string { return e.Message }

// errorFromDocument decodes the C ABI's error document.
func errorFromDocument(document string) *Error {
	var parsed struct {
		Kind             ErrorKind `json:"kind"`
		Message          string    `json:"message"`
		GuessesRemaining *int      `json:"guesses_remaining"`
	}
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		return &Error{Kind: ErrorKindInternal, Message: document}
	}
	return &Error{Kind: parsed.Kind, Message: parsed.Message, GuessesRemaining: parsed.GuessesRemaining}
}
