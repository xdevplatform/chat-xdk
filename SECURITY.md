# Security Policy

chat-xdk is a cryptography library. If you believe you have found a security
vulnerability — in the protocol implementation, key handling, signature
verification, or any language binding — please report it privately.

## Reporting a vulnerability

- Report through X's vulnerability disclosure program:
  [hackerone.com/x](https://hackerone.com/x)
- Do **not** open a public GitHub issue for suspected vulnerabilities.

Please include the SDK version (or commit), the affected binding, and a
minimal reproduction where possible.

## Scope notes

- Deliberate protocol-level constraints — no forward secrecy or
  post-compromise security, message encryption without context-binding AAD,
  and single-shared-key group conversations — are documented in
  [docs/CRYPTO.md](docs/CRYPTO.md) under Known Limitations. Reports that
  restate those limitations without a new exploitation path are unlikely to
  qualify.
- The SDK performs no networking for chat itself — the application embedding
  it owns all X API transport. The one exception is the Juicebox layer:
  `setup`/`unlock` contact Juicebox realm servers to store and recover
  PIN-protected key material, so vulnerabilities in that client path are in
  scope.
