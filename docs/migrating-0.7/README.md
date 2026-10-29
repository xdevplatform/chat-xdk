# Migrating to chat-xdk 0.7.2

0.7.2 changes the API of every binding. Each guide below moves one
binding's code written for 0.5.x (0.5.0, 0.5.1 or 0.5.2) to 0.7.2 on its
own, and every guide has the same sections:

0. **Before you start**: the install line, the readers to upgrade first, and
   the feature-switch request.
1. **Symbol index**: every 0.5.x name that changes, with its 0.7.2 form.
2. **Compile-time changes**, in the order an app meets them.
3. **Runtime and behavior changes**, which nothing reports before the code
   runs.
4. **Group and receipt signing**: every signed request, with its X API
   method, path and body.
5. **Verify**: the build, a search for 0.5.x names, and a round trip.

A checklist at the top of each guide tags every item `[rollout]`,
`[compile]`, `[runtime]` or `[new]`. CI compiles the 0.7.2 half of every
snippet in the guides against 0.7.2. [Why 0.7.2 changes](why.md) explains
why each change was made.

| Binding | Package | Migration guide |
|---|---|---|
| Rust | `chat-xdk-core` | [Rust](rust.md) |
| Python | `chatxdk` | [Python](python.md) |
| JavaScript and TypeScript (WASM) | `@xdevplatform/chat-xdk` | [JavaScript](javascript.md) |
| Go | `github.com/xdevplatform/chat-xdk/go/chatxdk` | [Go](go.md) |
| JVM | `com.x:chatxdk` | [JVM](jvm.md) |
| .NET | `XDevPlatform.ChatXdk` | [.NET](dotnet.md) |
| C ABI, called directly | `chat_xdk.h` | [C ABI](c-abi.md) |

One step applies across bindings: upgrade every app that reads your
conversations before any sender can send v1, the format with per-message
keys, and before you remove group members or add them with a description,
because 0.5.x rejects those signatures. Each guide explains it under
"Upgrade readers first".

The [CHANGELOG](../../CHANGELOG.md) lists every change by release, and
[API.md](../API.md) documents the 0.7.2 API.
