# Migrating to chat-xdk 0.6.0

0.6.0 changes the API of every binding. Each guide below covers one
binding: a checklist of everything its code written for 0.5.x (0.5.0, 0.5.1
or 0.5.2) runs into, then each change with the lines to change.
[Why 0.6.0 changes](why.md) explains why each change was made.

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
keys, because 0.5.x rejects v1 sends. Each page explains it under "Upgrade
readers before v1 sends start".

The [CHANGELOG](../../CHANGELOG.md) lists every change in 0.6.0, and
[API.md](../API.md) documents the 0.6.0 API.
