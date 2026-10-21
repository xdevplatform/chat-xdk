#!/usr/bin/env bash
# Checks that chat-xdk-core's internal `bindings` feature fails to compile when
# CHAT_XDK_BINDINGS is not "1", as in any build outside this repository. The
# repository's .cargo/config.toml sets it to "1"; the override below stands in
# for a dependent crate's build, which never reads that file.
set -uo pipefail
cd "$(dirname "$0")/.."

out=$(env -u CHAT_XDK_BINDINGS cargo check -p chat-xdk-core --features bindings \
  --config 'env.CHAT_XDK_BINDINGS="0"' 2>&1)
if grep -q "internal to the chat-xdk repository" <<<"$out"; then
  echo "bindings gate: the feature is rejected outside this repository"
  exit 0
fi
echo "$out" | tail -20
echo "bindings gate: chat-xdk-core compiled with the bindings feature outside this repository" >&2
exit 1
