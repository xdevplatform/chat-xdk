#!/usr/bin/env python3
"""Compile the 0.6.0 snippets of the migration guides against this tree.

Usage: scripts/check_doc_snippets.py LANG FILE...

LANG is rust, python, ts, go, java, csharp or c. Each fenced block of the
language splits at its `0.5.x` and `0.6.0` marker comments, and a block
without markers is 0.6.0. Every 0.6.0 half becomes one function over the
stand-in names the guides' "About the snippets" sections define, and the
binding's compiler checks the result: cargo (Rust), tsc (against
index.d.ts), go vet, javac, dotnet build and gcc (against chat_xdk.h).
Python runs each half with the real params classes and a `chat` whose
methods are mocked, so a wrong argument raises. A snippet that drifts from
the API fails the run.

Tools come from PATH, or from TSC (tsc), JAVA_CLASSPATH (the JVM binding's
dependency classpath) and DOTNET_BUILD_ARGS (extra `dotnet build` arguments).
"""

import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "target" / "guide-snippets"

FENCES = {
    "rust": ["rust"],
    "python": ["python"],
    "ts": ["js", "ts", "typescript"],
    "go": ["go"],
    "java": ["java"],
    "csharp": ["csharp"],
    "c": ["c"],
}


def halves(block, comment):
    """Split a block into (version, code) halves at its version markers."""
    marker = re.compile(rf"\s*{re.escape(comment)}\s*(0\.5\.x|0\.6\.0)\s*$")
    parts, version, lines = [], "0.6.0", []
    for line in block.splitlines():
        m = marker.match(line)
        if m:
            if any(l.strip() for l in lines):
                parts.append((version, "\n".join(lines)))
            version, lines = m.group(1), []
        else:
            lines.append(line)
    if any(l.strip() for l in lines):
        parts.append((version, "\n".join(lines)))
    return parts


def snippets(lang, paths):
    """Yield (path, line, code) for every 0.6.0 half of LANG in PATHS."""
    comment = "#" if lang == "python" else "//"
    fences = "|".join(FENCES[lang])
    for path in paths:
        text = pathlib.Path(path).read_text()
        for m in re.finditer(rf"```(?:{fences})\n(.*?)```", text, re.S):
            line = text[: m.start()].count("\n") + 1
            for version, code in halves(m.group(1), comment):
                if version == "0.6.0":
                    yield path, line, code


def run(cmd, **kwargs):
    print("$", " ".join(str(c) for c in cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    out = (r.stdout + r.stderr).strip()
    if r.returncode != 0:
        print(out[-20000:])
    return r.returncode


def declared(code, pattern):
    return {m.group(1) for m in re.finditer(pattern, code, re.M)}


# Rust ---------------------------------------------------------------------

RUST_PRELUDE = r"""#![allow(unused, unreachable_code, clippy::all)]
use chat_xdk_core::error::{ErrorKind, SdkError};
use chat_xdk_core::keys::juicebox::JuiceboxConfig;
use chat_xdk_core::*;
use std::collections::HashMap;
type R = Result<(), Box<dyn std::error::Error>>;
struct Api;
impl Api {
    fn post(&self, _path: &str, _body: &serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error>> { unimplemented!() }
    fn put(&self, _path: &str, _body: &serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error>> { unimplemented!() }
    fn delete(&self, _path: &str, _body: &serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error>> { unimplemented!() }
    fn get(&self, _path: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> { unimplemented!() }
}
fn http_get(_url: &str, _timeout_ms: u64, _max_bytes: usize) -> Result<(u16, Vec<u8>), Box<dyn std::error::Error>> { unimplemented!() }
fn photo_attachment(_media_hash_key: &str) -> AttachmentDescriptor { unimplemented!() }
fn show_edit(_sequence_id: &str, _text: &str) {}
fn show_title(_title: &str) {}
fn show_description(_description: &str) {}
fn show_avatar(_avatar_url: &str, _conversation_key_version: Option<&str>) {}
fn handle(_event: &Event) {}
fn log_skipped(_event_b64: &str, _err: &SdkError) {}
fn store_conversation_key(_conversation_id: &str, _version: &str, _key: &crypto::keys::XChatConversationKey) {}
"""

RUST_LOCALS = r"""
    let chat: ChatCore = unimplemented!();
    let api = Api;
    let keys: HashMap<String, crypto::keys::XChatConversationKey> = unimplemented!();
    let payload: SendPayload = unimplemented!();
    let prepared: PreparedConversationChange = unimplemented!();
    let key_change: ConversationKeyChangeParams = unimplemented!();
    let received_key_change: KeyChangeEvent = unimplemented!();
    let message: Message = unimplemented!();
    let deleted: MessageDeletedEvent = unimplemented!();
    let receipt: ReadReceiptEvent = unimplemented!();
    let group_change: GroupChangeEvent = unimplemented!();
    let err: SdkError = unimplemented!();
    let juicebox_config: String = unimplemented!();
    let user_id: &str = unimplemented!();
    let my_user_id: &str = unimplemented!();
    let signing_key_version: &str = unimplemented!();
    let public_key_version: &str = unimplemented!();
    let conversation_id: &str = unimplemented!();
    let path_id: &str = unimplemented!();
    let conversation_key_version: &str = unimplemented!();
    let event_b64: String = unimplemented!();
    let file_event_b64: String = unimplemented!();
    let file_hash_key: String = unimplemented!();
    let media_hash_key: String = unimplemented!();
    let photo: Vec<u8> = unimplemented!();
    let downloaded: Vec<u8> = unimplemented!();
    let private_keys: Vec<u8> = unimplemented!();
    let events: Vec<String> = unimplemented!();
    let page: serde_json::Value = unimplemented!();
    let signing_keys: Vec<SigningKeyEntry> = unimplemented!();
    let sequence_ids: Vec<String> = unimplemented!();
    let user_ids: Vec<String> = unimplemented!();
    let remaining_public_keys: Vec<PublicKeyInput> = unimplemented!();
    let public_keys: Vec<PublicKeyInput> = unimplemented!();
    let member_ids: Vec<String> = unimplemented!();
    let new_member_ids: Vec<String> = unimplemented!();
    let admin_ids: Vec<String> = unimplemented!();
    let promote_admin_id: &str = unimplemented!();
    let title: &str = unimplemented!();
    let avatar_url: &str = unimplemented!();
    let description: &str = unimplemented!();
    let invite_url: &str = unimplemented!();
    let invite_token: &str = unimplemented!();
    let expires_at_msec: i64 = unimplemented!();
    let ttl_msec: i64 = unimplemented!();
    let seen_until_sequence_id: &str = unimplemented!();
    let signing_public_key: &str = unimplemented!();
    let identity_public_key: &str = unimplemented!();
    let identity_public_key_signature: &str = unimplemented!();
    let data: Vec<u8> = unimplemented!();
"""


def check_rust(paths):
    fns = []
    for path, line, code in snippets("rust", paths):
        tag = re.sub(r"\W", "_", pathlib.Path(path).stem)
        fns.append(f"\n// {path}:{line}\nfn s_{tag}_{line}() -> R {{\n{RUST_LOCALS}\n{code}\n    Ok(())\n}}\n")
    crate = OUT / "rust"
    (crate / "src").mkdir(parents=True, exist_ok=True)
    (crate / "src" / "lib.rs").write_text(RUST_PRELUDE + "".join(fns))
    thrift = re.search(r"^thrift = .*$", (ROOT / "Cargo.toml").read_text(), re.M).group(0)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "doc-snippets"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n'
        "[workspace]\n\n[dependencies]\n"
        f'chat-xdk-core = {{ path = "{ROOT / "crates" / "core"}" }}\nserde_json = "1"\n\n'
        f"[patch.crates-io]\n{thrift}\n"
    )
    lock = crate / "Cargo.lock"
    if not lock.exists():
        lock.write_text((ROOT / "Cargo.lock").read_text())
    print(f"{len(fns)} Rust snippets")
    return run(["cargo", "check", "--quiet", "--manifest-path", str(crate / "Cargo.toml")],
               env={**os.environ, "CARGO_TARGET_DIR": str(crate / "target")})


# Python -------------------------------------------------------------------

def check_python(paths):
    sys.path.insert(0, str(ROOT / "crates" / "pyo3" / "python"))
    import inspect
    from unittest import mock

    import chat_xdk

    class Fake(str):
        """A stand-in result: indexes, reads attributes, iterates and calls."""

        def __new__(cls, value="1"):
            return super().__new__(cls, value)

        def __getitem__(self, key):
            return Fake()

        def __getattr__(self, name):
            if name.startswith("__"):
                raise AttributeError(name)
            return Fake()

        def __call__(self, *args, **kwargs):
            return Fake()

        def __iter__(self):
            return iter([Fake()])

        def get(self, key, default=None):
            return Fake()

    conversion = re.compile(r"cannot be converted|Can't extract|object cannot be interpreted|expected .* got|must be")

    def checked(cls):
        """A params class that constructs as the real one, or accepts the
        fakes a mocked result hands it when only their type differs."""

        def make(*args, **kwargs):
            try:
                return cls(*args, **kwargs)
            except TypeError as e:
                values = list(args) + list(kwargs.values())
                if conversion.search(str(e)) and any(isinstance(v, Fake) for v in values):
                    return Fake()
                raise

        return make

    returns_bytes = {"encrypt_file", "decrypt_file", "export_keys", "sign", "decrypt_conversation_key"}

    class ChatMock:
        """A Chat whose methods check their arguments against the real
        signatures and return fakes."""

        def __getattr__(self, name):
            method = getattr(chat_xdk.Chat, name)
            if not callable(method):
                return Fake()
            signature = inspect.signature(method)

            def call(*args, **kwargs):
                try:
                    signature.bind(self, *args, **kwargs)
                except TypeError as e:
                    raise TypeError(f"chat.{name}{signature}: {e}") from None
                return b"\x02" * 32 if name in returns_bytes else Fake()

            return call

    def chat_mock():
        return ChatMock()

    def api_mock():
        api = mock.Mock()
        for verb in ("post", "put", "delete", "get"):
            getattr(api, verb).return_value = Fake()
        return api

    def stand_ins():
        names = {k: getattr(chat_xdk, k) for k in dir(chat_xdk) if not k.startswith("_")}
        for k, v in list(names.items()):
            if isinstance(v, type) and k.endswith("Params"):
                names[k] = checked(v)
        names.update({
            "chat": chat_mock(),
            "api": api_mock(),
            "keys": {"1": b"\x02" * 32},
            "payload": Fake(),
            "prepared": Fake(),
            "key_change": Fake(),
            "message": Fake(),
            "deleted": Fake(),
            "receipt": Fake(),
            "group_change": Fake(),
            "page": {"data": [{"id": "1", "encoded_event": "ZXZlbnQ="}], "meta": {}},
            "photo_attachment": lambda key: {"attachment_type": "media", "media_hash_key": key},
            "show_edit": lambda *a: None,
            "show_title": lambda *a: None,
            "show_description": lambda *a: None,
            "show_avatar": lambda *a: None,
            "handle": lambda *a: None,
            "log_skipped": lambda *a: None,
            "store_conversation_key": lambda *a: None,
            "user_id": "1001",
            "my_user_id": "1001",
            "signing_key_version": "1",
            "conversation_id": "g1",
            "path_id": "g1",
            "conversation_key_version": "1",
            "event_b64": "ZXZlbnQ=",
            "file_event_b64": "ZXZlbnQ=",
            "file_hash_key": "hash",
            "media_hash_key": "hash",
            "photo": b"photo",
            "downloaded": b"enc",
            "private_keys": b"\x01" * 64,
            "events": ["ZXZlbnQ="],
            "signing_keys": [],
            "sequence_ids": ["1"],
            "user_ids": ["2"],
            "member_ids": ["1001"],
            "new_member_ids": ["2"],
            "admin_ids": ["1001"],
            "public_keys": [{"user_id": "1", "identity_public_key": "pk", "public_key_version": "1"}],
            "remaining_public_keys": [{"user_id": "1", "identity_public_key": "pk", "public_key_version": "1"}],
            "pin": b"2580",
            "identity_public_key": "pk",
            "public_key_version": "1",
            "promote_admin_id": "3",
            "title": "Team",
            "avatar_url": "https://ton.x.com/xchat_media/g1/a",
            "description": "About",
            "invite_url": "https://x.com/i/chat/group_join/g1/abcdefghij",
            "invite_token": "abcdefghij",
            "expires_at_msec": 1,
            "ttl_msec": 60_000,
            "seen_until_sequence_id": "1",
            "signing_public_key": "spk",
            "public_key": {"public_key": "pk"},
            "data": b"data",
        })
        return names

    failures, count = 0, 0
    for path, line, code in snippets("python", paths):
        count += 1
        where = f"{path}:{line}"
        try:
            exec(compile(code, where, "exec"), stand_ins())
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"{where}: {type(e).__name__}: {e}")
    print(f"{count} Python snippets, {failures} failed")
    return 1 if failures else 0


# TypeScript ---------------------------------------------------------------

TS_TYPES = [
    "ChatWithJuicebox", "Event", "SendPayload", "PreparedConversationChange", "PublicKeyInput",
    "SigningKeyEntry", "AttachmentDescriptor", "ConversationKeyMap",
]
TS_VALUES = ["ChatXdkError", "createChat", "encryptedFileSize", "bytesToBase64"]

TS_PRELUDE = r"""
declare const chat: ChatWithJuicebox;
declare const api: {
  post(path: string, body: unknown): Promise<any>;
  put(path: string, body: unknown): Promise<any>;
  delete(path: string, body: unknown): Promise<any>;
  get(path: string): Promise<any>;
};
declare function toSnake(value: unknown): any;
declare const keys: ConversationKeyMap;
declare const payload: SendPayload;
declare const prepared: PreparedConversationChange;
declare const keyChange: Event;
declare const message: Event;
declare const deleted: Event;
declare const receipt: Event;
declare const groupChange: Event;
declare const page: { data: { id: string; encoded_event: string }[]; meta: any };
declare function photoAttachment(mediaHashKey: string): AttachmentDescriptor;
declare function showEdit(sequenceId: string, text: string): void;
declare function showTitle(title: string): void;
declare function showDescription(description: string): void;
declare function showAvatar(avatarUrl: string, conversationKeyVersion: string | null | undefined): void;
declare function showGuessesLeft(guessesLeft: number | null): void;
declare function handle(event: Event): void;
declare function logSkipped(eventB64: string, err: unknown): void;
declare function storeConversationKey(conversationId: string, version: string, key: Uint8Array): void;
declare const userId: string;
declare const myUserId: string;
declare const signingKeyVersion: string;
declare const conversationId: string;
declare const pathId: string;
declare const conversationKeyVersion: string;
declare const eventB64: string;
declare const fileEventB64: string;
declare const fileHashKey: string;
declare const mediaHashKey: string;
declare const photo: Uint8Array;
declare const downloaded: Uint8Array;
declare const events: string[];
declare const signingKeys: SigningKeyEntry[];
declare const sequenceIds: string[];
declare const userIds: string[];
declare const memberIds: string[];
declare const newMemberIds: string[];
declare const adminIds: string[];
declare const remainingPublicKeys: PublicKeyInput[];
declare const publicKeys: PublicKeyInput[];
declare const promoteAdminId: string;
declare const title: string;
declare const avatarUrl: string;
declare const description: string;
declare const inviteUrl: string;
declare const inviteToken: string;
declare const expiresAtMsec: number;
declare const ttlMsec: number;
declare const seenUntilSequenceId: string;
declare const conversationKey: Uint8Array;
declare const signingPublicKey: string;
declare const pin: string;
declare const juiceboxConfig: string;
declare const getAuthToken: (realmId: string) => Promise<string>;
declare const privateKeys: Uint8Array;
declare const identityPublicKey: string;
declare const publicKeyVersion: string;
declare const err: unknown;
declare const data: Uint8Array;
"""


def check_ts(paths):
    """Each snippet is its own module, so the names it imports and declares
    don't collide with another snippet's."""
    d = OUT / "ts"
    if d.exists():
        for old in d.glob("s_*.ts"):
            old.unlink()
    d.mkdir(parents=True, exist_ok=True)
    files = []
    for path, line, code in snippets("ts", paths):
        if re.search(r"^\s*(export\s+)?(interface|type) \w+", code, re.M):
            continue
        code = code.replace('"@xdevplatform/chat-xdk"', '"chat-xdk"')
        imports = [l for l in code.splitlines() if l.startswith("import ")]
        body = "\n".join(l for l in code.splitlines() if not l.startswith("import "))
        imported = set(re.findall(r"\b(\w+)\b", " ".join(re.findall(r"\{([^}]*)\}", " ".join(imports)))))
        types = [t for t in TS_TYPES if t not in imported]
        values = [v for v in TS_VALUES if v not in imported]
        header = f'import type {{ {", ".join(types)} }} from "chat-xdk";\n'
        header += f'import {{ {", ".join(values)} }} from "chat-xdk";\n' if values else ""
        tag = re.sub(r"\W", "_", pathlib.Path(path).stem)
        name = f"s_{tag}_{line}.ts"
        (d / name).write_text(
            f"// {path}:{line}\n{header}" + "\n".join(imports) + TS_PRELUDE
            + f"\nexport async function snippet() {{\n{body}\n}}\n"
        )
        files.append(name)
    dts = ROOT / "crates" / "wasm" / "js" / "index.d.ts"
    (d / "tsconfig.json").write_text(
        '{"compilerOptions": {"strict": true, "noEmit": true, "noUnusedLocals": false, '
        '"target": "es2022", "module": "es2022", "moduleResolution": "bundler", '
        '"lib": ["es2022", "dom"], "skipLibCheck": true, '
        f'"paths": {{"chat-xdk": ["{dts}"]}}}}, "files": {files!r}}}'.replace("'", '"')
    )
    print(f"{len(files)} TypeScript snippets")
    return run([os.environ.get("TSC", "tsc"), "-p", str(d)])


# Go -----------------------------------------------------------------------

GO_PARAMS = [
    ("chat", "*chatxdk.Chat"), ("api", "apiClient"), ("keys", "map[string][]byte"),
    ("payload", "*chatxdk.SendPayload"), ("prepared", "*chatxdk.PreparedConversationChange"),
    ("keyChange", "*chatxdk.KeyChangeEvent"), ("message", "*chatxdk.Message"),
    ("receipt", "*chatxdk.ReadReceiptEvent"), ("deleted", "*chatxdk.MessageDeletedEvent"),
    ("groupChange", "*chatxdk.GroupChangeEvent"), ("event", "*chatxdk.Event"),
    ("bundle", "*chatxdk.ConversationKeyBundle"), ("page", "eventsPage"),
] + [(n, "string") for n in [
    "userID", "myUserID", "signingKeyVersion", "conversationID", "pathID", "conversationKeyVersion",
    "eventB64", "fileEventB64", "fileHashKey", "mediaHashKey", "promoteAdminID", "title",
    "avatarURL", "description", "inviteURL", "inviteToken", "seenUntilSequenceID",
    "signingPublicKey", "juiceboxConfig", "identityPublicKey", "publicKeyVersion",
]] + [
    ("photo", "[]byte"), ("downloaded", "[]byte"), ("privateKeys", "[]byte"), ("pin", "[]byte"),
    ("conversationKey", "[]byte"), ("data", "[]byte"), ("events", "[]string"),
    ("sequenceIDs", "[]string"), ("userIDs", "[]string"), ("memberIDs", "[]string"),
    ("newMemberIDs", "[]string"), ("adminIDs", "[]string"),
    ("signingKeys", "[]chatxdk.SigningKeyEntry"), ("remainingPublicKeys", "[]chatxdk.PublicKeyInput"),
    ("publicKeys", "[]chatxdk.PublicKeyInput"), ("ttlMsec", "int64"), ("expiresAtMsec", "int64"),
    ("err", "error"),
]

GO_PRELUDE = """package snippets

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/xdevplatform/chat-xdk/go/chatxdk"
)

var _ = base64.StdEncoding
var _ = json.Marshal
var _ = errors.As
var _ = fmt.Sprintf
var _ = log.Printf
var _ = strings.ReplaceAll

type apiClient interface {
	Post(path string, body any) (map[string]any, error)
	Put(path string, body any) (map[string]any, error)
	Delete(path string, body any) (map[string]any, error)
	Get(path string) (map[string]any, error)
}

type eventsPage struct {
	Data []struct {
		ID           string `json:"id"`
		EncodedEvent string `json:"encoded_event"`
	} `json:"data"`
}

func photoAttachment(mediaHashKey string) chatxdk.AttachmentDescriptor { return chatxdk.AttachmentDescriptor{} }
func showEdit(sequenceID, text string)                                {}
func showTitle(title string)                                          {}
func showDescription(description string)                              {}
func showAvatar(avatarURL string, conversationKeyVersion *string)     {}
func showGuessesLeft(n int, ok bool)                                  {}
func handle(event *chatxdk.Event)                                     {}
func logSkipped(eventB64 string, err error)                           {}
func storeConversationKey(conversationID, version string, key []byte) {}
"""


def go_declared(code):
    names = set()
    for m in re.finditer(r"^\s*([\w, ]+?)\s*:=", code, re.M):
        if re.match(r"(for|if|switch|select)\b", m.group(1).strip()):
            continue
        names.update(n.strip() for n in m.group(1).split(","))
    names |= declared(code, r"^\s*var (\w+)")
    names.discard("_")
    return names


def check_go(paths):
    out = [GO_PRELUDE]
    count = 0
    for path, line, code in snippets("go", paths):
        count += 1
        names = go_declared(code)
        params = ", ".join(f"{n} {t}" for n, t in GO_PARAMS if n not in names)
        uses = "\n".join(f"\t_ = {n}" for n in sorted(names) if re.fullmatch(r"\w+", n))
        out.append(f"\n// {path}:{line}\nfunc s{line}({params}) {{\n{code}\n{uses}\n}}\n")
    d = OUT / "go"
    d.mkdir(parents=True, exist_ok=True)
    (d / "snippets.go").write_text("".join(out))
    (d / "go.mod").write_text(
        "module snippets\n\ngo 1.21\n\nrequire github.com/xdevplatform/chat-xdk/go/chatxdk v0.0.0\n\n"
        f"replace github.com/xdevplatform/chat-xdk/go/chatxdk => {ROOT / 'go' / 'chatxdk'}\n"
    )
    print(f"{count} Go snippets")
    return run(["go", "vet", "./..."], cwd=d, env={**os.environ, "CGO_ENABLED": "1", "GOFLAGS": "-mod=mod"})


# Java ---------------------------------------------------------------------

JAVA_PARAMS = [
    ("chat", "Chat"), ("api", "Api"), ("keys", "Map<String, byte[]>"),
    ("bundle", "ConversationKeyBundle"), ("payload", "SendPayload"),
    ("prepared", "PreparedConversationChange"), ("keyChange", "JsonNode"),
    ("message", "JsonNode"), ("deleted", "JsonNode"), ("receipt", "JsonNode"),
    ("groupChange", "JsonNode"), ("page", "JsonNode"),
] + [(n, "String") for n in [
    "userId", "myUserId", "signingKeyVersion", "conversationId", "pathId", "conversationKeyVersion",
    "eventB64", "fileEventB64", "fileHashKey", "mediaHashKey", "promoteAdminId", "title",
    "avatarUrl", "description", "inviteUrl", "inviteToken", "seenUntilSequenceId",
    "signingPublicKey", "juiceboxConfig", "identityPublicKey", "publicKeyVersion",
    "identityPublicKeySignature",
]] + [
    ("photo", "byte[]"), ("downloaded", "byte[]"), ("privateKeys", "byte[]"), ("pin", "byte[]"),
    ("conversationKey", "byte[]"), ("data", "byte[]"), ("events", "List<String>"),
    ("sequenceIds", "List<String>"), ("userIds", "List<String>"), ("memberIds", "List<String>"),
    ("newMemberIds", "List<String>"), ("adminIds", "List<String>"),
    ("signingKeys", "List<SigningKeyEntry>"), ("remainingPublicKeys", "List<PublicKeyInput>"),
    ("publicKeys", "List<PublicKeyInput>"), ("ttlMsec", "long"), ("expiresAtMsec", "long"),
    ("e", "ChatXdkException"),
]

JAVA_PRELUDE = """import com.x.chatxdk.*;
import com.x.chatxdk.Types.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.*;

class Snippets {
    interface Api {
        JsonNode post(String path, Object body) throws Exception;
        JsonNode put(String path, Object body) throws Exception;
        JsonNode delete(String path, Object body) throws Exception;
        JsonNode get(String path) throws Exception;
    }
    static AttachmentDescriptor photoAttachment(String mediaHashKey) { return null; }
    static void showEdit(String sequenceId, String text) {}
    static void showTitle(String title) {}
    static void showDescription(String description) {}
    static void showAvatar(String avatarUrl, String conversationKeyVersion) {}
    static void showGuessesLeft(Integer guessesLeft) {}
    static void handle(JsonNode event) {}
    static void logSkipped(String eventB64, Exception error) {}
    static void storeConversationKey(String conversationId, String version, byte[] key) {}
"""


def check_java(paths):
    out = [JAVA_PRELUDE]
    count = 0
    for path, line, code in snippets("java", paths):
        count += 1
        names = declared(code, r"^\s*(?:final\s+)?[\w.<>\[\], ]+?\s+(\w+)\s*=[^=]")
        params = ", ".join(f"{t} {n}" for n, t in JAVA_PARAMS if n not in names)
        out.append(f"\n    // {path}:{line}\n    void s{line}({params}) throws Exception {{\n{code}\n    }}\n")
    d = OUT / "java"
    d.mkdir(parents=True, exist_ok=True)
    (d / "Snippets.java").write_text("".join(out) + "}\n")
    classes = ROOT / "crates" / "jvm" / "java" / "chatxdk" / "target" / "classes"
    classpath = os.pathsep.join(filter(None, [os.environ.get("JAVA_CLASSPATH", ""), str(classes)]))
    print(f"{count} Java snippets")
    return run(["javac", "-nowarn", "-d", str(d / "out"), "-cp", classpath, str(d / "Snippets.java")])


# C# -----------------------------------------------------------------------

CSHARP_PARAMS = [
    ("chat", "Chat"), ("api", "IApi"), ("keys", "Dictionary<string, byte[]>"),
    ("bundle", "ConversationKeyBundle"), ("payload", "SendPayload"),
    ("prepared", "PreparedConversationChange"), ("keyChange", "JsonElement"),
    ("message", "JsonElement"), ("deleted", "JsonElement"), ("receipt", "JsonElement"),
    ("groupChange", "JsonElement"), ("page", "JsonElement"),
] + [(n, "string") for n in [
    "userId", "myUserId", "signingKeyVersion", "conversationId", "pathId", "conversationKeyVersion",
    "eventB64", "fileEventB64", "fileHashKey", "mediaHashKey", "promoteAdminId", "title",
    "avatarUrl", "description", "inviteUrl", "inviteToken", "seenUntilSequenceId",
    "signingPublicKey", "juiceboxConfig", "identityPublicKey", "publicKeyVersion",
    "identityPublicKeySignature",
]] + [
    ("photo", "byte[]"), ("downloaded", "byte[]"), ("privateKeys", "byte[]"), ("pin", "byte[]"),
    ("conversationKey", "byte[]"), ("data", "byte[]"), ("events", "List<string>"),
    ("sequenceIds", "List<string>"), ("userIds", "List<string>"), ("memberIds", "List<string>"),
    ("newMemberIds", "List<string>"), ("adminIds", "List<string>"),
    ("signingKeys", "List<SigningKeyEntry>"), ("remainingPublicKeys", "List<PublicKeyInput>"),
    ("publicKeys", "List<PublicKeyInput>"), ("ttlMsec", "long"), ("expiresAtMsec", "long"),
    ("signingKeyQuery", "IEnumerable<SigningKeyEntry>"), ("e", "ChatXdkException"),
]

CSHARP_PRELUDE = """#nullable enable
using System.Text;
using System.Text.Json;
using ChatXdk;

public interface IApi
{
    JsonElement Post(string path, object body);
    JsonElement Put(string path, object body);
    JsonElement Delete(string path, object body);
    JsonElement Get(string path);
}

public class Snippets
{
    static AttachmentDescriptor PhotoAttachment(string mediaHashKey) => null!;
    static void ShowEdit(string? sequenceId, string? text) {}
    static void ShowTitle(string title) {}
    static void ShowDescription(string description) {}
    static void ShowAvatar(string avatarUrl, string? conversationKeyVersion) {}
    static void ShowGuessesLeft(int? guessesLeft) {}
    static void Handle(JsonElement evt) {}
    static void LogSkipped(string eventB64, Exception error) {}
    static void StoreConversationKey(string conversationId, string version, byte[] key) {}
"""

CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <LangVersion>latest</LangVersion>
    <NoWarn>CS1591;CS0168;CS0219;CS8321;CS1998;CS0162</NoWarn>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
  </PropertyGroup>
  <ItemGroup>
    <Compile Include="Snippets.cs" />
    <ProjectReference Include="{ref}" />
  </ItemGroup>
</Project>
"""


def check_csharp(paths):
    out = [CSHARP_PRELUDE]
    count = 0
    for path, line, code in snippets("csharp", paths):
        count += 1
        names = declared(code, r"^\s*(?:using\s+)?[\w.<>\[\], ?]+?\s+(\w+)\s*=[^=]")
        params = ", ".join(f"{t} {n}" for n, t in CSHARP_PARAMS if n not in names)
        out.append(f"\n    // {path}:{line}\n    async Task S{line}({params})\n    {{\n{code}\n    }}\n")
    d = OUT / "csharp"
    d.mkdir(parents=True, exist_ok=True)
    (d / "Snippets.cs").write_text("".join(out) + "}\n")
    ref = ROOT / "crates" / "dotnet" / "dotnet" / "ChatXdk" / "ChatXdk.csproj"
    (d / "Snippets.csproj").write_text(CSPROJ.format(ref=ref))
    extra = os.environ.get("DOTNET_BUILD_ARGS", "").split()
    print(f"{count} C# snippets")
    return run(["dotnet", "build", "-nologo", "-v", "q", *extra], cwd=d)


# C ------------------------------------------------------------------------

C_PARAMS = [
    ("chat", "struct ChatHandle *"), ("keys", "const uint8_t *"), ("keys_len", "size_t"),
    ("pin", "const uint8_t *"), ("pin_len", "size_t"), ("data", "const uint8_t *"),
    ("data_len", "size_t"),
] + [(n, "const char *") for n in [
    "user_id", "my_user_id", "signing_key_version", "conversation_id", "path_id", "event_b64",
    "title", "avatar_url", "description", "public_key_b64", "signature_b64",
]]

C_PRELUDE = """#define CHAT_XDK_JUICEBOX
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "chat_xdk.h"

char *take(struct FfiResult result);
char *take_error(struct FfiResult result);
int32_t http_get(const char *url, uint32_t timeout_ms, size_t max_bytes, uint8_t **body, size_t *body_len);
void handle(const char *event_json);
void log_skipped(const char *event_b64, const char *error_json);
void store_conversation_key(const char *conversation_id, const char *prepared_json);
"""


def check_c(paths):
    out = [C_PRELUDE]
    count = 0
    for path, line, code in snippets("c", paths):
        count += 1
        names = declared(code, r"^\s*(?:const\s+)?(?:struct\s+)?[\w]+\s*\**\s*(\w+)\s*(?:=|;|\[)")
        used = set(re.findall(r"\b(\w+_json|\w+_b64)\b(?!\s*\()", code))
        params = [(n, t) for n, t in C_PARAMS if n not in names]
        params += [(n, "const char *") for n in sorted(used) if n not in names and n not in dict(params)]
        sig = ", ".join(f"{t} {n}" for n, t in params) or "void"
        out.append(f"\n// {path}:{line}\nvoid s{line}({sig}) {{\n{code}\n}}\n")
    d = OUT / "c"
    d.mkdir(parents=True, exist_ok=True)
    (d / "snippets.c").write_text("".join(out))
    print(f"{count} C snippets")
    return run(["gcc", "-std=c11", "-fsyntax-only", "-Wall", "-Wno-unused-variable",
                "-Wno-unused-but-set-variable", "-Werror", "-I", str(ROOT / "go" / "chatxdk" / "include"),
                str(d / "snippets.c")])


CHECKS = {
    "rust": check_rust,
    "python": check_python,
    "ts": check_ts,
    "go": check_go,
    "java": check_java,
    "csharp": check_csharp,
    "c": check_c,
}


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in CHECKS:
        sys.exit(__doc__)
    sys.exit(1 if CHECKS[sys.argv[1]](sys.argv[2:]) else 0)


if __name__ == "__main__":
    main()
