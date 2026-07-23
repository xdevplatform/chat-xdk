import assert from "node:assert/strict";
import fs from "node:fs/promises";

import init, { Chat } from "../../pkg/chat_xdk_wasm.js";

// Node 18 exposes WebCrypto only via node:crypto; the wasm module's
// random-byte source needs it on the global scope.
if (typeof globalThis.crypto === "undefined") {
  const { webcrypto } = await import("node:crypto");
  globalThis.crypto = webcrypto;
}


async function loadVectors() {
  const path = new URL("../../../../tests/fixtures/sdk_vectors.json", import.meta.url);
  const raw = await fs.readFile(path, "utf-8");
  return JSON.parse(raw);
}

function b64ToBytes(b64) {
  return Uint8Array.from(Buffer.from(b64, "base64"));
}

function bytesToB64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

async function main() {
  // wasm-bindgen's default init path uses `fetch(new URL(...))`, which breaks in Node
  // for `file://` URLs. Feed the wasm bytes directly instead.
  const wasmUrl = new URL("../../pkg/chat_xdk_wasm_bg.wasm", import.meta.url);
  const wasmBytes = await fs.readFile(wasmUrl);
  await init({ module_or_path: wasmBytes });
  const v = await loadVectors();

  const chat = new Chat();

  // import keys (raw bytes, not base64)
  assert.throws(() => chat.importKeys(new Uint8Array([0])), /Invalid key format|expected/i);
  chat.importKeys(b64ToBytes(v.private_keys_concat_b64), v.event_recipient_key_version);
  assert.equal(chat.isUnlocked(), true);

  // public keys match fixture
  const keys = chat.getPublicKeys();
  assert.equal(keys.identity, v.identity_public_b64);
  assert.equal(keys.signing, v.signing_public_b64);

  // deterministic signature matches fixture (sign returns Uint8Array)
  const msgBytes = new TextEncoder().encode(v.message_utf8);
  const sigBytes = chat.sign(msgBytes);
  const sigB64 = bytesToB64(sigBytes);
  assert.equal(sigB64, v.signature_b64);
  assert.equal(chat.verify(v.signing_public_b64, sigBytes, msgBytes), true);
  assert.equal(chat.verify(v.signing_public_b64, sigBytes, new TextEncoder().encode(v.message_utf8 + "!")), false);

  // conversation-key change ECIES roundtrip (ciphertext randomized, key retained locally)
  const prep = chat.prepareConversationKeyChange({
    senderId: "me",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "me", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "conv-1",
  });
  const decryptedKey = chat.decryptConversationKey(prep.participantKeys[0].encryptedKey);
  assert.deepEqual(decryptedKey, prep.conversationKey);

  // stream fixture uses the deterministic conversation key
  const convKey = b64ToBytes(v.conversation_key_b64);

  // stream encrypt/decrypt roundtrip (ciphertext randomized)
  const plaintext = b64ToBytes(v.plaintext_b64);
  const ct1 = chat.encryptStream(plaintext, convKey);
  const ct2 = chat.encryptStream(plaintext, convKey);
  assert.notDeepEqual(ct1, ct2); // randomized nonces
  const pt1 = chat.decryptStream(ct1, convKey);
  assert.deepEqual(pt1, plaintext);

  // wrong key fails decryption
  const wrongKey = new Uint8Array(convKey);
  wrongKey[31] ^= 0xff;
  assert.throws(() => chat.decryptStream(ct1, wrongKey));

  // decryptEvents over the fixture event vectors: [signed KeyChange, signed
  // message, garbage]. The batch never throws; the garbage event lands in
  // `errors` keyed by its index, the KeyChange's key is adopted, and the
  // message verifies with the fixture text.
  const signingKeys = [
    {
      userId: v.event_sender_id,
      publicKeyVersion: v.event_signing_key_version,
      publicKey: v.signing_public_b64,
      identityPublicKey: v.identity_public_b64,
      identityPublicKeySignature: v.identity_public_key_signature_b64,
    },
  ];
  const batch = chat.decryptEvents(
    [v.event_key_change_b64, v.event_message_b64, v.event_garbage_b64],
    signingKeys,
  );
  assert.deepEqual(Object.keys(batch.errors), ["2"]);
  assert.equal(batch.conversationKeys.latestVersion, v.event_conversation_key_version);
  assert.deepEqual(
    batch.conversationKeys.keys[v.event_conversation_key_version],
    b64ToBytes(v.conversation_key_b64),
  );
  const keyChanges = batch.messages.filter((m) => m.event.type === "keyChange");
  assert.equal(keyChanges.length, 1);
  assert.equal(keyChanges[0].event.verified, true);
  assert.equal(keyChanges[0].event.keyVersion, v.event_conversation_key_version);
  const messages = batch.messages.filter((m) => m.event.type === "message");
  assert.equal(messages.length, 1);
  assert.equal(messages[0].event.content.text, v.event_message_text);
  assert.equal(messages[0].event.verified, true);

  // Single-event path with pre-cached keys verifies the same message …
  const single = chat.decryptEvent(v.event_message_b64, batch.conversationKeys.keys, signingKeys);
  assert.equal(single.type, "message");
  assert.equal(single.content.text, v.event_message_text);
  assert.equal(single.verified, true);

  // … and throws on the garbage event.
  assert.throws(() => chat.decryptEvent(v.event_garbage_b64, {}, signingKeys));

  // setSigningKeys: the stored keys back an omitted signingKeys argument on
  // the single-event path, so the message still verifies.
  chat.setSigningKeys(signingKeys);
  const viaStore = chat.decryptEvent(v.event_message_b64, batch.conversationKeys.keys);
  assert.equal(viaStore.verified, true);
  assert.equal(viaStore.content.text, v.event_message_text);

  // Reply-preview validation over the fixture reply events: both replies
  // decrypt to the fixture reply text, the honest preview validates and the
  // forged one is flagged (the enum serializes camelCased: valid/invalid).
  const replyBatch = chat.decryptEvents(
    [v.event_key_change_b64, v.event_reply_valid_b64, v.event_reply_forged_b64],
    signingKeys,
  );
  assert.deepEqual(Object.keys(replyBatch.errors), []);
  const replies = replyBatch.messages.filter((m) => m.event.type === "message");
  assert.equal(replies.length, 2);
  const [validReply, forgedReply] = replies;
  assert.equal(validReply.event.content.text, v.event_reply_text);
  assert.equal(validReply.event.replyPreviewValidation, "valid");
  assert.equal(forgedReply.event.content.text, v.event_reply_text);
  assert.equal(forgedReply.event.replyPreviewValidation, "invalid");

  // Failure events are unsigned by protocol: the fixture failure decodes with
  // no keys, and JS camelCases the discriminator values and the tier field.
  const failure = chat.decryptEvent(v.event_failure_b64, {}, []);
  assert.equal(failure.type, "failure");
  assert.equal(failure.failure, "rateLimitUpsell");
  assert.equal(failure.rateLimitTier, "premium");
  assert.equal(failure.senderId, v.event_sender_id);

  // Session identity + opt-in key cache: importKeys(bytes, version) records
  // the registered key version, decryptEvents populates the cache from the
  // verified KeyChange, and encryptMessage resolves the omitted identity and
  // key pair from the session.
  {
    const session = new Chat();
    session.importKeys(b64ToBytes(v.private_keys_concat_b64), v.event_recipient_key_version);
    session.setIdentity(v.event_sender_id, v.event_signing_key_version);
    session.setCacheKeys(true);
    session.decryptEvents([v.event_key_change_b64], signingKeys);
    const cached = session.encryptMessage({
      conversationId: v.event_conversation_id,
      text: "hello from the cache",
    });
    assert.equal(cached.conversationKeyVersion, v.event_conversation_key_version);
    assert.equal(cached.signatureInfo.publicKeyVersion, v.event_signing_key_version);

    // Replying by raw event derives the preview from the signed original.
    const reply = session.encryptReply({
      conversationId: v.event_conversation_id,
      text: "a threaded reply",
      replyToEvent: v.event_message_b64,
      conversationKey: b64ToBytes(v.conversation_key_b64),
      conversationKeyVersion: v.event_conversation_key_version,
    });
    assert.ok(reply.messageId.length > 0);
    assert.ok(reply.encryptedContent.length > 0);

    // Reacting by raw event derives the conversation id and sequence id.
    const reaction = session.encryptAddReaction({
      emoji: "\u{1F44D}",
      targetEvent: v.event_message_b64,
    });
    assert.ok(reaction.encryptedContent.length > 0);
  }

  // Without the opt-in cache, an omitted conversation key is an error even
  // after the key change decrypted.
  {
    const noCache = new Chat();
    noCache.importKeys(b64ToBytes(v.private_keys_concat_b64), v.event_recipient_key_version);
    noCache.setIdentity(v.event_sender_id, v.event_signing_key_version);
    noCache.decryptEvents([v.event_key_change_b64], signingKeys);
    assert.throws(
      () => noCache.encryptMessage({ conversationId: v.event_conversation_id, text: "x" }),
      /no cached conversation key/,
    );
  }

  // With no session identity and no explicit senderId, encryption fails in
  // the core naming the missing sender_id.
  {
    const noIdentity = new Chat();
    noIdentity.importKeys(b64ToBytes(v.private_keys_concat_b64));
    assert.throws(
      () =>
        noIdentity.encryptMessage({
          conversationId: v.event_conversation_id,
          text: "x",
          conversationKey: b64ToBytes(v.conversation_key_b64),
          conversationKeyVersion: "1",
        }),
      /sender_id/,
    );
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

