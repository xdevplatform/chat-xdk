import assert from "node:assert/strict";
import fs from "node:fs/promises";

import init, {
  Chat,
  bytesToBase64,
  base64ToBytes,
  bytesToHex,
  hexToBytes,
  detectMimeType,
  detectImageDimensions,
  encryptedFileSize,
} from "../pkg/chat_xdk_wasm.js";
import { featureServer, keepOffline, reading, v1Chat, waitForV1 } from "./feature_server.mjs";

/** File encrypt params from params that carry a one-key `conversationKeys` map. */
const withKey = ({ conversationKeys, ...rest }) => {
  const [[conversationKeyVersion, conversationKey]] = Object.entries(conversationKeys);
  return { ...rest, conversationKey, conversationKeyVersion };
};

/** The one `actionSignatures` entry of a prepared delete or read receipt. */
const onlyAction = (prepared) => {
  assert.deepEqual(Object.keys(prepared), ["actionSignatures"]);
  assert.equal(prepared.actionSignatures.length, 1);
  return prepared.actionSignatures[0];
};

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

async function main() {
  // Feed wasm bytes directly (fetch of file:// URLs breaks in Node).
  const wasmUrl = new URL("../pkg/chat_xdk_wasm_bg.wasm", import.meta.url);
  const wasmBytes = await fs.readFile(wasmUrl);
  await init({ module_or_path: wasmBytes });
  keepOffline();

  const v = await loadVectors();

  // 1. Module-level utility functions

  // base64 roundtrip
  const someBytes = new Uint8Array([0, 1, 2, 3, 250, 251, 252, 253, 254, 255]);
  const b64 = bytesToBase64(someBytes);
  assert.equal(typeof b64, "string");
  assert.deepEqual(base64ToBytes(b64), someBytes);
  // matches Node's own base64 encoding
  assert.equal(b64, Buffer.from(someBytes).toString("base64"));

  assert.equal(encryptedFileSize(0), 24);
  assert.equal(encryptedFileSize(1), 42);
  assert.equal(encryptedFileSize(1024), 1065);
  assert.equal(encryptedFileSize(1025), 1083);
  assert.throws(() => encryptedFileSize(-1), /non-negative safe integer/);

  // hex roundtrip
  const hex = bytesToHex(someBytes);
  assert.equal(typeof hex, "string");
  assert.equal(hex, "000102 03fafbfcfdfeff".replace(/\s/g, ""));
  assert.deepEqual(hexToBytes(hex), someBytes);

  // detectMimeType on a PNG header (needs >= 12 bytes)
  const pngHeader = new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
    0x00, 0x00, 0x00, 0x0d,                         // IHDR length
  ]);
  assert.equal(detectMimeType(pngHeader), "image/png");
  // non-image input returns undefined
  assert.equal(detectMimeType(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b])), undefined);

  // detectImageDimensions on a small known PNG (100x200)
  const png = new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // signature
    0x00, 0x00, 0x00, 0x0d,                         // IHDR length
    0x49, 0x48, 0x44, 0x52,                         // "IHDR"
    0x00, 0x00, 0x00, 0x64,                         // width  = 100 (BE)
    0x00, 0x00, 0x00, 0xc8,                         // height = 200 (BE)
  ]);
  const dims = detectImageDimensions(png);
  assert.equal(dims.width, 100);
  assert.equal(dims.height, 200);

  // 1b. generateKeypairs returns a full registration payload (fresh Chat so
  // the fixture identity below is untouched).
  {
    const fresh = new Chat();
    const payload = fresh.generateKeypairs();
    assert.ok(payload.publicKey.publicKey.length > 0);
    assert.ok(payload.publicKey.signingPublicKey.length > 0);
    assert.ok(payload.publicKey.identityPublicKeySignature.length > 0);
    assert.equal(payload.publicKey.registrationMethod, "CustomPin");
    // Fingerprint: SHA-256 → 32 bytes → 43 URL-safe base64 chars (no padding)
    assert.equal(payload.publicKey.publicKeyFingerprint.length, 43);

    // Generated keys have no signing-key version until setIdentity.
    const deleteParams = {
      senderId: "1234",
      conversationId: "1234-5678",
      sequenceIds: ["seq-1"],
      deleteForAll: false,
    };
    assert.throws(() => fresh.prepareMessageDelete(deleteParams), /signing_key_version is not set/);
    fresh.setIdentity({ userId: "1234", signingKeyVersion: "1700000000123" });
    assert.equal(
      onlyAction(fresh.prepareMessageDelete(deleteParams)).messageEventSignature.publicKeyVersion,
      "1700000000123",
    );

    // Restored keys carry the version passed to importKeys, and none
    // without it.
    const keys = new Uint8Array(fresh.exportKeys());
    const restored = new Chat();
    restored.importKeys({ keys: keys, signingKeyVersion: "1700000000456" });
    assert.equal(
      onlyAction(restored.prepareMessageDelete(deleteParams)).messageEventSignature.publicKeyVersion,
      "1700000000456",
    );
    restored.importKeys({ keys: keys });
    assert.throws(
      () => restored.prepareMessageDelete(deleteParams),
      /signing_key_version is not set/,
    );
    restored.free();
    fresh.free();
  }

  // Set up a Chat with the fixture keys (raw crypto, no Juicebox)
  const chat = new Chat();
  chat.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64) });
  assert.equal(chat.isUnlocked(), true);

  // 1c. exportKeys returns the exact private bytes that were imported.
  assert.deepEqual(new Uint8Array(chat.exportKeys()), b64ToBytes(v.private_keys_concat_b64));

  // 1d. verifyKeyBinding: the fixture binding verifies; a tampered signature
  // and a mismatched identity key do not.
  assert.equal(
    chat.verifyKeyBinding(
      v.identity_public_b64,
      v.signing_public_b64,
      v.identity_public_key_signature_b64,
    ),
    true,
  );
  const tamperedBinding = b64ToBytes(v.identity_public_key_signature_b64);
  tamperedBinding[0] ^= 0xff;
  assert.equal(
    chat.verifyKeyBinding(
      v.identity_public_b64,
      v.signing_public_b64,
      bytesToBase64(tamperedBinding),
    ),
    false,
  );
  assert.equal(
    chat.verifyKeyBinding(
      v.signing_public_b64, // wrong key in the identity slot
      v.signing_public_b64,
      v.identity_public_key_signature_b64,
    ),
    false,
  );

  // matchesRegisteredKey: the loaded identity key matches in both the
  // SPKI form (what the X API returns) and the raw SEC1 form (what
  // getPublicKeys returns); a different key does not.
  {
    const fresh = new Chat();
    const payload = fresh.generateKeypairs();
    assert.equal(fresh.matchesRegisteredKey(payload.publicKey.publicKey), true);
    assert.equal(fresh.matchesRegisteredKey(fresh.getPublicKeys().identity), true);
    assert.equal(fresh.matchesRegisteredKey(v.identity_public_b64), false);
    // Invalid base64 throws rather than returning false.
    assert.throws(() => fresh.matchesRegisteredKey('not base64!!'));
    fresh.free();
  }
  {
    // No identity loaded throws rather than returning false.
    const locked = new Chat();
    assert.throws(() => locked.matchesRegisteredKey(v.identity_public_b64));
    locked.free();
  }
  assert.equal(chat.matchesRegisteredKey(v.identity_public_b64), true);
  assert.equal(chat.matchesRegisteredKey(v.signing_public_b64), false);

  // 1e. extractConversationKeys: empty input yields an empty bundle; the
  // fixture KeyChange yields the fixture conversation key.
  const emptyBundle = chat.extractConversationKeys([]);
  assert.deepEqual(Object.keys(emptyBundle.keys), []);
  assert.equal(emptyBundle.latestVersion, null);
  const bundle = chat.extractConversationKeys([v.event_key_change_b64]);
  assert.equal(bundle.latestVersion, v.event_conversation_key_version);
  assert.deepEqual(
    bundle.keys[v.event_conversation_key_version],
    b64ToBytes(v.conversation_key_b64),
  );

  // 2. Conversation-key change: generate + encrypt + sign, then ECIES roundtrip
  const prep = chat.prepareConversationKeyChange({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "conv-1",
  });
  assert.ok(prep.conversationKey instanceof Uint8Array);
  assert.equal(prep.conversationKey.length, 32);
  assert.equal(prep.conversationId, "conv-1");
  assert.equal(prep.conversationParticipantKeys.length, 1);
  // The entries take the request's field names.
  assert.deepEqual(Object.keys(prep.conversationParticipantKeys[0]).sort(), [
    "encryptedConversationKey",
    "publicKeyVersion",
    "userId",
  ]);
  assert.equal(prep.actionSignatures.length, 1);
  // Omitted: the payload embeds the plaintext conversation key and is withheld.
  assert.equal(prep.actionSignatures[0].signaturePayload, undefined);
  // Nested as the request's actionSignatures carry it.
  assert.equal(prep.actionSignatures[0].messageEventSignature.publicKeyVersion, "1");
  assert.equal(prep.actionSignatures[0].messageEventSignature.signingPublicKey, chat.getPublicKeys().signing);
  const decryptedKey = chat.decryptConversationKey(prep.conversationParticipantKeys[0].encryptedConversationKey);
  assert.deepEqual(decryptedKey, prep.conversationKey);
  // two prepared changes generate different keys (randomized)
  const prep2 = chat.prepareConversationKeyChange({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "conv-1",
  });
  assert.notDeepEqual(prep.conversationKey, prep2.conversationKey);

  // 2b. Group create: emits two action signatures (CKCE + GroupCreate) with
  // populated encoded event details.
  const groupPrep = chat.prepareGroupCreate({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "g-1",
    memberIds: ["910002", "910005"],
    adminIds: ["910002"],
    title: "My Group",
  });
  assert.equal(groupPrep.conversationId, "g-1");
  assert.equal(groupPrep.actionSignatures.length, 2);
  // Omitted: the payload embeds the plaintext conversation key and is withheld.
  assert.equal(groupPrep.actionSignatures[0].signaturePayload, undefined);
  assert.ok(groupPrep.actionSignatures[0].encodedMessageEventDetail.length > 0);
  assert.ok(groupPrep.actionSignatures[1].signaturePayload.startsWith("GroupChangeEvent.GroupCreate,"));
  assert.ok(groupPrep.actionSignatures[1].encodedMessageEventDetail.length > 0);

  // 2c. An empty title is the "not set" encoding: it signs the null
  // sentinel, exactly like omitting the field.
  for (const title of ["", undefined]) {
    const p = chat.prepareGroupCreate({
      senderId: "910002",
      signingKeyVersion: "1",
      publicKeys: [{ userId: "910002", publicKey: v.identity_public_b64, keyVersion: "1" }],
      conversationId: "g-1",
      memberIds: ["910002", "910005"],
      adminIds: ["910002"],
      title,
      avatarUrl: title,
    });
    assert.ok(
      p.actionSignatures[1].signaturePayload.endsWith(",null,null,null"),
      `title/avatar must sign as the null sentinel, got: ${p.actionSignatures[1].signaturePayload}`,
    );
  }

  const convKey = b64ToBytes(v.conversation_key_b64);

  // 3. encrypt/decrypt (generic string) + encryptFile/decryptFile
  const text = "group name \u{1F510} \u00e9\u00e8";
  const ciphertextB64 = chat.encrypt(text, convKey);
  assert.equal(typeof ciphertextB64, "string");
  assert.equal(chat.decrypt(ciphertextB64, convKey), text);
  // randomized ciphertext
  assert.notEqual(chat.encrypt(text, convKey), chat.encrypt(text, convKey));

  // A message with files is built first; each file is then encrypted from
  // the returned eventB64 and the media hash key its attachment names, and
  // decrypts through the sent message's event.
  const sender = new Chat();
  const v1Sender = await v1Chat();
  for (const from of [sender, v1Sender]) {
    from.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64), signingKeyVersion: v.event_recipient_key_version });
    from.setIdentity({ userId: "111", signingKeyVersion: "1" });
  }
  const mediaHashKey = "photo";
  const mediaKeys = { "1": convKey };
  const photoAttachment = (hash) => ({
    attachment_type: "media",
    media_hash_key: hash,
    width: 4,
    height: 3,
    filesize_bytes: 64,
    filename: `${hash}.jpg`,
    media_type: 1,
  });
  const photosFrom = (from) => (text, hashes) =>
    from.encryptMessage({
      conversationId: "conv-1",
      text,
      conversationKey: convKey,
      conversationKeyVersion: "1",
      attachments: hashes.map(photoAttachment),
    });
  const sendPhotos = photosFrom(sender);
  const sendV1Photos = photosFrom(v1Sender);
  const photoPayload = sendPhotos("a photo", [mediaHashKey]);
  const mediaEvent = photoPayload.eventB64;
  const fileParams = { eventB64: mediaEvent, conversationKeys: mediaKeys, mediaHashKey };

  const plaintext = b64ToBytes(v.plaintext_b64);
  // A session with no identity encrypts the file.
  const fileCt1 = new Chat().encryptFile(withKey({ ...fileParams, file: plaintext }));
  const fileCt2 = sender.encryptFile(withKey({ ...fileParams, file: plaintext }));
  assert.notDeepEqual(fileCt1, fileCt2); // randomized nonces
  assert.equal(fileCt1.length, encryptedFileSize(plaintext.length));
  assert.deepEqual(chat.decryptFile({ ...fileParams, encrypted: fileCt1 }), plaintext);

  // A v0 message, the default, takes a random id, as 0.5.x did.
  assert.notEqual(sendPhotos("a photo", [mediaHashKey]).messageId, photoPayload.messageId);

  // A v1 message with files takes the id its files derive: building it again
  // gives the same id, so files already encrypted stay valid.
  await waitForV1(() => sendV1Photos("turn v1 on", ["turn-v1-on"]));
  const v1PhotoPayload = sendV1Photos("a photo", [mediaHashKey]);
  assert.equal(sendV1Photos("another caption", [mediaHashKey]).messageId, v1PhotoPayload.messageId);
  assert.notEqual(sendV1Photos("a photo", ["other"]).messageId, v1PhotoPayload.messageId);
  assert.match(v1PhotoPayload.messageId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

  // Each file needs its own media hash key.
  assert.throws(
    () => sendV1Photos("twice", [mediaHashKey, mediaHashKey]),
    /media_hash_key 'photo' is in more than one attachment/,
  );

  // File errors say what to pass instead.
  assert.throws(
    () => sender.encryptFile(withKey({ ...fileParams, file: plaintext, mediaHashKey: "other" })),
    /is not one of the message's files/,
  );
  assert.throws(
    () => sender.encryptFile(withKey({ ...fileParams, file: [1, 2, 3] })),
    /Invalid encryptFile params: file must be a Uint8Array/,
  );
  assert.throws(
    () => sender.encryptFile(withKey({ ...fileParams, file: plaintext, conversationKeys: { "1": new Uint8Array(3) } })),
    /Invalid conversation key \(expected 32 bytes\)/,
  );
  assert.throws(
    () => sender.encryptFile(withKey({ ...fileParams, file: plaintext, conversationKeys: { "9": convKey } })),
    /conversation_key_version '9' is not the message's key version '1'/,
  );
  assert.throws(
    () => sender.encryptFile(withKey({ eventB64: mediaEvent, conversationKeys: mediaKeys, file: plaintext })),
    /Invalid encryptFile params.*missing field `mediaHashKey`/,
  );

  // 3b. Incremental files: chunked encryptor/decryptor roundtrip over a
  // multi-frame payload, and a truncated file fails at finish (missing
  // final frame).
  {
    const concat = (pieces) => {
      const out = new Uint8Array(pieces.reduce((n, p) => n + p.length, 0));
      let off = 0;
      for (const p of pieces) {
        out.set(p, off);
        off += p.length;
      }
      return out;
    };
    const bigPlain = new Uint8Array(5000).fill(0xab);
    const enc = sender.fileEncryptor(withKey(fileParams));
    const ctPieces = [];
    for (let i = 0; i < bigPlain.length; i += 700) {
      ctPieces.push(enc.push(bigPlain.subarray(i, i + 700)));
    }
    ctPieces.push(enc.finish());
    const ciphertext = concat(ctPieces);
    assert.equal(ciphertext.length, encryptedFileSize(bigPlain.length));

    const dec = chat.fileDecryptor(fileParams);
    const ptPieces = [];
    for (let i = 0; i < ciphertext.length; i += 333) {
      ptPieces.push(dec.push(ciphertext.subarray(i, i + 333)));
    }
    ptPieces.push(dec.finish());
    assert.deepEqual(concat(ptPieces), bigPlain);

    const truncated = chat.fileDecryptor(fileParams);
    truncated.push(ciphertext.subarray(0, ciphertext.length - 4));
    assert.throws(() => truncated.finish(), /truncated/);
  }

  // 4. encryptMessage returns a SendPayload with signatureVersion === "7"
  //    (v0) until the v1_send feature switch is on.
  const payload = chat.encryptMessage({
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    text: "hello world",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
  });
  // The SDK generates and returns the message id.
  assert.equal(typeof payload.messageId, "string");
  assert.ok(payload.messageId.length > 0);
  // The payload's fields take the send request's names.
  assert.ok(payload.encodedMessageCreateEvent.length > 0);
  assert.ok(payload.encodedMessageEventSignature.length > 0);
  assert.equal(typeof payload.signature, "string");
  assert.ok(payload.signatureInfo);
  assert.equal(payload.signatureInfo.signatureVersion, "7");
  assert.equal(payload.conversationKeyVersion, "1");
  assert.equal(typeof payload.xdkVersion, "string");
  assert.ok(payload.xdkVersion.length > 0);

  // 4b. encryptReply produces a signed payload like encryptMessage
  const replyPayload = chat.encryptReply({
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    text: "this is my reply",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
    replyToSequenceId: "seq-42",
    replyToSenderId: "12345",
    replyToText: "original message",
  });
  assert.ok(replyPayload.encodedMessageCreateEvent.length > 0);
  assert.ok(replyPayload.signature.length > 0);
  assert.ok(replyPayload.encodedMessageEventSignature.length > 0);
  assert.equal(replyPayload.signatureInfo.signatureVersion, "7");
  assert.equal(replyPayload.conversationKeyVersion, "1");

  // 4c. Once the feature switches turn v1_send on, sends switch to v1
  //     (signature version 10). A chat of its own, so `chat` keeps sending v0;
  //     its answer comes late, so its first send is v0.
  const lateAnswer = await featureServer();
  lateAnswer.delayMs = 500;
  const switching = reading(lateAnswer.endpoint);
  switching.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64) });
  const sendHello = () =>
    switching.encryptMessage({
      senderId: "111",
      conversationId: "conv-1",
      conversationKey: convKey,
      text: "hello v1",
      conversationKeyVersion: "1",
      signingKeyVersion: "1",
    });
  assert.equal(sendHello().signatureInfo.signatureVersion, "7");
  await waitForV1(sendHello);
  assert.equal(sendHello().signatureInfo.signatureVersion, "10");
  switching.free();
  await lateAnswer.close();

  // Own sends decrypt through their eventB64, verified against the fixture
  // signing key registered to sender 111.
  const ownSigningKeys = [
    {
      userId: "111",
      publicKeyVersion: "1",
      publicKey: v.signing_public_b64,
      identityPublicKey: v.identity_public_b64,
      identityPublicKeySignature: v.identity_public_key_signature_b64,
    },
  ];
  const decryptOwn = (sent) => {
    const event = chat.decryptEvent({
      eventB64: sent.eventB64,
      conversationKeys: { "1": convKey },
      signingKeys: ownSigningKeys,
    });
    assert.equal(event.verified, true);
    assert.equal(event.id, sent.messageId);
    assert.equal(event.sequenceId, null);
    return event.content;
  };

  // 4b2. replyToSenderId precision: a snowflake-sized id passed as a string
  // must land in the reply payload exactly. The id is above 2^53, where JS
  // numbers stop being exact.
  const bigSenderId = 0x2122232425262728n; // 2387509390608492328 > 2^53
  const replyParamsBase = {
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    text: "precision reply",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
    replyToSequenceId: "seq-43",
    replyToText: "original",
  };
  const bigReplyPayload = chat.encryptReply({
    ...replyParamsBase,
    replyToSenderId: bigSenderId.toString(),
  });
  assert.equal(
    decryptOwn(bigReplyPayload).replyingToPreview.senderId,
    bigSenderId.toString(),
    "the decrypted reply preview must carry the exact sender id",
  );
  // A user id is a digits-only string: numbers, which JS may already have
  // rounded, and other strings are rejected.
  assert.throws(
    () => chat.encryptReply({ ...replyParamsBase, replyToSenderId: Number(bigSenderId) }),
    /replyToSenderId/,
  );
  assert.throws(
    () => chat.encryptReply({ ...replyParamsBase, replyToSenderId: 12345 }),
    /replyToSenderId/,
  );
  assert.throws(
    () => chat.encryptReply({ ...replyParamsBase, replyToSenderId: "not-a-number" }),
    /Invalid reply_to_sender_id 'not-a-number'/,
  );

  // 4c. encryptAddReaction / encryptRemoveReaction produce signed payloads
  const reactionParams = {
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    targetMessageSequenceId: "seq-99",
    emoji: "\u{1F44D}",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
  };
  const addPayload = chat.encryptAddReaction(reactionParams);
  assert.ok(addPayload.encodedMessageCreateEvent.length > 0);
  assert.ok(addPayload.signature.length > 0);
  assert.ok(addPayload.encodedMessageEventSignature.length > 0);
  const removePayload = chat.encryptRemoveReaction(reactionParams);
  assert.ok(removePayload.encodedMessageCreateEvent.length > 0);
  assert.ok(removePayload.signature.length > 0);
  assert.ok(removePayload.encodedMessageEventSignature.length > 0);

  // 4c2. encryptEdit produces a signed payload that decrypts back to the
  // edit: updated text, target sequence id, and the [start, end, type]
  // entity tuple all survive the WASM boundary.
  const editPayload = chat.encryptEdit({
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    targetMessageSequenceId: "seq-99",
    updatedText: "see https://example.com",
    entities: [[4, 23, "url"]],
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
  });
  assert.ok(editPayload.encodedMessageCreateEvent.length > 0);
  assert.ok(editPayload.signature.length > 0);
  assert.ok(editPayload.encodedMessageEventSignature.length > 0);
  assert.ok(editPayload.messageId.length > 0);
  const decodedEdit = decryptOwn(editPayload);
  assert.equal(decodedEdit.newText, "see https://example.com");
  assert.equal(decodedEdit.targetMessageId, "seq-99");
  assert.equal(decodedEdit.entities.length, 1);
  assert.equal(decodedEdit.entities[0].startIndex, 4);
  assert.equal(decodedEdit.entities[0].endIndex, 23);

  // 4c3. prepareMessageDelete returns the request's actionSignatures: one
  // signed action with the encoded MessageDeleteEvent detail, its signature
  // nested; 1:1 ids are signed in canonical colon form.
  const deleteSig = onlyAction(chat.prepareMessageDelete({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "222-111",
    sequenceIds: ["seq-10", "seq-11"],
    deleteForAll: true,
  }));
  assert.ok(deleteSig.messageId.length > 0);
  assert.ok(deleteSig.encodedMessageEventDetail.length > 0);
  assert.deepEqual(Object.keys(deleteSig.messageEventSignature).sort(), [
    "publicKeyVersion",
    "signature",
    "signatureVersion",
    "signingPublicKey",
  ]);
  assert.ok(deleteSig.messageEventSignature.signature.length > 0);
  assert.equal(deleteSig.messageEventSignature.signatureVersion, "7");
  assert.equal(deleteSig.messageEventSignature.publicKeyVersion, "1");
  assert.equal(deleteSig.messageEventSignature.signingPublicKey, chat.getPublicKeys().signing);
  assert.equal(
    deleteSig.signaturePayload,
    `MessageDeleteEvent,${deleteSig.messageId},111,111:222,2,seq-10,seq-11`,
  );
  const deleteForSelfSig = onlyAction(chat.prepareMessageDelete({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g999",
    sequenceIds: ["seq-1"],
    deleteForAll: false,
  }));
  assert.equal(
    deleteForSelfSig.signaturePayload,
    `MessageDeleteEvent,${deleteForSelfSig.messageId},111,g999,1,seq-1`,
  );

  // 4c5. Group actions: a removal signs version 11 and rotates the key for
  // the members who stay, and the other prepares sign one version-7 payload.
  const keys = chat.getPublicKeys();
  const remaining = [{ userId: "111", publicKey: keys.identity, keyVersion: "1" }];
  const rotated = chat.prepareGroupMembersRemove({
    senderId: "111",
    signingKeyVersion: "1",
    publicKeys: remaining,
    conversationId: "g100",
    userIds: ["910007"],
  });
  assert.equal(rotated.conversationKey.length, 32);
  assert.equal(rotated.conversationParticipantKeys.length, 1);
  assert.equal(rotated.actionSignatures.length, 2);
  assert.equal(rotated.actionSignatures[0].messageEventSignature.signatureVersion, "11");
  assert.ok(
    rotated.actionSignatures[0].signaturePayload.endsWith(
      `,910007,${rotated.conversationKeyVersion},signature_version=11`,
    ),
  );
  assert.equal(rotated.actionSignatures[1].signaturePayload, undefined);
  assert.throws(
    () => chat.prepareGroupMembersRemove({
      senderId: "111",
      signingKeyVersion: "1",
      publicKeys: [],
      conversationId: "g100",
      userIds: ["910007"],
    }),
    /public_keys is empty: pass the public keys of the remaining members/,
  );

  const left = chat.prepareGroupLeave({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g100",
    promoteAdminId: "910008",
    conversationKeyVersion: "7",
  });
  assert.equal(left.actionSignatures.length, 3);
  assert.ok(left.actionSignatures[1].signaturePayload.endsWith(",910008"));
  assert.ok(left.actionSignatures[2].signaturePayload.startsWith("ConversationDeleteEvent,"));

  const title = chat.prepareGroupTitleChange({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g100",
    conversationKeyVersion: "4",
    customTitle: "enc-title",
  });
  assert.ok(onlyAction(title).signaturePayload.endsWith(",4,enc-title"));
  const description = onlyAction(chat.prepareGroupDescriptionChange({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g100",
    conversationKeyVersion: "4",
    customDescription: "enc-desc",
  }));
  assert.ok(description.signaturePayload.startsWith("GroupChangeEvent.GroupDescriptionChange,"));
  const blocking = onlyAction(chat.prepareScreenCapture({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g100",
    change: "blockingEnabled",
  }));
  assert.ok(blocking.signaturePayload.startsWith(
    "ConversationMetadataChangeEvent.EnableScreenCaptureBlocking,",
  ));
  const detection = onlyAction(chat.prepareScreenCapture({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g100",
    change: "detectionDisabled",
  }));
  assert.ok(detection.signaturePayload.startsWith(
    "ConversationMetadataChangeEvent.DisableScreenCaptureDetection,",
  ));
  assert.throws(
    () => chat.prepareScreenCapture({
      senderId: "111",
      signingKeyVersion: "1",
      conversationId: "g100",
      change: "nope",
    }),
    /Invalid screen capture change: 'nope'/,
  );

  // 4c4. prepareMarkConversationRead signs the read point and its time with
  // the signing key; 1:1 ids are signed in canonical colon form.
  const readSig = onlyAction(chat.prepareMarkConversationRead({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "222-111",
    seenUntilSequenceId: "2011626338877079553",
    seenAtMsec: 1700000000123,
  }));
  assert.ok(readSig.messageId.length > 0);
  assert.ok(readSig.encodedMessageEventDetail.length > 0);
  assert.equal(readSig.messageEventSignature.publicKeyVersion, "1");
  assert.equal(readSig.messageEventSignature.signingPublicKey, chat.getPublicKeys().signing);
  assert.equal(
    readSig.signaturePayload,
    `MarkConversationReadEvent,${readSig.messageId},111,111:222,2011626338877079553,1700000000123`,
  );
  assert.equal(
    chat.verify(
      v.signing_public_b64,
      b64ToBytes(readSig.messageEventSignature.signature),
      new TextEncoder().encode(readSig.signaturePayload),
    ),
    true,
  );

  // An omitted seenAtMsec signs the JavaScript clock's current time.
  const beforeRead = Date.now();
  const readNowSig = onlyAction(chat.prepareMarkConversationRead({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g999",
    seenUntilSequenceId: "seq-1",
  }));
  const afterRead = Date.now();
  const readNowPrefix = `MarkConversationReadEvent,${readNowSig.messageId},111,g999,seq-1,`;
  assert.ok(readNowSig.signaturePayload.startsWith(readNowPrefix));
  const readNowAt = Number(readNowSig.signaturePayload.slice(readNowPrefix.length));
  assert.ok(readNowAt >= beforeRead && readNowAt <= afterRead);

  assert.throws(
    () =>
      chat.prepareMarkConversationRead({
        senderId: "111",
        signingKeyVersion: "1",
        conversationId: "g999",
      }),
    /prepareMarkConversationRead params.*seenUntilSequenceId/,
  );
  assert.throws(
    () =>
      chat.prepareMarkConversationRead({
        senderId: "111",
        signingKeyVersion: "1",
        conversationId: "g999",
        seenUntilSequenceId: "",
      }),
    /seen_until_sequence_id is empty/,
  );

  // 4d. prepareGroupMembersChange emits two action signatures (CKCE + member
  // add) with populated encoded event details and a fresh raw key.
  const membersPrep = chat.prepareGroupMembersChange({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "g-1",
    newMemberIds: ["910005"],
    currentMemberIds: ["910002"],
    currentAdminIds: ["910002"],
    currentPendingMemberIds: [],
  });
  assert.equal(membersPrep.conversationId, "g-1");
  assert.ok(membersPrep.conversationKey instanceof Uint8Array);
  assert.equal(membersPrep.conversationKey.length, 32);
  assert.equal(membersPrep.actionSignatures.length, 2);
  assert.ok(membersPrep.actionSignatures[0].encodedMessageEventDetail.length > 0);
  assert.ok(membersPrep.actionSignatures[1].encodedMessageEventDetail.length > 0);
  assert.ok(
    membersPrep.actionSignatures[1].signaturePayload.startsWith(
      "GroupChangeEvent.GroupMemberAddChange,",
    ),
  );
  // Unset screen-capture blocking signs as the trailing null sentinel.
  assert.ok(membersPrep.actionSignatures[1].signaturePayload.endsWith(",null"));

  // 4d2. The group's screen-capture-blocking state fills the trailing signed slot.
  const membersPrepScb = chat.prepareGroupMembersChange({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "g-1",
    newMemberIds: ["910005"],
    currentMemberIds: ["910002"],
    currentAdminIds: ["910002"],
    currentPendingMemberIds: [],
    currentScreenCaptureBlockingEnabled: true,
  });
  assert.ok(membersPrepScb.actionSignatures[1].signaturePayload.endsWith(",true"));

  // 4d3. Omitting conversationId derives the canonical numeric-sorted
  // one-to-one id from the two participants.
  const derivedPrep = chat.prepareConversationKeyChange({
    senderId: "1491585161162473473",
    signingKeyVersion: "1",
    publicKeys: [
      { userId: "1491585161162473473", publicKey: v.identity_public_b64, keyVersion: "1" },
      { userId: "17380288", publicKey: v.identity_public_b64, keyVersion: "1" },
    ],
  });
  assert.equal(derivedPrep.conversationId, "17380288:1491585161162473473");

  // 4e. A params object missing a required field throws an error naming it.
  assert.throws(
    () =>
      chat.encryptMessage({
        senderId: "111",
        conversationKey: convKey,
        text: "hello world",
        conversationKeyVersion: "1",
        signingKeyVersion: "1",
      }),
    /encryptMessage params.*conversationId/,
  );

  // 4e2. senderId is optional in the params object, but with no session
  // identity set either, the core rejects the encrypt naming sender_id.
  assert.throws(
    () =>
      chat.encryptMessage({
        conversationId: "conv-1",
        conversationKey: convKey,
        text: "hello world",
        conversationKeyVersion: "1",
        signingKeyVersion: "1",
      }),
    /sender_id/,
  );

  // 4e3. A conversation key without its version (or vice versa) is rejected:
  // the pair travels together.
  assert.throws(
    () =>
      chat.encryptMessage({
        senderId: "111",
        conversationId: "conv-1",
        conversationKey: convKey,
        text: "hello world",
        signingKeyVersion: "1",
      }),
    /conversation_key_version/,
  );

  // 4f. A media attachment missing its required fields (width, height,
  // filesize_bytes, filename) is rejected rather than silently defaulted.
  assert.throws(
    () =>
      chat.encryptMessage({
        senderId: "111",
        conversationId: "conv-1",
        conversationKey: convKey,
        text: "hello world",
        conversationKeyVersion: "1",
        signingKeyVersion: "1",
        attachments: [{ attachment_type: "media", media_hash_key: "h" }],
      }),
    /encryptMessage params/,
  );

  // 4g. A URL card attachment carries encrypted banner/favicon image
  // references (media hash keys) for clickable preview cards.
  const urlCardPayload = v1Sender.encryptMessage({
    conversationId: "conv-1",
    conversationKey: convKey,
    text: "check this out",
    conversationKeyVersion: "1",
    attachments: [
      {
        attachment_type: "url",
        url: "https://example.com/product",
        display_title: "Example Product",
        banner_image: {
          media_hash_key: "banner-hash",
          filesize_bytes: 24000,
          filename: "banner.jpg",
          width: 1200,
          height: 630,
        },
        favicon_image: {
          media_hash_key: "favicon-hash",
          filesize_bytes: 1200,
          filename: "favicon.ico",
        },
      },
    ],
  });
  assert.ok(urlCardPayload.encodedMessageCreateEvent.length > 0);
  assert.ok(urlCardPayload.signature.length > 0);
  assert.deepEqual(
    chat.decryptFile({
      encrypted: v1Sender.encryptFile(withKey({
        file: plaintext,
        eventB64: urlCardPayload.eventB64,
        conversationKeys: mediaKeys,
        mediaHashKey: "favicon-hash",
      })),
      eventB64: urlCardPayload.eventB64,
      conversationKeys: mediaKeys,
      mediaHashKey: "favicon-hash",
    }),
    plaintext,
  );

  // 4h. A banner image missing any of its required fields is rejected.
  // media_hash_key, filesize_bytes, and filename are all mandatory: receiving
  // clients silently discard the preview image when any is missing.
  for (const incompleteBanner of [
    { filesize_bytes: 24000, filename: "banner.jpg" }, // no media_hash_key
    { media_hash_key: "banner-hash", filename: "banner.jpg" }, // no filesize_bytes
    { media_hash_key: "banner-hash", filesize_bytes: 24000 }, // no filename
  ]) {
    assert.throws(
      () =>
        chat.encryptMessage({
          senderId: "111",
          conversationId: "conv-1",
          conversationKey: convKey,
          text: "check this out",
          conversationKeyVersion: "1",
          signingKeyVersion: "1",
          attachments: [
            {
              attachment_type: "url",
              url: "https://example.com",
              banner_image: incompleteBanner,
            },
          ],
        }),
      /encryptMessage params/,
    );
  }

  // 4i. Only image/gif/video media may appear in multiples; a list mixing a
  // media attachment with a URL card is rejected before encryption.
  assert.throws(
    () =>
      chat.encryptMessage({
        senderId: "111",
        conversationId: "conv-1",
        conversationKey: convKey,
        text: "mixed attachments",
        conversationKeyVersion: "1",
        signingKeyVersion: "1",
        attachments: [
          {
            attachment_type: "media",
            media_hash_key: "h",
            width: 100,
            height: 100,
            filesize_bytes: 1000,
            filename: "pic.jpg",
            media_type: 1,
          },
          { attachment_type: "url", url: "https://example.com" },
        ],
      }),
    /attachment combination/,
  );

  // 5. decryptEvents / decryptEvent throw on a malformed (3-field) signingKeys entry
  const malformedSigningKeys = [
    { userId: "111", publicKeyVersion: "1", publicKey: v.signing_public_b64 },
  ];
  assert.throws(
    () => chat.decryptEvents({ events: ["AAAA"], signingKeys: malformedSigningKeys }),
    /Invalid decryptEvents params.*missing field `identityPublicKey`/,
  );
  assert.throws(
    () => chat.decryptEvent({ eventB64: "AAAA", conversationKeys: {}, signingKeys: malformedSigningKeys }),
    /Invalid decryptEvent params.*missing field `identityPublicKey`/,
  );

  // 5b. decryptEvent's key map is optional: omitted or null, it reads as an
  // empty map. A value that is not an object, or an entry that is not a
  // 32-byte key, is an error.
  const outcome = (params) => {
    try {
      return chat.decryptEvent(params);
    } catch (e) {
      return String(e);
    }
  };
  const withEmptyMap = outcome({ eventB64: v.event_message_b64, conversationKeys: {} });
  assert.deepEqual(outcome({ eventB64: v.event_message_b64 }), withEmptyMap);
  assert.deepEqual(outcome({ eventB64: v.event_message_b64, conversationKeys: null }), withEmptyMap);
  assert.throws(
    () => chat.decryptEvent({ eventB64: v.event_message_b64, conversationKeys: "keys" }),
    /conversationKeys must be an object/,
  );
  assert.throws(
    () => chat.decryptEvent({ eventB64: v.event_message_b64, conversationKeys: bundle }),
    /the key for version 'keys' in the conversation key map is not 32 bytes/,
  );

  // 6. Juicebox guess-budget parity with the native bindings: the config's
  // max_guess_count applies, defaults are shape-dependent (sdk_config and
  // key_store_token_map_json → 20, bare token_map → 5), and the explicit
  // option is an override only.
  const { resolveMaxGuessCount } = await import("../index.js");
  const sdkConfigShape = { sdk_config: '{"realms":[]}', tokens: {} };
  const tokenMapShape = { token_map: [] };
  const xApiShape = { key_store_token_map_json: '{"realms":[]}', token_map: [] };
  assert.equal(resolveMaxGuessCount({ ...sdkConfigShape, max_guess_count: 7 }), 7);
  assert.equal(resolveMaxGuessCount({ ...tokenMapShape, max_guess_count: 7 }), 7);
  assert.equal(resolveMaxGuessCount({ ...xApiShape, max_guess_count: 7 }), 7);
  assert.equal(resolveMaxGuessCount(sdkConfigShape), 20);
  assert.equal(resolveMaxGuessCount(tokenMapShape), 5);
  assert.equal(resolveMaxGuessCount(xApiShape), 20);
  assert.equal(resolveMaxGuessCount({ ...sdkConfigShape, max_guess_count: 7 }, 9), 9);
  // Edge semantics match Rust's `as_u64`: a present integer (0 included) is
  // used as-is; fractional, negative, or non-numeric values fall back to the
  // shape default.
  assert.equal(resolveMaxGuessCount({ ...sdkConfigShape, max_guess_count: 0 }), 0);
  assert.equal(resolveMaxGuessCount({ ...tokenMapShape, max_guess_count: 0 }), 0);
  assert.equal(resolveMaxGuessCount({ ...sdkConfigShape, max_guess_count: 7.5 }), 20);
  assert.equal(resolveMaxGuessCount({ ...tokenMapShape, max_guess_count: 7.5 }), 5);
  assert.equal(resolveMaxGuessCount({ ...sdkConfigShape, max_guess_count: -3 }), 20);
  assert.equal(resolveMaxGuessCount({ ...tokenMapShape, max_guess_count: -3 }), 5);
  assert.equal(resolveMaxGuessCount({ ...sdkConfigShape, max_guess_count: "9" }), 20);
  // The explicit override obeys the same integer rule (0 valid, 7.5 not).
  assert.equal(resolveMaxGuessCount({ ...tokenMapShape, max_guess_count: 7 }, 0), 0);
  assert.equal(resolveMaxGuessCount({ ...tokenMapShape, max_guess_count: 7 }, 7.5), 7);
  assert.equal(resolveMaxGuessCount({ ...tokenMapShape, max_guess_count: 7 }, -1), 7);

  // 7. Config-shape parity with the native bindings: every shape
  // from_x_api_json accepts must be usable here, with the same realm
  // derivation (register = all, recover = majority).
  const { juiceboxClientConfig } = await import("../index.js");
  assert.equal(juiceboxClientConfig(sdkConfigShape), '{"realms":[]}');
  const derived = juiceboxClientConfig({
    token_map: [
      { key: "r1", value: { address: "https://r1.example", token: "t1" } },
      { key: "r2", value: { address: "https://r2.example", token: "t2" } },
      { key: "r3", value: { address: "https://r3.example", token: "t3" } },
    ],
  });
  assert.deepEqual(derived.realms, [
    { id: "r1", address: "https://r1.example" },
    { id: "r2", address: "https://r2.example" },
    { id: "r3", address: "https://r3.example" },
  ]);
  assert.equal(derived.register_threshold, 3);
  assert.equal(derived.recover_threshold, 2);
  assert.equal(derived.pin_hashing_mode, "Standard2019");
  const rawRealms = { realms: [{ id: "r1", address: "https://r1.example" }] };
  assert.equal(juiceboxClientConfig(rawRealms), rawRealms);
  assert.throws(
    () => juiceboxClientConfig({ token_map: [{ key: "r1" }] }),
    /Invalid token_map entry/,
  );

  console.log("api.test.mjs: all assertions passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
