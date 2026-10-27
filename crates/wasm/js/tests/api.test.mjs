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

/**
 * Whether `sig`'s signature verifies, under the signer's own signing key,
 * over `payload`: the comma-joined fields its event signs.
 */
const signs = (chat, sig, payload) =>
  chat.verify(
    sig.messageEventSignature.signingPublicKey,
    b64ToBytes(sig.messageEventSignature.signature),
    new TextEncoder().encode(payload),
  );

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
    publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
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
  // Nested as the request's actionSignatures carry it.
  assert.equal(prep.actionSignatures[0].messageEventSignature.publicKeyVersion, "1");
  assert.equal(prep.actionSignatures[0].messageEventSignature.signingPublicKey, chat.getPublicKeys().signing);
  const decryptedKey = chat.decryptConversationKey(prep.conversationParticipantKeys[0].encryptedConversationKey);
  assert.deepEqual(decryptedKey, prep.conversationKey);
  // two prepared changes generate different keys (randomized)
  const prep2 = chat.prepareConversationKeyChange({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
    conversationId: "conv-1",
  });
  assert.notDeepEqual(prep.conversationKey, prep2.conversationKey);

  // 2b. Group create: emits two action signatures (CKCE + GroupCreate) with
  // populated encoded event details.
  const groupPrep = chat.prepareGroupCreate({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
    conversationId: "g-1",
    memberIds: ["910002", "910005"],
    adminIds: ["910002"],
    title: "My Group",
  });
  assert.equal(groupPrep.conversationId, "g-1");
  assert.equal(groupPrep.actionSignatures.length, 2);
  assert.ok(groupPrep.actionSignatures[0].encodedMessageEventDetail.length > 0);
  assert.ok(groupPrep.actionSignatures[1].encodedMessageEventDetail.length > 0);
  // The title goes out encrypted under the new key, the value the request
  // sends as group_name; the signature covers the ciphertext.
  assert.equal(typeof groupPrep.encryptedTitle, "string");
  const groupCreate = groupPrep.actionSignatures[1];
  assert.ok(signs(chat, groupCreate,
    `GroupChangeEvent.GroupCreate,${groupCreate.messageId},910002,${groupPrep.conversationKeyVersion},` +
    `910002,910005,null,${groupPrep.encryptedTitle},null`));
  assert.equal(chat.decrypt(groupPrep.encryptedTitle, groupPrep.conversationKey), "My Group");
  assert.equal("encryptedDescription" in groupPrep, false);
  const commaPrep = chat.prepareGroupCreate({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
    conversationId: "g-1",
    memberIds: ["910002"],
    adminIds: ["910002"],
    title: "Team, the sequel",
  });
  assert.equal(chat.decrypt(commaPrep.encryptedTitle, commaPrep.conversationKey), "Team, the sequel");

  // 2c. An empty title is the "not set" encoding: it signs the null
  // sentinel, exactly like omitting the field.
  for (const title of ["", undefined]) {
    const p = chat.prepareGroupCreate({
      senderId: "910002",
      signingKeyVersion: "1",
      publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
      conversationId: "g-1",
      memberIds: ["910002", "910005"],
      adminIds: ["910002"],
      title,
    });
    const create = p.actionSignatures[1];
    assert.ok(
      signs(chat, create,
        `GroupChangeEvent.GroupCreate,${create.messageId},910002,${p.conversationKeyVersion},` +
        "910002,910005,null,null,null"),
      "the title and avatar must sign as the null sentinel",
    );
    assert.equal("encryptedTitle" in p, false);
  }

  const convKey = b64ToBytes(v.conversation_key_b64);

  // 3. decrypt (the group title a title change sends) + encryptFile/decryptFile
  const text = "group name \u{1F510} \u00e9\u00e8";
  const titleParams = {
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g100",
    newTitle: text,
    conversationKey: convKey,
    conversationKeyVersion: "4",
  };
  const ciphertextB64 = chat.prepareGroupTitleChange(titleParams).encryptedValue;
  assert.equal(typeof ciphertextB64, "string");
  assert.equal(chat.decrypt(ciphertextB64, convKey), text);
  // randomized ciphertext
  assert.notEqual(chat.prepareGroupTitleChange(titleParams).encryptedValue, ciphertextB64);

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
  assert.deepEqual(decryptOwn(addPayload), {
    contentType: "reaction",
    emoji: "\u{1F44D}",
    targetMessageSequenceId: "seq-99",
  });
  assert.equal(decryptOwn(removePayload).targetMessageSequenceId, "seq-99");

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
  assert.equal(decodedEdit.updatedText, "see https://example.com");
  assert.equal(decodedEdit.targetMessageSequenceId, "seq-99");
  // A v0 edit names its target by sequence id only.
  assert.equal(decodedEdit.targetMessageId, undefined);
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
  assert.ok(signs(chat, deleteSig, `MessageDeleteEvent,${deleteSig.messageId},111,111:222,2,seq-10,seq-11`));
  const deleteForSelfSig = onlyAction(chat.prepareMessageDelete({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g999",
    sequenceIds: ["seq-1"],
    deleteForAll: false,
  }));
  assert.ok(signs(chat, deleteForSelfSig, `MessageDeleteEvent,${deleteForSelfSig.messageId},111,g999,1,seq-1`));

  // 4c5. Group actions: a removal signs version 11 and rotates the key for
  // the members who stay, the title and description changes sign the value
  // encrypted under the conversation key, the avatar change signs the media
  // URL as is, and the other prepares sign one version-7 payload.
  const identity = { senderId: "111", signingKeyVersion: "1" };
  const keys = chat.getPublicKeys();
  const remaining = [{ userId: "111", identityPublicKey: keys.identity, publicKeyVersion: "1" }];
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
  const removal = rotated.actionSignatures[0];
  assert.ok(signs(chat, removal,
    `GroupChangeEvent.GroupMemberRemoveChange,${removal.messageId},111,g100,910007,` +
    `${rotated.conversationKeyVersion},signature_version=11`));
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
  const [leaving, promoting, deleting] = left.actionSignatures;
  assert.ok(signs(chat, leaving,
    `GroupChangeEvent.GroupMemberRemoveChange,${leaving.messageId},111,g100,111,7,signature_version=11`));
  assert.ok(signs(chat, promoting, `GroupChangeEvent.GroupAdminAddChange,${promoting.messageId},111,g100,910008`));
  assert.ok(signs(chat, deleting, `ConversationDeleteEvent,${deleting.messageId},111,g100`));

  const metadataKey = { conversationKey: rotated.conversationKey, conversationKeyVersion: rotated.conversationKeyVersion };
  const metadata = [
    [chat.prepareGroupTitleChange({ ...identity, conversationId: "g100", newTitle: "Board: layoffs, Q3", ...metadataKey }),
      "GroupChangeEvent.GroupTitleChange,", "Board: layoffs, Q3"],
    [chat.prepareGroupDescriptionChange({ ...identity, conversationId: "g100", newDescription: "Rules: be kind", ...metadataKey }),
      "GroupChangeEvent.GroupDescriptionChange,", "Rules: be kind"],
  ];
  for (const [prepared, prefix, plaintext] of metadata) {
    assert.deepEqual(Object.keys(prepared).sort(), ["actionSignatures", "conversationKeyVersion", "encryptedValue"]);
    assert.equal(prepared.conversationKeyVersion, rotated.conversationKeyVersion);
    assert.equal(prepared.actionSignatures.length, 1);
    const sig = prepared.actionSignatures[0];
    assert.ok(signs(chat, sig,
      `${prefix}${sig.messageId},111,g100,${prepared.conversationKeyVersion},${prepared.encryptedValue}`));
    assert.equal(chat.decrypt(prepared.encryptedValue, rotated.conversationKey), plaintext);
  }
  const groupAvatarUrl = "https://ton.x.com/xchat_media/g100/avatar";
  const avatarPrep = chat.prepareGroupAvatarChange({
    ...identity,
    conversationId: "g100",
    newAvatarUrl: groupAvatarUrl,
    conversationKeyVersion: rotated.conversationKeyVersion,
  });
  const avatarSig = onlyAction(avatarPrep);
  assert.ok(signs(chat, avatarSig,
    `GroupChangeEvent.GroupAvatarUrlChange,${avatarSig.messageId},111,g100,` +
    `${rotated.conversationKeyVersion},${groupAvatarUrl}`));
  assert.throws(
    () => chat.prepareGroupTitleChange({ ...identity, conversationId: "g100", newTitle: "Board" }),
    /no cached conversation key for 'g100'/,
  );
  const withTitle = chat.prepareGroupMembersRemove({
    ...identity,
    publicKeys: remaining,
    conversationId: "g100",
    userIds: ["910007"],
    title: "Board",
  });
  assert.equal(withTitle.actionSignatures.length, 3);
  const [titledRemoval, titleChange] = withTitle.actionSignatures;
  assert.ok(signs(chat, titledRemoval,
    `GroupChangeEvent.GroupMemberRemoveChange,${titledRemoval.messageId},111,g100,910007,` +
    `${withTitle.conversationKeyVersion},signature_version=11`));
  assert.equal(titleChange.messageEventSignature.signatureVersion, "7");
  assert.ok(titleChange.encodedMessageEventDetail.length > 0);
  const blocking = onlyAction(chat.prepareScreenCapture({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g100",
    change: "blockingEnabled",
  }));
  assert.ok(signs(chat, blocking,
    `ConversationMetadataChangeEvent.EnableScreenCaptureBlocking,${blocking.messageId},111,g100`));
  const detection = onlyAction(chat.prepareScreenCapture({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g100",
    change: "detectionDisabled",
  }));
  assert.ok(signs(chat, detection,
    `ConversationMetadataChangeEvent.DisableScreenCaptureDetection,${detection.messageId},111,g100`));
  assert.throws(
    () => chat.prepareScreenCapture({
      senderId: "111",
      signingKeyVersion: "1",
      conversationId: "g100",
      change: "nope",
    }),
    /Invalid screen capture change: 'nope'/,
  );

  // 4c3b. The group and conversation-metadata actions each sign one action at
  // signature version 7 over the event name, the action's message id, the
  // sender, the conversation and the signed fields, and the signature
  // verifies with the signer's signing key.
  {
    const signingKey = chat.getPublicKeys().signing;
    const ident = { senderId: "111", signingKeyVersion: "1", conversationId: "g100" };
    const cases = [
      ["GroupChangeEvent.GroupAvatarUrlChange", () => ",g100,4,https://img/a.png",
        () => chat.prepareGroupAvatarChange({ ...ident, conversationKeyVersion: "4", newAvatarUrl: "https://img/a.png" })],
      ["GroupChangeEvent.GroupDescriptionChange", (result) => `,g100,4,${result.encryptedValue}`,
        () => chat.prepareGroupDescriptionChange({
          ...ident,
          newDescription: "Ships the app",
          conversationKey: new Uint8Array(32),
          conversationKeyVersion: "4",
        })],
      ["GroupChangeEvent.GroupAdminAddChange", () => ",g100,910008,910009",
        () => chat.prepareGroupAdminsAdd({ ...ident, userIds: ["910008", "910009"] })],
      ["GroupChangeEvent.GroupAdminRemoveChange", () => ",g100,910008",
        () => chat.prepareGroupAdminsRemove({ ...ident, userIds: ["910008"] })],
      ["GroupChangeEvent.GroupInviteEnable", () => ",g100,https://x.com/i/invite/abc,null,null",
        () => chat.prepareGroupInviteEnable({ ...ident, inviteUrl: "https://x.com/i/invite/abc" })],
      ["GroupChangeEvent.GroupInviteDisable", () => ",g100,111", () => chat.prepareGroupInviteDisable({ ...ident })],
      ["GroupChangeEvent.GroupJoinRequest", () => ",g100,111", () => chat.prepareGroupJoinRequest({ ...ident })],
      ["GroupChangeEvent.GroupJoinReject", () => ",g100,910010",
        () => chat.prepareGroupJoinReject({ ...ident, userIds: ["910010"] })],
      ["ConversationMetadataChangeEvent.MessageDurationChange", () => ",g100,86400000",
        () => chat.prepareMessageTtlChange({ ...ident, ttlMsec: 86400000 })],
      ["ConversationMetadataChangeEvent.MessageDurationRemove", () => ",g100",
        () => chat.prepareMessageTtlRemove({ ...ident })],
    ];
    for (const [event, signedFields, prepare] of cases) {
      const result = prepare();
      assert.equal(result.actionSignatures.length, 1, event);
      const [action] = result.actionSignatures;
      const sig = action.messageEventSignature;
      assert.equal(sig.signatureVersion, "7", event);
      assert.equal(sig.signingPublicKey, signingKey, event);
      const payload = `${event},${action.messageId},111${signedFields(result)}`;
      assert.ok(signs(chat, action, payload), payload);
    }
  }

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
  assert.equal(readSig.messageEventSignature.signingPublicKey, v.signing_public_b64);
  assert.ok(signs(chat, readSig,
    `MarkConversationReadEvent,${readSig.messageId},111,111:222,2011626338877079553,1700000000123`));

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
  let readNowSigned = false;
  for (let at = beforeRead; at <= afterRead && !readNowSigned; at++) {
    readNowSigned = signs(chat, readNowSig, `${readNowPrefix}${at}`);
  }
  assert.ok(readNowSigned);

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

  // A millisecond field takes a finite number within the safe integer range:
  // NaN, an infinity or a number past that range names no instant or
  // duration and is rejected. A fraction is truncated toward zero.
  const invalidMsec = /a millisecond value must be a finite number within the safe integer range/;
  for (const bad of [NaN, Infinity, -Infinity, 2 ** 53, -(2 ** 60)]) {
    assert.throws(
      () => chat.prepareMarkConversationRead({ ...identity, conversationId: "g999", seenUntilSequenceId: "seq-1", seenAtMsec: bad }),
      invalidMsec,
    );
    assert.throws(() => chat.prepareMessageTtlChange({ ...identity, conversationId: "g999", ttlMsec: bad }), invalidMsec);
    assert.throws(
      () =>
        chat.encryptMessage({
          ...identity,
          conversationId: "111:222",
          text: "hi",
          ttlMsec: bad,
          conversationKey: b64ToBytes(v.conversation_key_b64),
          conversationKeyVersion: "1",
        }),
      invalidMsec,
    );
    assert.throws(
      () => chat.prepareGroupInviteEnable({ ...identity, conversationId: "g999", inviteUrl: "https://x.com/i/chat/i", expiresAtMsec: bad }),
      invalidMsec,
    );
  }
  assert.throws(
    () => chat.prepareMessageTtlChange({ ...identity, conversationId: "g999", ttlMsec: -Infinity }),
    /got -Infinity$/,
  );
  const ttlPayload = (sig, ttl) =>
    `ConversationMetadataChangeEvent.MessageDurationChange,${sig.messageId},111,g999,${ttl}`;
  const fractionalTtl = onlyAction(chat.prepareMessageTtlChange({ ...identity, conversationId: "g999", ttlMsec: 86400000.9 }));
  assert.ok(signs(chat, fractionalTtl, ttlPayload(fractionalTtl, 86400000)));
  const largestTtl = onlyAction(chat.prepareMessageTtlChange({ ...identity, conversationId: "g999", ttlMsec: 2 ** 53 - 1 }));
  assert.ok(signs(chat, largestTtl, ttlPayload(largestTtl, 2 ** 53 - 1)));

  // 4d. prepareGroupMembersChange emits two action signatures (CKCE + member
  // add) with populated encoded event details and a fresh raw key.
  const membersPrep = chat.prepareGroupMembersChange({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
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
  // Unset screen-capture blocking signs as the trailing null sentinel.
  const membersAdd = membersPrep.actionSignatures[1];
  assert.ok(signs(chat, membersAdd,
    `GroupChangeEvent.GroupMemberAddChange,${membersAdd.messageId},910002,g-1,910005,910002,910002,` +
    `null,null,null,${membersPrep.conversationKeyVersion},null`));

  // 4d1. The current title and description go out encrypted under the key
  // the add generates, as the result returns them; the description is
  // signed at version 8, after the screen-capture slot, and the avatar URL
  // as passed.
  const avatarUrl = "https://ton.x.com/xchat_media/g-1/avatar";
  const describedPrep = chat.prepareGroupMembersChange({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
    conversationId: "g-1",
    newMemberIds: ["910005"],
    currentMemberIds: ["910002"],
    currentAdminIds: ["910002"],
    currentPendingMemberIds: [],
    currentTitle: "Team",
    currentDescription: "Ships the app",
    currentAvatarUrl: avatarUrl,
  });
  const describedAdd = describedPrep.actionSignatures[1];
  assert.equal(chat.decrypt(describedPrep.encryptedTitle, describedPrep.conversationKey), "Team");
  assert.equal(
    chat.decrypt(describedPrep.encryptedDescription, describedPrep.conversationKey),
    "Ships the app",
  );
  assert.equal(describedAdd.messageEventSignature.signatureVersion, "8");
  assert.ok(signs(chat, describedAdd,
    `GroupChangeEvent.GroupMemberAddChange,${describedAdd.messageId},910002,g-1,910005,910002,910002,` +
    `${describedPrep.encryptedTitle},${avatarUrl},null,${describedPrep.conversationKeyVersion},null,` +
    describedPrep.encryptedDescription));
  assert.equal("encryptedTitle" in membersPrep, false);
  assert.equal(membersPrep.actionSignatures[1].messageEventSignature.signatureVersion, "7");

  // 4d2. The group's screen-capture-blocking state fills the trailing signed slot.
  const membersPrepScb = chat.prepareGroupMembersChange({
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" }],
    conversationId: "g-1",
    newMemberIds: ["910005"],
    currentMemberIds: ["910002"],
    currentAdminIds: ["910002"],
    currentPendingMemberIds: [],
    currentScreenCaptureBlockingEnabled: true,
  });
  const scbAdd = membersPrepScb.actionSignatures[1];
  assert.ok(signs(chat, scbAdd,
    `GroupChangeEvent.GroupMemberAddChange,${scbAdd.messageId},910002,g-1,910005,910002,910002,` +
    `null,null,null,${membersPrepScb.conversationKeyVersion},true`));

  // 4d3. Omitting conversationId derives the canonical numeric-sorted
  // one-to-one id from the two participants.
  const derivedPrep = chat.prepareConversationKeyChange({
    senderId: "1491585161162473473",
    signingKeyVersion: "1",
    publicKeys: [
      { userId: "1491585161162473473", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" },
      { userId: "17380288", identityPublicKey: v.identity_public_b64, publicKeyVersion: "1" },
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

  // 4j. A file without a name or a size, and an entity of an unknown or
  // empty type, fail with the core's invalid-input error naming them.
  const invalidInput = (message) => (err) => {
    assert.equal(err.kind, "invalidInput");
    assert.equal(err.message, message);
    return true;
  };
  const send = (extra) =>
    chat.encryptMessage({
      senderId: "111",
      conversationId: "conv-1",
      conversationKey: convKey,
      text: "hi @bob",
      conversationKeyVersion: "1",
      signingKeyVersion: "1",
      ...extra,
    });
  const noName = "has an empty filename: pass the file's original name";
  const noSize =
    "has filesize_bytes 0: pass the encrypted file's size, which encrypted_file_size gives";
  const photo = {
    attachment_type: "media",
    media_hash_key: "photo",
    width: 100,
    height: 100,
    filesize_bytes: 1000,
    filename: "photo.jpg",
    media_type: 1,
  };
  const card = (images) => ({ attachment_type: "url", url: "https://example.com", ...images });
  for (const [attachment, message] of [
    [{ ...photo, filename: "" }, `media_hash_key 'photo' ${noName}`],
    [{ ...photo, filesize_bytes: 0 }, `media_hash_key 'photo' ${noSize}`],
    [
      card({ banner_image: { media_hash_key: "banner", filesize_bytes: 1000, filename: "" } }),
      `media_hash_key 'banner' ${noName}`,
    ],
    [
      card({ favicon_image: { media_hash_key: "favicon", filesize_bytes: 0, filename: "f.png" } }),
      `media_hash_key 'favicon' ${noSize}`,
    ],
  ]) {
    assert.throws(() => send({ attachments: [attachment] }), invalidInput(message));
  }
  for (const entityType of ["bogus", ""]) {
    assert.throws(
      () => send({ entities: [[3, 7, entityType]] }),
      invalidInput(
        `Invalid entity_type '${entityType}': pass url, mention, hashtag, cashtag, email, ` +
          "address or phone_number",
      ),
    );
  }
  for (const [extra, message] of [
    [
      { entities: [[-1, 4, "mention"]] },
      "Invalid entity offsets -1..4: offsets count bytes of the UTF-8 text, from 0",
    ],
    [{ entities: [[5, 3, "mention"]] }, "Invalid entity offsets 5..3: end is before start"],
    [
      { entities: [[3, 8, "mention"]] },
      "Invalid entity offsets 3..8: end is past the end of the text, which is 7 bytes of UTF-8",
    ],
    [
      { attachments: [{ attachment_type: "url", url: "" }] },
      "a URL card's url is empty: pass the link the card shows",
    ],
    [
      { attachments: [{ attachment_type: "post" }] },
      "a post attachment has neither rest_id nor post_url: pass the post's id or its URL",
    ],
    [
      { attachments: [{ ...photo, width: -1 }] },
      "media_hash_key 'photo' has width -1: pass the width in pixels, 0 or more",
    ],
    [
      {
        attachments: [
          card({
            banner_image: { media_hash_key: "banner", filesize_bytes: 1000, filename: "b.png", height: -1 },
          }),
        ],
      },
      "media_hash_key 'banner' has height -1: pass the height in pixels, 0 or more",
    ],
  ]) {
    assert.throws(() => send(extra), invalidInput(message));
  }
  // Offsets count UTF-8 bytes: "é @bob" is 7 bytes, and "@bob" is bytes 3..7.
  send({ text: "é @bob", entities: [[3, 7, "mention"]] });

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

  // 6. Every error carries its kind, named as in every binding. Before the
  // wrapper registers its ChatXdkError class, the module throws Errors with
  // the same name and fields.
  const thrown = (fn) => {
    try {
      fn();
    } catch (e) {
      return e;
    }
    return assert.fail("expected an error");
  };
  const badIdentity = thrown(() => chat.setIdentity({ userId: "user-1", signingKeyVersion: "1" }));
  assert.ok(badIdentity instanceof Error);
  assert.equal(badIdentity.name, "ChatXdkError");
  assert.equal(badIdentity.kind, "invalidInput");
  assert.equal(badIdentity.guessesRemaining, null);
  assert.equal(
    thrown(() => chat.decryptEvent({ eventB64: v.event_garbage_b64, conversationKeys: {} })).kind,
    "parse",
  );
  assert.equal(thrown(() => chat.decryptEvents({ events: "AAAA" })).kind, "invalidInput");
  assert.equal(thrown(() => encryptedFileSize(-1)).kind, "invalidInput");
  const locked = new Chat();
  assert.equal(thrown(() => locked.exportKeys()).kind, "invalidState");
  assert.equal(thrown(() => locked.importKeys({ keys: new Uint8Array(5) })).kind, "invalidInput");
  locked.free();

  console.log("api.test.mjs: all assertions passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
