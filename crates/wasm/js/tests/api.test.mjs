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
} from "../../pkg/chat_xdk_wasm.js";

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
  const wasmUrl = new URL("../../pkg/chat_xdk_wasm_bg.wasm", import.meta.url);
  const wasmBytes = await fs.readFile(wasmUrl);
  await init({ module_or_path: wasmBytes });

  const v = await loadVectors();

  // 1. Module-level utility functions

  // base64 roundtrip
  const someBytes = new Uint8Array([0, 1, 2, 3, 250, 251, 252, 253, 254, 255]);
  const b64 = bytesToBase64(someBytes);
  assert.equal(typeof b64, "string");
  assert.deepEqual(base64ToBytes(b64), someBytes);
  // matches Node's own base64 encoding
  assert.equal(b64, Buffer.from(someBytes).toString("base64"));

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
    assert.equal(payload.generateVersion, true);
    // Fingerprint: SHA-256 → 32 bytes → 43 URL-safe base64 chars (no padding)
    assert.equal(payload.publicKey.publicKeyFingerprint.length, 43);
    fresh.free();
  }

  // Set up a Chat with the fixture keys (raw crypto, no Juicebox)
  const chat = new Chat();
  chat.importKeys(b64ToBytes(v.private_keys_concat_b64));
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
    senderId: "me",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "me", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "conv-1",
  });
  assert.ok(prep.conversationKey instanceof Uint8Array);
  assert.equal(prep.conversationKey.length, 32);
  assert.equal(prep.conversationId, "conv-1");
  assert.equal(prep.participantKeys.length, 1);
  assert.equal(prep.actionSignatures.length, 1);
  // Omitted: the payload embeds the plaintext conversation key and is withheld.
  assert.equal(prep.actionSignatures[0].signaturePayload, undefined);
  const decryptedKey = chat.decryptConversationKey(prep.participantKeys[0].encryptedKey);
  assert.deepEqual(decryptedKey, prep.conversationKey);
  // two prepared changes generate different keys (randomized)
  const prep2 = chat.prepareConversationKeyChange({
    senderId: "me",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "me", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "conv-1",
  });
  assert.notDeepEqual(prep.conversationKey, prep2.conversationKey);

  // 2b. Group create: emits two action signatures (CKCE + GroupCreate) with
  // populated encoded event details.
  const groupPrep = chat.prepareGroupCreate({
    senderId: "me",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "me", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "g-1",
    memberIds: ["me", "friend"],
    adminIds: ["me"],
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
      senderId: "me",
      signingKeyVersion: "1",
      publicKeys: [{ userId: "me", publicKey: v.identity_public_b64, keyVersion: "1" }],
      conversationId: "g-1",
      memberIds: ["me", "friend"],
      adminIds: ["me"],
      title,
      avatarUrl: title,
    });
    assert.ok(
      p.actionSignatures[1].signaturePayload.endsWith(",null,null,null"),
      `title/avatar must sign as the null sentinel, got: ${p.actionSignatures[1].signaturePayload}`,
    );
  }

  const convKey = b64ToBytes(v.conversation_key_b64);

  // 3. encrypt/decrypt (generic string) + encryptStream/decryptStream
  const text = "group name \u{1F510} \u00e9\u00e8";
  const ciphertextB64 = chat.encrypt(text, convKey);
  assert.equal(typeof ciphertextB64, "string");
  assert.equal(chat.decrypt(ciphertextB64, convKey), text);
  // randomized ciphertext
  assert.notEqual(chat.encrypt(text, convKey), chat.encrypt(text, convKey));

  const plaintext = b64ToBytes(v.plaintext_b64);
  const streamCt1 = chat.encryptStream(plaintext, convKey);
  const streamCt2 = chat.encryptStream(plaintext, convKey);
  assert.notDeepEqual(streamCt1, streamCt2); // randomized nonces
  assert.deepEqual(chat.decryptStream(streamCt1, convKey), plaintext);

  // 3b. Incremental streams: chunked encryptor/decryptor roundtrip over a
  // multi-frame payload, and a truncated stream fails at finish (missing
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
    const enc = chat.streamEncryptor(convKey);
    const ctPieces = [];
    for (let i = 0; i < bigPlain.length; i += 700) {
      ctPieces.push(enc.push(bigPlain.subarray(i, i + 700)));
    }
    ctPieces.push(enc.finish());
    const ciphertext = concat(ctPieces);

    const dec = chat.streamDecryptor(convKey);
    const ptPieces = [];
    for (let i = 0; i < ciphertext.length; i += 333) {
      ptPieces.push(dec.push(ciphertext.subarray(i, i + 333)));
    }
    ptPieces.push(dec.finish());
    assert.deepEqual(concat(ptPieces), bigPlain);

    const truncated = chat.streamDecryptor(convKey);
    truncated.push(ciphertext.subarray(0, ciphertext.length - 4));
    assert.throws(() => truncated.finish());
  }

  // 4. encryptMessage returns a SendPayload with signatureVersion === "7"
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
  assert.equal(typeof payload.encryptedContent, "string");
  assert.equal(typeof payload.signature, "string");
  assert.ok(payload.signatureInfo);
  assert.equal(payload.signatureInfo.signatureVersion, "7");
  assert.equal(payload.conversationKeyVersion, "1");

  // 4b. encryptReply produces a signed payload like encryptMessage
  const replyPayload = chat.encryptReply({
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    text: "this is my reply",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
    replyToSequenceId: "seq-42",
    replyToSenderId: 12345,
    replyToText: "original message",
  });
  assert.ok(replyPayload.encryptedContent.length > 0);
  assert.ok(replyPayload.signature.length > 0);
  assert.ok(replyPayload.encodedEventSignature.length > 0);
  assert.equal(replyPayload.signatureInfo.signatureVersion, "7");
  assert.equal(replyPayload.conversationKeyVersion, "1");

  // 4b2. replyToSenderId precision: a snowflake-sized id passed as a string
  // must land in the reply payload exactly. The id is above 2^53 (where JS
  // numbers stop being exact) and chosen so its 8 big-endian i64 bytes are
  // all ASCII, keeping the Thrift plaintext valid UTF-8 so the encrypted
  // content can be inspected through chat.decrypt with the same key.
  const bigSenderId = 0x2122232425262728n; // 2387509390608492328 > 2^53
  const bigSenderIdBE = "!\"#$%&'("; // bytes 0x21..0x28, big-endian
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
  // encryptedContent is a Thrift MessageCreateEvent whose `contents` field
  // (id 100, binary) is the XSalsa20-Poly1305 ciphertext: 0x0B type byte,
  // i16 field id, i32 big-endian length, then the ciphertext itself.
  const eventBytes = b64ToBytes(bigReplyPayload.encryptedContent);
  assert.equal(eventBytes[0], 0x0b);
  assert.equal((eventBytes[1] << 8) | eventBytes[2], 100);
  const ctLen =
    (eventBytes[3] << 24) | (eventBytes[4] << 16) | (eventBytes[5] << 8) | eventBytes[6];
  const replyCiphertext = eventBytes.subarray(7, 7 + ctLen);
  const decodedReplyContent = chat.decrypt(bytesToBase64(replyCiphertext), convKey);
  assert.ok(
    decodedReplyContent.includes(bigSenderIdBE),
    "decrypted reply content must embed the exact big-endian sender id",
  );
  // The same id as a number has already been rounded by JS — rejected.
  assert.throws(
    () => chat.encryptReply({ ...replyParamsBase, replyToSenderId: Number(bigSenderId) }),
    /replyToSenderId/,
  );
  // Non-integral numbers and non-numeric strings are rejected.
  assert.throws(
    () => chat.encryptReply({ ...replyParamsBase, replyToSenderId: 1.5 }),
    /replyToSenderId/,
  );
  assert.throws(
    () => chat.encryptReply({ ...replyParamsBase, replyToSenderId: "not-a-number" }),
    /replyToSenderId/,
  );
  // Small integral numbers remain accepted.
  const smallNumReply = chat.encryptReply({ ...replyParamsBase, replyToSenderId: 12345 });
  assert.ok(smallNumReply.encryptedContent.length > 0);

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
  assert.ok(addPayload.encryptedContent.length > 0);
  assert.ok(addPayload.signature.length > 0);
  assert.ok(addPayload.encodedEventSignature.length > 0);
  const removePayload = chat.encryptRemoveReaction(reactionParams);
  assert.ok(removePayload.encryptedContent.length > 0);
  assert.ok(removePayload.signature.length > 0);
  assert.ok(removePayload.encodedEventSignature.length > 0);

  // 4c2. encryptEdit produces a signed payload whose encrypted contents
  // decrypt back to the edit: updated text, target sequence id, and the
  // [start, end, type] entity tuple all survive the WASM boundary.
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
  assert.ok(editPayload.encryptedContent.length > 0);
  assert.ok(editPayload.signature.length > 0);
  assert.ok(editPayload.encodedEventSignature.length > 0);
  assert.ok(editPayload.messageId.length > 0);
  // Same extraction as 4b2: the ciphertext is the `contents` binary field
  // (id 100) of the Thrift MessageCreateEvent, and the edit plaintext is
  // all-ASCII Thrift, so chat.decrypt returns it intact as a string.
  const editEventBytes = b64ToBytes(editPayload.encryptedContent);
  assert.equal(editEventBytes[0], 0x0b);
  assert.equal((editEventBytes[1] << 8) | editEventBytes[2], 100);
  const editCtLen =
    (editEventBytes[3] << 24) |
    (editEventBytes[4] << 16) |
    (editEventBytes[5] << 8) |
    editEventBytes[6];
  const editCiphertext = editEventBytes.subarray(7, 7 + editCtLen);
  const decodedEdit = chat.decrypt(bytesToBase64(editCiphertext), convKey);
  assert.ok(
    decodedEdit.includes("see https://example.com"),
    "decrypted edit content must embed the updated text",
  );
  assert.ok(
    decodedEdit.includes("seq-99"),
    "decrypted edit content must embed the target sequence id",
  );
  // Thrift RichTextEntity serializes field 1 (i32 startIndex) then field 2
  // (i32 endIndex): the [4, 23, "url"] tuple must land as start=4, end=23.
  assert.ok(
    decodedEdit.includes(
      "\u0008\u0000\u0001\u0000\u0000\u0000\u0004\u0008\u0000\u0002\u0000\u0000\u0000\u0017",
    ),
    "decrypted edit content must carry the entity's start/end indexes",
  );

  // 4c3. prepareMessageDelete returns a signed action with the encoded
  // MessageDeleteEvent detail; 1:1 ids are signed in canonical colon form.
  const deleteSig = chat.prepareMessageDelete({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "222-111",
    sequenceIds: ["seq-10", "seq-11"],
    deleteForAll: true,
  });
  assert.ok(deleteSig.messageId.length > 0);
  assert.ok(deleteSig.encodedMessageEventDetail.length > 0);
  assert.ok(deleteSig.signature.length > 0);
  assert.equal(
    deleteSig.signaturePayload,
    `MessageDeleteEvent,${deleteSig.messageId},111,111:222,2,seq-10,seq-11`,
  );
  const deleteForSelfSig = chat.prepareMessageDelete({
    senderId: "111",
    signingKeyVersion: "1",
    conversationId: "g999",
    sequenceIds: ["seq-1"],
    deleteForAll: false,
  });
  assert.equal(
    deleteForSelfSig.signaturePayload,
    `MessageDeleteEvent,${deleteForSelfSig.messageId},111,g999,1,seq-1`,
  );

  // 4d. prepareGroupMembersChange emits two action signatures (CKCE + member
  // add) with populated encoded event details and a fresh raw key.
  const membersPrep = chat.prepareGroupMembersChange({
    senderId: "me",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "me", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "g-1",
    newMemberIds: ["friend"],
    currentMemberIds: ["me"],
    currentAdminIds: ["me"],
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
    senderId: "me",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "me", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "g-1",
    newMemberIds: ["friend"],
    currentMemberIds: ["me"],
    currentAdminIds: ["me"],
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
  const urlCardPayload = chat.encryptMessage({
    senderId: "111",
    conversationId: "conv-1",
    conversationKey: convKey,
    text: "check this out",
    conversationKeyVersion: "1",
    signingKeyVersion: "1",
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
  assert.ok(urlCardPayload.encryptedContent.length > 0);
  assert.ok(urlCardPayload.signature.length > 0);

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
    () => chat.decryptEvents(["AAAA"], malformedSigningKeys),
    /Invalid signingKeys/i,
  );
  assert.throws(
    () => chat.decryptEvent("AAAA", {}, malformedSigningKeys),
    /Invalid signingKeys/i,
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
