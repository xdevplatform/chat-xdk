import assert from "node:assert/strict";
import fs from "node:fs/promises";

import init, { Chat } from "../pkg/chat_xdk_wasm.js";
import { keepOffline, v1Chat, waitForV1 } from "./feature_server.mjs";
import { delivered } from "./frame.mjs";

/** File encrypt params from params that carry a one-key `conversationKeys` map. */
const withKey = ({ conversationKeys, ...rest }) => {
  const [[conversationKeyVersion, conversationKey]] = Object.entries(conversationKeys);
  return { ...rest, conversationKey, conversationKeyVersion };
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

function bytesToB64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

const QUICK_REPLY_REQUEST = {
  request: {
    options: {
      id: "qr-1",
      options: [
        { id: "yes", label: "Yes", metadata: "m-yes", description: "Confirm" },
        { id: "no", label: "No", metadata: "m-no", description: "Decline" },
      ],
    },
  },
};

const QUICK_REPLY_RESPONSE = {
  response: { options: { requestId: "qr-1", metadata: "m-yes", selectedOptionId: "yes" } },
};

async function main() {
  // wasm-bindgen's default init path uses `fetch(new URL(...))`, which breaks in Node
  // for `file://` URLs. Feed the wasm bytes directly instead.
  const wasmUrl = new URL("../pkg/chat_xdk_wasm_bg.wasm", import.meta.url);
  const wasmBytes = await fs.readFile(wasmUrl);
  await init({ module_or_path: wasmBytes });
  keepOffline();
  const v = await loadVectors();

  const chat = new Chat();

  // import keys (raw bytes, not base64)
  assert.throws(() => chat.importKeys({ keys: new Uint8Array([0]) }), /Invalid key format|expected/i);
  chat.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64), signingKeyVersion: v.event_recipient_key_version });
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
    senderId: "910002",
    signingKeyVersion: "1",
    publicKeys: [{ userId: "910002", publicKey: v.identity_public_b64, keyVersion: "1" }],
    conversationId: "conv-1",
  });
  const decryptedKey = chat.decryptConversationKey(prep.conversationParticipantKeys[0].encryptedConversationKey);
  assert.deepEqual(decryptedKey, prep.conversationKey);

  // file fixtures use the deterministic conversation key
  const convKey = b64ToBytes(v.conversation_key_b64);

  // A v1 message with files is built first; each file is then encrypted
  // from the returned eventB64 and the media hash key its attachment names,
  // and opens from the sent message's event.
  const fixtureKeys = { [v.event_conversation_key_version]: convKey };
  const sender = await v1Chat();
  sender.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64), signingKeyVersion: v.event_recipient_key_version });
  sender.setIdentity({ userId: v.event_sender_id, signingKeyVersion: v.event_signing_key_version });
  await waitForV1(() =>
    sender.encryptMessage({
      conversationId: v.event_conversation_id,
      text: "turn v1 on",
      conversationKey: convKey,
      conversationKeyVersion: v.event_conversation_key_version,
    }),
  );
  const media = (mediaHashKey) => ({
    attachment_type: "media",
    media_hash_key: mediaHashKey,
    width: 4,
    height: 3,
    filesize_bytes: 64,
    filename: `${mediaHashKey}.jpg`,
    media_type: 1,
  });
  const sendFiles = (text, attachments) =>
    sender.encryptMessage({
      conversationId: v.event_conversation_id,
      text,
      conversationKey: convKey,
      conversationKeyVersion: v.event_conversation_key_version,
      attachments,
    });
  const mediaPayload = sendFiles("two photos", [media("photo-0"), media("photo-1")]);
  assert.match(mediaPayload.messageId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(mediaPayload.signatureInfo.signatureVersion, "10");
  const mediaEvent = mediaPayload.eventB64;
  const fileParams = (mediaHashKey, keys = fixtureKeys) => ({
    eventB64: mediaEvent,
    conversationKeys: keys,
    mediaHashKey,
  });
  const plaintext = b64ToBytes(v.plaintext_b64);
  const ct1 = sender.encryptFile(withKey({ ...fileParams("photo-0"), file: plaintext }));
  const ct2 = sender.encryptFile(withKey({ ...fileParams("photo-0"), file: plaintext }));
  assert.notDeepEqual(ct1, ct2); // randomized nonces
  const second = new Uint8Array(5000).fill(0xab);
  const secondEncryptor = sender.fileEncryptor(withKey(fileParams("photo-1")));
  const secondPieces = [];
  for (let i = 0; i < second.length; i += 700) {
    secondPieces.push(...secondEncryptor.push(second.subarray(i, i + 700)));
  }
  secondPieces.push(...secondEncryptor.finish());
  const secondCt = new Uint8Array(secondPieces);
  assert.deepEqual(chat.decryptFile({ ...fileParams("photo-0"), encrypted: ct1 }), plaintext);
  assert.deepEqual(chat.decryptFile({ ...fileParams("photo-1"), encrypted: secondCt }), second);
  // A file encrypted for another attachment does not open.
  assert.throws(() => chat.decryptFile({ ...fileParams("photo-0"), encrypted: secondCt }));

  // a wrong key for the message's version fails
  const wrongKey = new Uint8Array(convKey);
  wrongKey[31] ^= 0xff;
  assert.throws(
    () =>
      chat.decryptFile({
        ...fileParams("photo-0", { [v.event_conversation_key_version]: wrongKey }),
        encrypted: ct1,
      }),
    /does not decrypt the message/,
  );

  // Building the message again gives the same id, so its encrypted files
  // stay valid.
  {
    const rebuilt = sendFiles("final text", [media("photo-0"), media("photo-1")]);
    assert.equal(rebuilt.messageId, mediaPayload.messageId);
    assert.deepEqual(
      chat.decryptFile({
        encrypted: secondCt,
        eventB64: rebuilt.eventB64,
        conversationKeys: fixtureKeys,
        mediaHashKey: "photo-1",
      }),
      second,
    );
  }

  // A link card's banner and favicon share the card's key.
  {
    const cardPayload = sendFiles("a link", [
      {
        attachment_type: "url",
        url: "https://example.com",
        banner_image: { media_hash_key: "banner", filesize_bytes: 12, filename: "banner.png" },
        favicon_image: { media_hash_key: "favicon", filesize_bytes: 13, filename: "favicon.png" },
      },
    ]);
    for (const name of ["banner", "favicon"]) {
      const params = { eventB64: cardPayload.eventB64, conversationKeys: fixtureKeys, mediaHashKey: name };
      const encrypted = sender.encryptFile(withKey({ ...params, file: new TextEncoder().encode(`${name} bytes`) }));
      assert.equal(new TextDecoder().decode(chat.decryptFile({ ...params, encrypted })), `${name} bytes`);
    }
  }

  // A reply encrypts its own files; the files it quotes belong to the
  // quoted message. A reply needs the delivered event, which carries the
  // sequence id the server assigns.
  {
    assert.throws(
      () =>
        sender.encryptReply({
          conversationId: v.event_conversation_id,
          text: "too early",
          replyToEvent: mediaEvent,
          conversationKey: convKey,
          conversationKeyVersion: v.event_conversation_key_version,
        }),
      /reply_to_event carries no sequence_id/,
    );
    const reply = sender.encryptReply({
      conversationId: v.event_conversation_id,
      text: "and mine",
      replyToEvent: delivered(mediaEvent, "100"),
      conversationKey: convKey,
      conversationKeyVersion: v.event_conversation_key_version,
      attachments: [media("reply-photo")],
    });
    const params = { eventB64: reply.eventB64, conversationKeys: fixtureKeys };
    const encrypted = sender.encryptFile(withKey({ ...params, file: plaintext, mediaHashKey: "reply-photo" }));
    assert.deepEqual(chat.decryptFile({ ...params, encrypted, mediaHashKey: "reply-photo" }), plaintext);
    assert.deepEqual(chat.decryptFile({ ...params, encrypted: ct1, mediaHashKey: "photo-0" }), plaintext);
    assert.throws(
      () => sender.encryptFile(withKey({ ...params, file: plaintext, mediaHashKey: "photo-0" })),
      /is media the reply quotes/,
    );
  }

  // A message with files needs a sender identity like any other send.
  {
    const noIdentity = new Chat();
    noIdentity.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64) });
    assert.throws(
      () =>
        noIdentity.encryptMessage({
          conversationId: v.event_conversation_id,
          text: "a photo",
          conversationKey: convKey,
          conversationKeyVersion: v.event_conversation_key_version,
          attachments: [media("photo")],
        }),
      /call set_identity\(\) first/,
    );
  }

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
  const batch = chat.decryptEvents({
    events: [v.event_key_change_b64, v.event_message_b64, v.event_garbage_b64],
    signingKeys,
  });
  assert.deepEqual(Object.keys(batch.errors), ["2"]);
  assert.equal(batch.conversationKeys.latestVersion, v.event_conversation_key_version);
  assert.deepEqual(
    batch.conversationKeys.keys[v.event_conversation_key_version],
    b64ToBytes(v.conversation_key_b64),
  );
  const keyChanges = batch.messages.filter((m) => m.event.type === "keyChange");
  assert.equal(keyChanges.length, 1);
  assert.equal(keyChanges[0].event.verified, true);
  assert.equal(keyChanges[0].event.conversationKeyVersion, v.event_conversation_key_version);
  assert.ok(keyChanges[0].event.conversationParticipantKeys.length > 0);
  for (const key of keyChanges[0].event.conversationParticipantKeys) {
    assert.deepEqual(Object.keys(key).sort(), ["encryptedConversationKey", "publicKeyVersion", "userId"]);
  }
  const messages = batch.messages.filter((m) => m.event.type === "message");
  assert.equal(messages.length, 1);
  assert.equal(messages[0].event.content.text, v.event_message_text);
  assert.equal(messages[0].event.verified, true);
  assert.equal(messages[0].event.conversationKeyVersion, v.event_conversation_key_version);

  // Single-event path with pre-cached keys verifies the same message …
  const conversationKeys = batch.conversationKeys.keys;
  const single = chat.decryptEvent({ eventB64: v.event_message_b64, conversationKeys, signingKeys });
  assert.equal(single.type, "message");
  assert.equal(single.content.text, v.event_message_text);
  assert.equal(single.verified, true);

  // … and throws on the garbage event.
  assert.throws(() =>
    chat.decryptEvent({ eventB64: v.event_garbage_b64, conversationKeys: {}, signingKeys }),
  );

  // setSigningKeys: the stored keys back omitted signingKeys on the
  // single-event path, so the message still verifies.
  chat.setSigningKeys(signingKeys);
  const viaStore = chat.decryptEvent({ eventB64: v.event_message_b64, conversationKeys });
  assert.equal(viaStore.verified, true);
  assert.equal(viaStore.content.text, v.event_message_text);

  // Reply-preview validation over the fixture reply events: both replies
  // decrypt to the fixture reply text, the honest preview validates and the
  // forged one is flagged (the enum serializes camelCased: valid/invalid).
  const replyBatch = chat.decryptEvents({
    events: [v.event_key_change_b64, v.event_reply_valid_b64, v.event_reply_forged_b64],
    signingKeys,
  });
  assert.deepEqual(Object.keys(replyBatch.errors), []);
  const replies = replyBatch.messages.filter((m) => m.event.type === "message");
  assert.equal(replies.length, 2);
  const [validReply, forgedReply] = replies;
  assert.equal(validReply.event.content.text, v.event_reply_text);
  assert.equal(validReply.event.replyPreviewValidation, "valid");
  assert.equal(forgedReply.event.content.text, v.event_reply_text);
  assert.equal(forgedReply.event.replyPreviewValidation, "invalid");

  // A signed group description change: decryptEvent returns the description
  // decrypted under the fixture conversation key, and without that key the
  // change fails instead of coming back as ciphertext.
  const description = chat.decryptEvent({
    eventB64: v.event_group_description_b64,
    conversationKeys: fixtureKeys,
    signingKeys,
  });
  assert.equal(description.type, "groupChange");
  assert.equal(description.verified, true);
  assert.equal(description.conversationId, v.event_group_id);
  assert.deepEqual(description.change, {
    changeType: "descriptionChanged",
    newDescription: v.event_group_description,
  });
  assert.throws(
    () => chat.decryptEvent({
      eventB64: v.event_group_description_b64,
      conversationKeys: {},
      signingKeys,
    }),
    /Group description encrypted with key version/,
  );

  // Failure events are unsigned by protocol: the fixture failure decodes with
  // no keys, and JS camelCases the discriminator values and the tier field.
  const failure = chat.decryptEvent({ eventB64: v.event_failure_b64, conversationKeys: {} });
  assert.equal(failure.type, "failure");
  assert.equal(failure.failure, "rateLimitUpsell");
  assert.equal(failure.rateLimitTier, "premium");
  assert.equal(failure.senderId, v.event_sender_id);

  // Session identity + opt-in key cache: importKeys with a signingKeyVersion
  // records the registered key version, decryptEvents populates the cache
  // from the verified KeyChange, and encryptMessage resolves the omitted
  // identity and key pair from the session.
  {
    const session = new Chat();
    session.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64), signingKeyVersion: v.event_recipient_key_version });
    session.setIdentity({ userId: v.event_sender_id, signingKeyVersion: v.event_signing_key_version });
    session.setCacheKeys(true);
    session.decryptEvents({ events: [v.event_key_change_b64], signingKeys });
    const cached = session.encryptMessage({
      conversationId: v.event_conversation_id,
      text: "hello from the cache",
    });
    assert.equal(cached.conversationKeyVersion, v.event_conversation_key_version);
    assert.equal(cached.signatureInfo.publicKeyVersion, v.event_signing_key_version);

    // A file of a message sent from the cache encrypts under the same cached key.
    const photo = session.encryptMessage({
      conversationId: v.event_conversation_id,
      text: "a photo",
      attachments: [media("photo")],
    });
    const photoBytes = new TextEncoder().encode("photo bytes");
    const photoCt = session.encryptFile({ file: photoBytes, eventB64: photo.eventB64, mediaHashKey: "photo" });
    assert.deepEqual(
      chat.decryptFile({ encrypted: photoCt, eventB64: photo.eventB64, conversationKeys: fixtureKeys, mediaHashKey: "photo" }),
      photoBytes,
    );

    // Replying by raw event derives the preview from the signed original.
    const reply = session.encryptReply({
      conversationId: v.event_conversation_id,
      text: "a threaded reply",
      replyToEvent: v.event_message_b64,
      conversationKey: b64ToBytes(v.conversation_key_b64),
      conversationKeyVersion: v.event_conversation_key_version,
    });
    assert.ok(reply.messageId.length > 0);
    assert.ok(reply.encodedMessageCreateEvent.length > 0);

    // Reacting by raw event derives the conversation id and sequence id.
    const reaction = session.encryptAddReaction({
      emoji: "\u{1F44D}",
      targetEvent: v.event_message_b64,
    });
    assert.ok(reaction.encodedMessageCreateEvent.length > 0);
  }

  // Without the opt-in cache, an omitted conversation key is an error even
  // after the key change decrypted.
  {
    const noCache = new Chat();
    noCache.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64), signingKeyVersion: v.event_recipient_key_version });
    noCache.setIdentity({ userId: v.event_sender_id, signingKeyVersion: v.event_signing_key_version });
    noCache.decryptEvents({ events: [v.event_key_change_b64], signingKeys });
    assert.throws(
      () => noCache.encryptMessage({ conversationId: v.event_conversation_id, text: "x" }),
      /no cached conversation key/,
    );
  }

  // With no session identity and no explicit senderId, encryption fails in
  // the core naming the missing sender_id.
  {
    const noIdentity = new Chat();
    noIdentity.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64) });
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

  // Quick replies round-trip: what encryptMessage / encryptReply send
  // decrypts back to the same quickReply, in the shape decryption returns.
  {
    const qr = new Chat();
    qr.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64) });
    qr.setIdentity({ userId: v.event_sender_id, signingKeyVersion: v.event_signing_key_version });
    const key = {
      conversationKey: b64ToBytes(v.conversation_key_b64),
      conversationKeyVersion: v.event_conversation_key_version,
    };
    const keyMap = { [v.event_conversation_key_version]: b64ToBytes(v.conversation_key_b64) };
    const decryptOwn = (payload) => {
      const event = qr.decryptEvent({
        eventB64: payload.eventB64,
        conversationKeys: keyMap,
        signingKeys,
      });
      assert.equal(event.verified, true);
      return event.content;
    };

    for (const quickReply of [QUICK_REPLY_REQUEST, QUICK_REPLY_RESPONSE]) {
      const content = decryptOwn(
        qr.encryptMessage({
          conversationId: v.event_conversation_id,
          text: "Continue?",
          ...key,
          quickReply,
        }),
      );
      assert.equal(content.text, "Continue?");
      assert.deepEqual(content.quickReply, quickReply);

      // A received quick reply can be sent back unchanged.
      const resent = decryptOwn(
        qr.encryptMessage({
          conversationId: v.event_conversation_id,
          text: "again",
          ...key,
          quickReply: content.quickReply,
        }),
      );
      assert.deepEqual(resent.quickReply, quickReply);
    }

    const replyContent = decryptOwn(
      qr.encryptReply({
        conversationId: v.event_conversation_id,
        text: "Yes",
        ...key,
        replyToSequenceId: "seq-orig",
        replyToSenderId: v.event_sender_id,
        replyToText: "Continue?",
        quickReply: QUICK_REPLY_RESPONSE,
      }),
    );
    assert.deepEqual(replyContent.quickReply, QUICK_REPLY_RESPONSE);

    const plain = decryptOwn(
      qr.encryptMessage({ conversationId: v.event_conversation_id, text: "plain", ...key }),
    );
    assert.equal(plain.quickReply, undefined);

    assert.throws(
      () =>
        qr.encryptMessage({
          conversationId: v.event_conversation_id,
          text: "bad",
          ...key,
          quickReply: { neither: {} },
        }),
      /Invalid encryptMessage params/,
    );
  }

  // Message-key vectors: their contents and media are encrypted directly
  // under the known message and attachment keys, so they open only if the
  // SDK derives the same keys from the conversation key.
  {
    const hexToBytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
    const signingKeysFor = (...userIds) =>
      userIds.map((userId) => ({ ...signingKeys[0], userId }));
    const mkVersion = v.message_key_conversation_key_version;
    const mkKey = hexToBytes(v.message_key_conversation_key_hex);
    const mkKeys = { [mkVersion]: mkKey };
    const shortKeys = {
      [v.message_key_short_conversation_key_version]: hexToBytes(
        v.message_key_short_conversation_key_hex,
      ),
    };

    // Decrypt media whole and in 700-byte chunks on a fresh instance,
    // checking both agree.
    const openMedia = (eventB64, keys, mediaHashKey, encryptedB64) => {
      const media = new Chat();
      const encrypted = b64ToBytes(encryptedB64);
      const params = { eventB64, conversationKeys: keys, mediaHashKey };
      const whole = media.decryptFile({ ...params, encrypted });
      const decryptor = media.fileDecryptor(params);
      const parts = [];
      for (let i = 0; i < encrypted.length; i += 700) {
        parts.push(decryptor.push(encrypted.subarray(i, i + 700)));
      }
      parts.push(decryptor.finish());
      assert.deepEqual(Uint8Array.from(Buffer.concat(parts)), whole);
      return whole;
    };

    const receiver = new Chat();
    const mkMessage = receiver.decryptEvent({
      eventB64: v.event_message_key_b64,
      conversationKeys: mkKeys,
      signingKeys: signingKeysFor(v.message_key_sender_id),
    });
    assert.equal(mkMessage.type, "message");
    assert.equal(mkMessage.verified, true);
    assert.equal(mkMessage.content.text, v.event_message_key_text);
    assert.deepEqual(
      mkMessage.mediaHashes.map((h) => h.mediaHashKey),
      [v.media_first_hash_key, v.media_second_hash_key],
    );

    // Several files in one message.
    for (const name of ["first", "second"]) {
      assert.deepEqual(
        openMedia(
          v.event_message_key_b64,
          mkKeys,
          v[`media_${name}_hash_key`],
          v[`media_${name}_encrypted_b64`],
        ),
        b64ToBytes(v[`media_${name}_plaintext_b64`]),
      );
    }

    // Batch path: the key change in the batch supplies the conversation key.
    const batchReceiver = new Chat();
    batchReceiver.importKeys({ keys: b64ToBytes(v.private_keys_concat_b64), signingKeyVersion: v.event_recipient_key_version });
    const mkBatch = batchReceiver.decryptEvents({
      events: [v.event_key_change_message_key_b64, v.event_message_key_b64],
      signingKeys: signingKeysFor(v.event_sender_id, v.message_key_sender_id),
    });
    assert.deepEqual(Object.keys(mkBatch.errors), []);
    assert.deepEqual(mkBatch.conversationKeys.keys[mkVersion], mkKey);
    assert.deepEqual(
      mkBatch.messages.filter((m) => m.event.type === "message").map((m) => m.event.content.text),
      [v.event_message_key_text],
    );
    assert.deepEqual(
      openMedia(
        v.event_message_key_b64,
        mkBatch.conversationKeys.keys,
        v.media_second_hash_key,
        v.media_second_encrypted_b64,
      ),
      b64ToBytes(v.media_second_plaintext_b64),
    );

    // A v11 message from a short sender id, with one file.
    const short = new Chat().decryptEvent({
      eventB64: v.event_message_key_short_b64,
      conversationKeys: shortKeys,
      signingKeys: signingKeysFor(v.message_key_short_sender_id),
    });
    assert.equal(short.verified, true);
    assert.equal(short.content.text, v.event_message_key_short_text);
    assert.deepEqual(
      openMedia(
        v.event_message_key_short_b64,
        shortKeys,
        v.media_short_hash_key,
        v.media_short_encrypted_b64,
      ),
      b64ToBytes(v.media_short_plaintext_b64),
    );

    // A link card's banner and favicon share the card's key.
    for (const name of ["banner", "favicon"]) {
      assert.deepEqual(
        openMedia(
          v.event_link_card_b64,
          mkKeys,
          v[`media_${name}_hash_key`],
          v[`media_${name}_encrypted_b64`],
        ),
        b64ToBytes(v[`media_${name}_plaintext_b64`]),
      );
    }

    // A conversation-key message's media is under the conversation key.
    assert.deepEqual(
      openMedia(
        v.event_conversation_key_media_b64,
        fixtureKeys,
        v.media_conversation_key_hash_key,
        v.media_conversation_key_encrypted_b64,
      ),
      b64ToBytes(v.media_conversation_key_plaintext_b64),
    );

    // A reply under the fixture key carries the quoted message's key, and
    // the quoted media opens through the reply.
    const replyReceiver = new Chat();
    const mkReply = replyReceiver.decryptEvent({
      eventB64: v.event_reply_message_key_b64,
      conversationKeys: fixtureKeys,
      signingKeys: signingKeysFor(v.event_sender_id, v.message_key_sender_id),
    });
    assert.equal(mkReply.content.text, v.event_reply_message_key_text);
    assert.equal(mkReply.replyPreviewValidation, "valid");
    assert.deepEqual(
      openMedia(
        v.event_reply_message_key_b64,
        fixtureKeys,
        v.media_first_hash_key,
        v.media_first_encrypted_b64,
      ),
      b64ToBytes(v.media_first_plaintext_b64),
    );

    // Each error says what to pass.
    const first = b64ToBytes(v.media_first_encrypted_b64);
    const second = b64ToBytes(v.media_second_encrypted_b64);
    const firstHash = v.media_first_hash_key;
    const errorCases = [
      [first, v.event_message_key_b64, fixtureKeys, firstHash, `no key for version '${mkVersion}'`],
      [first, v.event_message_key_b64, mkKeys, "not-a-hash-key", "is not in the message"],
      [first, v.event_key_change_b64, mkKeys, firstHash, "the event is not a message"],
      [first, v.event_message_b64, fixtureKeys, firstHash, "the message has no media"],
      [second, v.event_message_key_b64, mkKeys, firstHash, `encrypted file of media_hash_key '${firstHash}'`],
      [first.subarray(0, first.length >> 1), v.event_message_key_b64, mkKeys, firstHash, "truncated"],
      [first, v.event_unencrypted_b64, mkKeys, v.media_unencrypted_hash_key, "the message is not encrypted"],
      [first, v.event_message_key_b64, { [mkVersion]: new Uint8Array(5) }, firstHash, "is not 32 bytes"],
    ];
    for (const [encrypted, eventB64, keys, mediaHashKey, expected] of errorCases) {
      assert.throws(
        () => new Chat().decryptFile({ encrypted, eventB64, conversationKeys: keys, mediaHashKey }),
        (e) => e.message.includes(expected),
        expected,
      );
    }
    assert.throws(
      () =>
        new Chat().fileDecryptor({
          eventB64: v.event_message_key_b64,
          conversationKeys: fixtureKeys,
          mediaHashKey: firstHash,
        }),
      /no key for version/,
    );

    // The known signature covers contents_encryption_version.
    const knownSignature = b64ToBytes(v.signature_v10_cev1_b64);
    const encode = (s) => new TextEncoder().encode(s);
    assert.equal(
      receiver.verify(
        v.signature_v10_cev1_public_key_b64,
        knownSignature,
        encode(v.payload_message_v10_cev1),
      ),
      true,
    );
    assert.equal(
      receiver.verify(v.signature_v10_cev1_public_key_b64, knownSignature, encode(v.payload_message_v10)),
      false,
    );
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

