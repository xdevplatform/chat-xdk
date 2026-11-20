// A Thrift string field: its id, then the value's length and bytes.
function stringField(id, value) {
  const bytes = Buffer.from(value, "utf-8");
  const header = Buffer.alloc(7);
  header.writeUInt8(11, 0);
  header.writeUInt16BE(id, 1);
  header.writeUInt32BE(bytes.length, 3);
  return Buffer.concat([header, bytes]);
}

// A Thrift struct field: its id, then the struct as already serialized.
function structField(id, struct) {
  const header = Buffer.alloc(3);
  header.writeUInt8(12, 0);
  header.writeUInt16BE(id, 1);
  return Buffer.concat([header, struct]);
}

const STOP = Buffer.from([0]);

// An outgoing event as delivered: `eventB64` with the sequence id the
// server assigns, prepended as Thrift string field 1.
export function delivered(eventB64, sequenceId) {
  return Buffer.concat([stringField(1, sequenceId), Buffer.from(eventB64, "base64")]).toString("base64");
}

// A signed action as delivered: the event the server relays for `action`, an
// entry of a prepared change's `actionSignatures`, from `senderId` in
// `conversationId`, with the sequence id the server assigns.
export function deliveredAction(action, senderId, conversationId, sequenceId) {
  const signed = action.messageEventSignature;
  const signature = Buffer.concat([
    stringField(1, signed.signature),
    stringField(2, signed.publicKeyVersion),
    stringField(3, signed.signatureVersion),
    STOP,
  ]);
  return Buffer.concat([
    stringField(1, sequenceId),
    stringField(2, action.messageId),
    stringField(3, senderId),
    stringField(4, conversationId),
    structField(7, Buffer.from(action.encodedMessageEventDetail, "base64")),
    structField(9, signature),
    STOP,
  ]).toString("base64");
}
