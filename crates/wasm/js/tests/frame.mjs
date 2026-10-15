// Frame a SendPayload as the base64 MessageEvent envelope decryptEvent
// consumes: string header fields, the payload's MessageCreateEvent in the
// detail union, and its encoded signature.
export function frameSendPayload(payload, senderId, conversationId) {
  const str = (id, value) => {
    const data = Buffer.from(value, "utf-8");
    const header = Buffer.alloc(7);
    header.writeUInt8(11, 0);
    header.writeUInt16BE(id, 1);
    header.writeUInt32BE(data.length, 3);
    return Buffer.concat([header, data]);
  };
  return Buffer.concat([
    str(1, "1"),
    str(2, payload.messageId),
    str(3, senderId),
    str(4, conversationId),
    str(6, "1700000000000"),
    Buffer.from([12, 0, 7, 12, 0, 1]),
    Buffer.from(payload.encryptedContent, "base64"),
    Buffer.from([0, 12, 0, 9]),
    Buffer.from(payload.encodedEventSignature, "base64"),
    Buffer.from([0]),
  ]).toString("base64");
}
