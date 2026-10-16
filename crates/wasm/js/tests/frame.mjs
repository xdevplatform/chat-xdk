// An outgoing event as delivered: `eventB64` with the sequence id the
// server assigns, prepended as Thrift string field 1.
export function delivered(eventB64, sequenceId) {
  const id = Buffer.from(sequenceId, "utf-8");
  const header = Buffer.alloc(7);
  header.writeUInt8(11, 0);
  header.writeUInt16BE(1, 1);
  header.writeUInt32BE(id.length, 3);
  return Buffer.concat([header, id, Buffer.from(eventB64, "base64")]).toString("base64");
}
