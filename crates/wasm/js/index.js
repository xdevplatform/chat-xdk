/**
 * X Chat SDK - JavaScript entry point (@xdevplatform/chat-xdk)
 *
 * A chat from this package keeps its private keys in Juicebox and has no
 * method that returns them. Servers that keep keys themselves use
 * @xdevplatform/chat-xdk-server, whose chat adds importKeys and exportKeys.
 */
export {
  ChatXdkError,
  ChatWithJuicebox,
  createChat,
  encryptedFileSize,
  bytesToBase64,
  base64ToBytes,
  bytesToHex,
  hexToBytes,
  detectMimeType,
  detectImageDimensions,
} from "./chat.js";
