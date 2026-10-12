// An encrypted conversation between the configurator and a device.
//
// Each direction has its own key and its own message counter. The counter is the nonce,
// so it is never sent: both sides count the messages they have handled. A message that is
// changed, replayed, reordered or sent by the wrong party no longer decrypts. The transport
// must deliver messages in order and without loss.

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { concat } from "./bytes.ts";
import { MessageType } from "./wire.ts";

export const KEY_LENGTH = 32;
const HEADER = Uint8Array.of(MessageType.DATA);

export class SessionError extends Error {}

// ChaCha20-Poly1305 takes a 12-byte nonce: four zero bytes and the 8-byte counter. The counter
// stays far below 2^53, so two 32-bit halves are enough.
function nonce(counter: number): Uint8Array {
  const bytes = new Uint8Array(12);
  const view = new DataView(bytes.buffer);
  view.setUint32(4, Math.floor(counter / 2 ** 32));
  view.setUint32(8, counter >>> 0);
  return bytes;
}

export class Session {
  private readonly sendKey: Uint8Array;
  private readonly receiveKey: Uint8Array;
  private sent = 0;
  private received = 0;

  constructor(sendKey: Uint8Array, receiveKey: Uint8Array) {
    if (sendKey.length !== KEY_LENGTH || receiveKey.length !== KEY_LENGTH) {
      throw new Error(`session keys are ${KEY_LENGTH} bytes long`);
    }
    this.sendKey = sendKey;
    this.receiveKey = receiveKey;
  }

  // Seals one message and returns the bytes to put on the wire.
  encrypt(plaintext: Uint8Array): Uint8Array {
    const sealed = chacha20poly1305(this.sendKey, nonce(this.sent), HEADER).encrypt(plaintext);
    this.sent += 1;
    return concat(HEADER, sealed);
  }

  // Opens the next message the device sent. Anything that does not authenticate raises
  // SessionError and leaves the session as it was, so a bad message cannot upset the counters.
  decrypt(message: Uint8Array): Uint8Array {
    if (message[0] !== MessageType.DATA) {
      throw new SessionError("not a data message");
    }
    let plaintext: Uint8Array;
    try {
      plaintext = chacha20poly1305(this.receiveKey, nonce(this.received), HEADER).decrypt(
        message.slice(1),
      );
    } catch {
      throw new SessionError("the message failed authentication");
    }
    this.received += 1;
    return plaintext;
  }
}
