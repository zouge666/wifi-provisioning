// The key agreement that turns a sticker into a private channel (the configurator's half).
//
// The device signs a fresh public key with its identity, so the configurator knows it is
// talking to the device on the sticker. Both sides then agree on a shared secret from two
// fresh keys and stir the setup code into it, so only someone who has read the sticker can
// follow the conversation. No secret is ever sent.
//
//   device                                   configurator
//     |  HELLO: fresh public key, signed        |
//     |---------------------------------------->|  checks the signature against the sticker
//     |  KEYSHARE: its own fresh public key     |
//     |<----------------------------------------|
//     |  both derive the same session keys      |

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concat, isAllZero, utf8 } from "./bytes.ts";
import { KEY_LENGTH, Session } from "./session.ts";
import type { Ticket } from "./ticket.ts";
import { MessageType, VERSION } from "./wire.ts";

const EPHEMERAL_KEY_LENGTH = 32;
const SIGNATURE_LENGTH = 64;
const HELLO_LENGTH = 2 + EPHEMERAL_KEY_LENGTH + SIGNATURE_LENGTH;

// A label ties a signature or a set of keys to one purpose, so that neither can be lifted
// out of this protocol and reused somewhere else.
const HELLO_LABEL = utf8("wifiprov/v1/hello");
const SESSION_LABEL = utf8("wifiprov/v1/session");

export class HandshakeError extends Error {}

// The device that answered is not the one on the sticker.
export class WrongDevice extends HandshakeError {}

export interface SessionKeys {
  configuratorToDevice: Uint8Array;
  deviceToConfigurator: Uint8Array;
}

// Stirs everything both sides know into two independent keys. The setup code goes in with
// the shared secret, so a configurator with the wrong code ends up with different keys.
// The hash of the whole conversation is the salt, so a change to any handshake message
// changes the keys too.
export function deriveSessionKeys(
  sharedSecret: Uint8Array,
  setupCode: string,
  devicePublicKey: Uint8Array,
  hello: Uint8Array,
  keyshare: Uint8Array,
): SessionKeys {
  const transcript = sha256(concat(devicePublicKey, hello, keyshare));
  const material = hkdf(
    sha256,
    concat(sharedSecret, utf8(setupCode)),
    transcript,
    SESSION_LABEL,
    2 * KEY_LENGTH,
  );
  return {
    configuratorToDevice: material.slice(0, KEY_LENGTH),
    deviceToConfigurator: material.slice(KEY_LENGTH),
  };
}

export class ConfiguratorHandshake {
  private readonly ticket: Ticket;
  private secret: Uint8Array | null;

  // A fixed secret key is only for test vectors. Normally it is made fresh.
  constructor(ticket: Ticket, ephemeralSecret?: Uint8Array) {
    this.ticket = ticket;
    this.secret = ephemeralSecret ?? x25519.utils.randomSecretKey();
  }

  // Checks the device's hello. Returns the reply to send and the session.
  accept(hello: Uint8Array): { keyshare: Uint8Array; session: Session } {
    if (this.secret === null) {
      throw new HandshakeError("the handshake has already been used");
    }
    const secret = this.secret;
    this.secret = null;

    const { devicePublic, signature } = parseHello(hello);
    if (!signatureIsGood(this.ticket.publicKey, concat(HELLO_LABEL, devicePublic), signature)) {
      throw new WrongDevice("this is not the device on the sticker");
    }
    const keyshare = concat(Uint8Array.of(MessageType.KEYSHARE), x25519.getPublicKey(secret));
    const shared = agree(secret, devicePublic);
    const keys = deriveSessionKeys(
      shared,
      this.ticket.setupCode,
      this.ticket.publicKey,
      hello,
      keyshare,
    );
    return { keyshare, session: new Session(keys.configuratorToDevice, keys.deviceToConfigurator) };
  }
}

function signatureIsGood(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

function agree(secret: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(secret, peerPublic);
  } catch {
    throw new HandshakeError("the key share is not usable");
  }
  // A handful of special public keys force the shared secret to zero, so an attacker could
  // pick it without knowing any private key.
  if (isAllZero(shared)) {
    throw new HandshakeError("the key share is not usable");
  }
  return shared;
}

function parseHello(message: Uint8Array): { devicePublic: Uint8Array; signature: Uint8Array } {
  if (message.length !== HELLO_LENGTH || message[0] !== MessageType.HELLO) {
    throw new HandshakeError("not a hello message");
  }
  if (message[1] !== VERSION) {
    throw new HandshakeError(`unsupported protocol version ${message[1]}`);
  }
  return {
    devicePublic: message.slice(2, 2 + EPHEMERAL_KEY_LENGTH),
    signature: message.slice(2 + EPHEMERAL_KEY_LENGTH),
  };
}
