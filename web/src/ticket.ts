// The sticker: the public key that says which device it is, and the setup code that
// says the person is next to it. It is written as a URI, so it fits in a QR code:
//
//   wifiprov://v1/K7Q3ZXD2?pk=<public key, base64url>&code=7K3Q-9ZXD

import { sha256 } from "@noble/hashes/sha2.js";
import * as b64url from "./b64url.ts";
import * as crockford from "./crockford.ts";

const PREFIX = "wifiprov://";
const VERSION = "v1";
const PUBLIC_KEY_LENGTH = 32;
const CODE_LENGTH = 8;

export class TicketError extends Error {}

export interface Ticket {
  publicKey: Uint8Array;
  setupCode: string; // without separators, for example 7K3Q9ZXD
  deviceId: string;
}

// A short label for people, made from the key. Authentication always uses the whole key.
export function deviceIdFromPublicKey(publicKey: Uint8Array): string {
  return crockford.encode(sha256(publicKey).slice(0, 5));
}

// The name of the Wi-Fi network a device makes, from the id on its sticker.
export function accessPointName(deviceId: string): string {
  return `wifiprov-${deviceId}`;
}

// Reads a setup code the way a technician may type it. Returns it without separators.
export function parseSetupCode(text: string): string {
  let symbols: string;
  try {
    symbols = crockford.normalize(text);
  } catch {
    throw new TicketError("a setup code uses only the letters and digits on the sticker");
  }
  if (symbols.length !== CODE_LENGTH) {
    throw new TicketError(`a setup code has ${CODE_LENGTH} characters`);
  }
  return symbols;
}

export function displaySetupCode(symbols: string): string {
  return `${symbols.slice(0, 4)}-${symbols.slice(4)}`;
}

// The text comes from outside, so the reader is strict. Errors never repeat the setup code.
export function parseTicket(text: string): Ticket {
  const uri = text.trim();
  if (!uri.startsWith(PREFIX)) {
    throw new TicketError(`a ticket starts with ${PREFIX}`);
  }
  if (uri.includes("#")) {
    throw new TicketError("unexpected data in ticket");
  }
  const rest = uri.slice(PREFIX.length);
  const questionMark = rest.indexOf("?");
  const place = questionMark < 0 ? rest : rest.slice(0, questionMark);
  const query = questionMark < 0 ? "" : rest.slice(questionMark + 1);
  const slash = place.indexOf("/");
  const version = slash < 0 ? place : place.slice(0, slash);
  const path = slash < 0 ? "" : place.slice(slash);
  if (version !== VERSION) {
    throw new TicketError("unsupported ticket version");
  }

  const fields = parseQuery(query);
  let publicKey: Uint8Array;
  let setupCode: string;
  try {
    publicKey = b64url.decode(fields.get("pk") ?? "");
    setupCode = parseSetupCode(fields.get("code") ?? "");
  } catch {
    throw new TicketError("the public key or the setup code is malformed");
  }
  if (publicKey.length !== PUBLIC_KEY_LENGTH) {
    throw new TicketError(`a public key has ${PUBLIC_KEY_LENGTH} bytes`);
  }
  const deviceId = deviceIdFromPublicKey(publicKey);
  if (path !== `/${deviceId}`) {
    throw new TicketError("the device ID does not match the public key");
  }
  return { publicKey, setupCode, deviceId };
}

function parseQuery(query: string): Map<string, string> {
  const fields = new Map<string, string>();
  for (const part of query.split("&")) {
    const equals = part.indexOf("=");
    if (equals < 0) {
      throw new TicketError("the ticket query is malformed");
    }
    const key = part.slice(0, equals);
    const value = part.slice(equals + 1);
    if (/[%+]/.test(value) || fields.has(key)) {
      throw new TicketError("the ticket query is malformed");
    }
    fields.set(key, value);
  }
  if (fields.size !== 2 || !fields.has("pk") || !fields.has("code")) {
    throw new TicketError("a ticket has exactly one pk and one code");
  }
  return fields;
}
