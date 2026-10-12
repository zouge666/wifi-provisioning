// The conversation inside an encrypted session.
//
// Every message is a small JSON object with a "type". The reader is strict, because the
// bytes come from outside: wrong types, values out of range and oversized input are all
// refused with a MessageError.

import { utf8 } from "./bytes.ts";

export const MAX_MESSAGE_BYTES = 4096;
export const MAX_NETWORKS = 32;
const SSID_MAX_BYTES = 32;

export class MessageError extends Error {}

export type Security = "open" | "wpa-psk" | "enterprise" | "other";
export type Failure =
  | "network_not_found"
  | "wrong_password"
  | "no_address"
  | "timeout"
  | "unsupported"
  | "other";

export interface Network {
  ssid: string;
  signal: number; // 0 (barely there) to 100 (right next to it)
  security: Security;
}

export interface Result {
  connected: boolean;
  failure?: Failure;
  ip?: string;
}

export type Request =
  | { kind: "scan" }
  | { kind: "status" }
  | { kind: "provision"; ssid: string; password?: string };

export type Response =
  | { kind: "networks"; networks: Network[] }
  | { kind: "accepted"; dropsLink: boolean }
  | ({ kind: "result" } & Result)
  | { kind: "last_attempt"; ssid?: string; result?: Result };

const SECURITIES: readonly string[] = ["open", "wpa-psk", "enterprise", "other"];
const FAILURES: readonly string[] = [
  "network_not_found",
  "wrong_password",
  "no_address",
  "timeout",
  "unsupported",
  "other",
];

type Document = Record<string, unknown>;

// ---------------------------------------------------------------- requests

export function encodeRequest(request: Request): Uint8Array {
  let document: Document;
  if (request.kind === "scan") {
    document = { type: "scan" };
  } else if (request.kind === "status") {
    document = { type: "status" };
  } else {
    checkSsid(request.ssid);
    document = { type: "provision", ssid: request.ssid };
    if (request.password !== undefined) {
      checkPassphrase(request.password);
      document.password = request.password;
    }
  }
  return utf8(JSON.stringify(document));
}

// The same rules the device applies, so a mistake is caught before anything is sent.
export function checkSsid(ssid: string): void {
  const size = utf8(ssid).length;
  if (size < 1 || size > SSID_MAX_BYTES) {
    throw new MessageError(`a network name has 1 to ${SSID_MAX_BYTES} bytes`);
  }
}

export function checkPassphrase(password: string): void {
  if (/^[0-9a-fA-F]{64}$/.test(password)) {
    return; // a raw 256-bit key written in hex
  }
  if (password.length < 8 || password.length > 63) {
    throw new MessageError("a Wi-Fi password has 8 to 63 characters");
  }
  if (!/^[\x20-\x7e]*$/.test(password)) {
    throw new MessageError("a Wi-Fi password uses printable ASCII characters only");
  }
  if (password.startsWith(" ") || password.endsWith(" ")) {
    throw new MessageError("a Wi-Fi password cannot start or end with a space");
  }
}

// ---------------------------------------------------------------- responses

export function decodeResponse(data: Uint8Array): Response {
  const document = load(data);
  switch (document.type) {
    case "networks":
      return readNetworks(document);
    case "accepted":
      return readAccepted(document);
    case "result":
      return { kind: "result", ...readResult(document) };
    case "last_attempt":
      return readLastAttempt(document);
    default:
      throw new MessageError("unknown response");
  }
}

function load(data: Uint8Array): Document {
  if (data.length > MAX_MESSAGE_BYTES) {
    throw new MessageError("the message is too large");
  }
  let document: unknown;
  try {
    document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data));
  } catch {
    throw new MessageError("not valid JSON");
  }
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    throw new MessageError("a message is a JSON object");
  }
  return document as Document;
}

function expectKeys(document: Document, required: string[], optional: string[] = []): void {
  const keys = Object.keys(document);
  const known = [...required, ...optional];
  if (!required.every((key) => keys.includes(key)) || !keys.every((key) => known.includes(key))) {
    throw new MessageError("unexpected or missing fields");
  }
}

function readNetworks(document: Document): Response {
  expectKeys(document, ["type", "networks"]);
  const entries = document.networks;
  if (!Array.isArray(entries)) {
    throw new MessageError("networks must be a list");
  }
  if (entries.length > MAX_NETWORKS) {
    throw new MessageError("the network list is not valid");
  }
  return { kind: "networks", networks: entries.map(readNetwork) };
}

function readNetwork(entry: unknown): Network {
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    throw new MessageError("a network is an object");
  }
  const network = entry as Document;
  expectKeys(network, ["ssid", "signal", "security"]);
  const { ssid, signal, security } = network;
  if (typeof ssid !== "string" || typeof signal !== "number" || typeof security !== "string") {
    throw new MessageError("the network list is not valid");
  }
  checkSsid(ssid);
  if (!Number.isInteger(signal) || signal < 0 || signal > 100 || !SECURITIES.includes(security)) {
    throw new MessageError("the network list is not valid");
  }
  return { ssid, signal, security: security as Security };
}

function readAccepted(document: Document): Response {
  expectKeys(document, ["type"], ["drops_link"]);
  const dropsLink = document.drops_link ?? false;
  if (typeof dropsLink !== "boolean") {
    throw new MessageError("drops_link must be true or false");
  }
  return { kind: "accepted", dropsLink };
}

function readResult(document: Document): Result {
  const connected = document.connected;
  if (typeof connected !== "boolean") {
    throw new MessageError("connected must be true or false");
  }
  if (connected) {
    expectKeys(document, ["type", "connected"], ["ip"]);
    const ip = document.ip;
    if (ip === undefined) {
      return { connected };
    }
    if (typeof ip !== "string" || !looksLikeAddress(ip)) {
      throw new MessageError("the result is not valid");
    }
    return { connected, ip };
  }
  expectKeys(document, ["type", "connected", "failure"]);
  const failure = document.failure;
  if (typeof failure !== "string" || !FAILURES.includes(failure)) {
    throw new MessageError("the result is not valid");
  }
  return { connected, failure: failure as Failure };
}

function readLastAttempt(document: Document): Response {
  if (Object.keys(document).length === 1) {
    expectKeys(document, ["type"]);
    return { kind: "last_attempt" };
  }
  const { ssid } = document;
  if (typeof ssid !== "string") {
    throw new MessageError("the status is not valid");
  }
  checkSsid(ssid);
  const rest: Document = { type: "result" };
  for (const [key, value] of Object.entries(document)) {
    if (key !== "type" && key !== "ssid") {
      rest[key] = value;
    }
  }
  return { kind: "last_attempt", ssid, result: readResult(rest) };
}

// A light check: the device sends addresses in their usual written form, and the page only
// shows the address, it does not decide anything with it.
function looksLikeAddress(text: string): boolean {
  const octet = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
  const version4 = new RegExp(`^${octet}(\\.${octet}){3}$`);
  return version4.test(text) || (/^[0-9a-f:.]{2,45}$/.test(text) && text.includes(":"));
}
