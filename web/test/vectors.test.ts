// Checks the TypeScript code against protocol/vectors.json, which the Python code makes.
// If both pass, the two implementations agree byte for byte.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as b64url from "../src/b64url.ts";
import { fromHex, toHex, utf8 } from "../src/bytes.ts";
import * as crockford from "../src/crockford.ts";
import {
  ConfiguratorHandshake,
  deriveSessionKeys,
  HandshakeError,
  WrongDevice,
} from "../src/handshake.ts";
import { decodeResponse, encodeRequest, MessageError } from "../src/messages.ts";
import { SessionError } from "../src/session.ts";
import {
  deviceIdFromPublicKey,
  displaySetupCode,
  parseSetupCode,
  parseTicket,
  TicketError,
} from "../src/ticket.ts";
import { decodeReject, WireError } from "../src/wire.ts";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const vectors: any = JSON.parse(
  readFileSync(new URL("../../protocol/vectors.json", import.meta.url), "utf8"),
);
const handshake = vectors.handshake;
const ticket = parseTicket(vectors.ticket.valid[0]);

function newHandshake(): ConfiguratorHandshake {
  return new ConfiguratorHandshake(ticket, fromHex(handshake.configurator_ephemeral_private_hex));
}

function newSession() {
  return newHandshake().accept(fromHex(handshake.hello_hex)).session;
}

// ---------------------------------------------------------------- encodings

test("base64url: bytes and text agree", () => {
  for (const { hex, text } of vectors.b64url.valid) {
    assert.equal(b64url.encode(fromHex(hex)), text);
    assert.equal(toHex(b64url.decode(text)), hex);
  }
});

test("base64url: only the canonical spelling is read", () => {
  for (const text of vectors.b64url.invalid) {
    assert.throws(() => b64url.decode(text), Error, JSON.stringify(text));
  }
});

test("crockford: bytes and text agree, and typing mistakes are forgiven", () => {
  for (const { hex, text } of vectors.crockford.encode) {
    assert.equal(crockford.encode(fromHex(hex)), text);
  }
  for (const { input, output } of vectors.crockford.normalize) {
    assert.equal(crockford.normalize(input), output);
  }
  for (const text of vectors.crockford.invalid) {
    assert.throws(() => crockford.normalize(text), Error, JSON.stringify(text));
  }
});

test("setup code: read forgivingly, written with a hyphen", () => {
  for (const { input, normalized, display } of vectors.setup_code.valid) {
    assert.equal(parseSetupCode(input), normalized);
    assert.equal(displaySetupCode(normalized), display);
  }
  for (const text of vectors.setup_code.invalid) {
    assert.throws(() => parseSetupCode(text), TicketError, JSON.stringify(text));
  }
});

// ---------------------------------------------------------------- the sticker

test("ticket: the same device, key and code come out of every valid spelling", () => {
  for (const text of vectors.ticket.valid) {
    const parsed = parseTicket(text);
    assert.equal(parsed.deviceId, vectors.ticket.device_id);
    assert.equal(toHex(parsed.publicKey), vectors.ticket.public_key_hex);
    assert.equal(parsed.setupCode, parseSetupCode(vectors.ticket.setup_code));
  }
  assert.equal(deviceIdFromPublicKey(fromHex(vectors.ticket.public_key_hex)), vectors.ticket.device_id);
});

test("ticket: text that is not a good ticket is refused", () => {
  for (const text of vectors.ticket.invalid) {
    assert.throws(() => parseTicket(text), TicketError, JSON.stringify(text));
  }
});

// ---------------------------------------------------------------- handshake

test("handshake: the configurator makes the same key share", () => {
  const { keyshare } = newHandshake().accept(fromHex(handshake.hello_hex));
  assert.equal(toHex(keyshare), handshake.keyshare_hex);
});

test("handshake: the keys follow from the shared secret and the setup code", () => {
  const keys = deriveSessionKeys(
    fromHex(handshake.shared_secret_hex),
    ticket.setupCode,
    ticket.publicKey,
    fromHex(handshake.hello_hex),
    fromHex(handshake.keyshare_hex),
  );
  assert.equal(toHex(keys.configuratorToDevice), handshake.configurator_to_device_key_hex);
  assert.equal(toHex(keys.deviceToConfigurator), handshake.device_to_configurator_key_hex);

  const wrong = vectors.handshake.wrong_code_keys;
  const other = deriveSessionKeys(
    fromHex(handshake.shared_secret_hex),
    parseSetupCode(wrong.setup_code),
    ticket.publicKey,
    fromHex(handshake.hello_hex),
    fromHex(handshake.keyshare_hex),
  );
  assert.equal(toHex(other.configuratorToDevice), wrong.configurator_to_device_key_hex);
  assert.notEqual(toHex(other.configuratorToDevice), handshake.configurator_to_device_key_hex);
});

test("handshake: a hello that is not from the device on the sticker is refused", () => {
  for (const { name, hello_hex, error } of handshake.bad_hellos) {
    const accept = () => newHandshake().accept(fromHex(hello_hex));
    if (error === "wrong_device") {
      assert.throws(accept, WrongDevice, name);
    } else {
      assert.throws(
        accept,
        (thrown: unknown) => thrown instanceof HandshakeError && !(thrown instanceof WrongDevice),
        name,
      );
    }
  }
});

test("handshake: one attempt can be used only once", () => {
  const attempt = newHandshake();
  attempt.accept(fromHex(handshake.hello_hex));
  assert.throws(() => attempt.accept(fromHex(handshake.hello_hex)), HandshakeError);
});

// ---------------------------------------------------------------- session

test("session: the configurator seals the same bytes", () => {
  const session = newSession();
  for (const { plaintext_hex, wire_hex } of handshake.session.from_configurator) {
    assert.equal(toHex(session.encrypt(fromHex(plaintext_hex))), wire_hex);
  }
});

test("session: the device's messages are opened", () => {
  const session = newSession();
  for (const { plaintext_hex, wire_hex } of handshake.session.from_device) {
    assert.equal(toHex(session.decrypt(fromHex(wire_hex))), plaintext_hex);
  }
});

test("session: messages that were changed, cut or out of order are refused", () => {
  for (const { name, wire_hex } of handshake.session.bad_messages) {
    assert.throws(() => newSession().decrypt(fromHex(wire_hex)), SessionError, name);
  }
});

test("session: a bad message does not upset the counters", () => {
  const { bad_wire_hex, good_wire_hex, plaintext_hex } = handshake.session.after_a_bad_message;
  const session = newSession();
  assert.throws(() => session.decrypt(fromHex(bad_wire_hex)), SessionError);
  assert.equal(toHex(session.decrypt(fromHex(good_wire_hex))), plaintext_hex);
});

// ---------------------------------------------------------------- messages and wire

test("messages: requests are written as the vectors say", () => {
  for (const { message, json } of vectors.messages.requests) {
    assert.equal(new TextDecoder().decode(encodeRequest(message)), json);
  }
});

test("messages: responses are read as the vectors say", () => {
  for (const { message, json } of vectors.messages.responses) {
    assert.deepEqual(decodeResponse(utf8(json)), message);
  }
});

test("messages: responses that are not valid are refused", () => {
  for (const text of vectors.messages.invalid_responses) {
    assert.throws(() => decodeResponse(utf8(text)), MessageError, text);
  }
});

test("messages: a network name or password the device would refuse is caught before sending", () => {
  assert.throws(() => encodeRequest({ kind: "provision", ssid: "" }), MessageError);
  assert.throws(() => encodeRequest({ kind: "provision", ssid: "x".repeat(33) }), MessageError);
  assert.throws(
    () => encodeRequest({ kind: "provision", ssid: "Hospital", password: "short" }),
    MessageError,
  );
  assert.throws(
    () => encodeRequest({ kind: "provision", ssid: "Hospital", password: " leading space" }),
    MessageError,
  );
});

test("wire: refusals are read", () => {
  for (const { hex, reason, retry_after } of vectors.wire.reject) {
    assert.deepEqual(decodeReject(fromHex(hex)), { reason, retryAfter: retry_after });
  }
  for (const hex of vectors.wire.invalid_reject) {
    assert.throws(() => decodeReject(fromHex(hex)), WireError, hex);
  }
});
