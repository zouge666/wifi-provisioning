// The conversation, played against a pretend device. The pretend device says exactly what the
// Python device said in protocol/vectors.json, so the configurator must send exactly the
// bytes of the vectors to get those answers.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fromHex, toHex } from "../src/bytes.ts";
import {
  Configurator,
  DeviceRefused,
  DeviceUnreachable,
  NotTheExpectedDevice,
  ProtocolProblem,
} from "../src/configurator.ts";
import { parseTicket } from "../src/ticket.ts";
import { TransportClosed, TransportTimeout, type Transport } from "../src/transport.ts";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const vectors: any = JSON.parse(
  readFileSync(new URL("../../protocol/vectors.json", import.meta.url), "utf8"),
);
const handshake = vectors.handshake;
const ticket = parseTicket(vectors.ticket.valid[0]);

// What the device sends, in order, and what the configurator is expected to send.
class PretendDevice implements Transport {
  readonly sent: string[] = [];
  private readonly incoming: Uint8Array[];
  closed = false;

  constructor(...incoming: Uint8Array[]) {
    this.incoming = incoming;
  }

  send(message: Uint8Array): void {
    this.sent.push(toHex(message));
  }

  async receive(): Promise<Uint8Array> {
    const next = this.incoming.shift();
    if (next === undefined) {
      throw new TransportClosed("nothing more to say");
    }
    return next;
  }

  close(): void {
    this.closed = true;
  }
}

function conversation(...fromDevice: string[]): PretendDevice {
  return new PretendDevice(fromHex(handshake.hello_hex), ...fromDevice.map(fromHex));
}

function configurator(device: Transport): Configurator {
  return new Configurator(ticket, device, {
    ephemeralSecret: fromHex(handshake.configurator_ephemeral_private_hex),
  });
}

const toDevice: { wire_hex: string }[] = handshake.session.from_configurator;
const fromDevice: { wire_hex: string }[] = handshake.session.from_device;

test("configurator: the handshake, a scan, a join and a status, as the vectors say", async () => {
  const device = conversation(...fromDevice.map((m) => m.wire_hex));
  const phone = configurator(device);

  await phone.open();
  assert.deepEqual(device.sent, [handshake.keyshare_hex]);

  const networks = await phone.scan();
  assert.deepEqual(networks, [{ ssid: "Hospital", signal: 80, security: "wpa-psk" }]);

  // The device says the link will be cut, so there is no result to wait for.
  assert.equal(await phone.join("Hospital", "correct horse"), null);

  const status = await phone.status();
  assert.deepEqual(status, {
    ssid: "Hospital",
    result: { connected: false, failure: "wrong_password" },
  });

  assert.deepEqual(device.sent, [handshake.keyshare_hex, ...toDevice.map((m) => m.wire_hex)]);
});

test("configurator: a join asks for a scan first, so the password is never the first message", async () => {
  // Joining without a scan before sends the scan request first.
  const device = conversation(fromDevice[0]!.wire_hex, fromDevice[1]!.wire_hex);
  const phone = configurator(device);
  await phone.open();
  await phone.join("Hospital", "correct horse");
  assert.deepEqual(device.sent, [
    handshake.keyshare_hex,
    toDevice[0]!.wire_hex, // the scan
    toDevice[1]!.wire_hex, // the join
  ]);
});

test("configurator: a device that refuses is reported with its reason", async () => {
  const phone = configurator(new PretendDevice(fromHex("04010000")));
  await assert.rejects(phone.open(), (error: unknown) => {
    return error instanceof DeviceRefused && error.reason === "auth_failed";
  });

  const locked = configurator(new PretendDevice(fromHex("0402012c")));
  await assert.rejects(locked.open(), (error: unknown) => {
    return error instanceof DeviceRefused && error.reason === "locked" && error.retryAfter === 300;
  });
});

test("configurator: a device that is not the one on the sticker is called out", async () => {
  const impostor = handshake.bad_hellos.find((c: { name: string }) => c.name === "signed by another device");
  const phone = configurator(new PretendDevice(fromHex(impostor.hello_hex)));
  await assert.rejects(phone.open(), NotTheExpectedDevice);
});

test("configurator: a hello that makes no sense is a protocol problem", async () => {
  const phone = configurator(new PretendDevice(fromHex("0101aabb")));
  await assert.rejects(phone.open(), ProtocolProblem);
});

test("configurator: a connection that breaks or goes quiet is reported as unreachable", async () => {
  await assert.rejects(configurator(new PretendDevice()).open(), DeviceUnreachable);

  const quiet: Transport = {
    send() {},
    receive: async () => {
      throw new TransportTimeout("slow");
    },
    close() {},
  };
  await assert.rejects(configurator(quiet).open(), DeviceUnreachable);
});

test("configurator: an answer that does not authenticate is a protocol problem", async () => {
  const bad = handshake.session.bad_messages[0].wire_hex;
  const device = conversation(bad);
  const phone = configurator(device);
  await phone.open();
  await assert.rejects(phone.scan(), ProtocolProblem);
});

test("configurator: requests need an open session", async () => {
  await assert.rejects(configurator(conversation()).scan(), /open\(\)/);
});
