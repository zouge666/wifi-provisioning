// The TypeScript configurator talking to the real Python device over a real WebSocket.
// The device runs with a pretend Wi-Fi adapter, so nothing on this machine changes.
//
//   npm run test:e2e        (needs uv, and runs the device with `uv run` from the repository)

import assert from "node:assert/strict";
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { Configurator } from "../../src/configurator.ts";
import { parseTicket } from "../../src/ticket.ts";
import { WebSocketTransport } from "../../src/transport.ts";

const repository = fileURLToPath(new URL("../../..", import.meta.url));
const haveUv = spawnSync("uv", ["--version"]).status === 0;

let folder = "";
let device: ChildProcess | null = null;
let port = 0;
let ticketText = "";

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      server.close(() => resolve(port));
    });
  });
}

function wifiprov(...args: string[]) {
  return spawn("uv", ["run", "wifiprov", ...args], { cwd: repository });
}

before(async () => {
  if (!haveUv) {
    return;
  }
  folder = mkdtempSync(join(tmpdir(), "wifiprov-e2e-"));
  const identity = join(folder, "identity.json");
  const ticket = join(folder, "ticket.txt");
  const init = spawnSync("uv", ["run", "wifiprov", "init", "--identity", identity, "--ticket-out", ticket], {
    cwd: repository,
  });
  assert.equal(init.status, 0, init.stderr.toString());
  ticketText = readFileSync(ticket, "utf8");

  port = await freePort();
  device = wifiprov("device", "--identity", identity, "--listen", "127.0.0.1:0", "--web-port", String(port));
  await new Promise<void>((resolve, reject) => {
    device!.stdout!.on("data", (chunk: Buffer) => {
      if (chunk.toString().includes("The page is at")) {
        resolve();
      }
    });
    device!.on("exit", () => reject(new Error("the device stopped before it was ready")));
  });
});

after(() => {
  device?.kill();
  if (folder) {
    rmSync(folder, { recursive: true, force: true });
  }
});

async function open(): Promise<Configurator> {
  const transport = await WebSocketTransport.open(`ws://127.0.0.1:${port}/ws`);
  const phone = new Configurator(parseTicket(ticketText), transport, { timeoutMs: 5000 });
  await phone.open();
  return phone;
}

test("e2e: scan, a wrong password, then the right one, in one conversation", { skip: !haveUv }, async () => {
  const phone = await open();
  const networks = await phone.scan();
  assert.ok(networks.some((network) => network.ssid === "Hospital WiFi"));

  const wrong = await phone.join("Hospital WiFi", "not the right one");
  assert.deepEqual(wrong, { connected: false, failure: "wrong_password", ip: undefined });

  const right = await phone.join("Hospital WiFi", "correct horse battery");
  assert.deepEqual(right, { connected: true, failure: undefined, ip: "10.20.0.7" });
  phone.close();
});

test("e2e: a new conversation can ask how the last attempt went", { skip: !haveUv }, async () => {
  const phone = await open();
  const status = await phone.status();
  assert.equal(status.ssid, "Hospital WiFi");
  assert.equal(status.result?.connected, true);
  phone.close();
});

test("e2e: the device does not serve files it was not asked to serve", { skip: !haveUv }, async () => {
  const response = await fetch(`http://127.0.0.1:${port}/etc/passwd`);
  assert.equal(response.status, 404);
});
