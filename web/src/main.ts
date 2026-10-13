// The page. It runs the protocol in the browser: the sticker text opens a session with the
// device that served this page, the person picks a network, and the password goes to the
// device encrypted.

import {
  Configurator,
  DeviceRefused,
  DeviceUnreachable,
  NotTheExpectedDevice,
  ProtocolProblem,
} from "./configurator.ts";
import { checkPassphrase, checkSsid, MessageError, type Failure, type Network } from "./messages.ts";
import { accessPointName, parseTicket, TicketError, type Ticket } from "./ticket.ts";
import { TransportClosed, WebSocketTransport } from "./transport.ts";

type Step = "sticker" | "network" | "result";
type View = "sticker" | "network" | "sent" | "result";

function find<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`the page has no #${id}`);
  }
  return element as T;
}

const views: View[] = ["sticker", "network", "sent", "result"];
const steps: Step[] = ["sticker", "network", "result"];
const stepOfView: Record<View, Step> = {
  sticker: "sticker",
  network: "network",
  sent: "result",
  result: "result",
};

const joinForm = find<HTMLFormElement>("join");

let ticket: Ticket | null = null;
let phone: Configurator | null = null;
let networks: Network[] = [];

// What the person has picked: a network from the list, or one whose name they typed.
let chosenSsid = "";
let chosenSecured = true;
let typedName = false;

// ---------------------------------------------------------------- what the person reads

function show(view: View): void {
  for (const name of views) {
    find(`view-${name}`).hidden = name !== view;
  }
  for (const step of steps) {
    find(`step-${step}`).classList.toggle("current", step === stepOfView[view]);
  }
  window.scrollTo(0, 0);
}

function setText(id: string, text: string): void {
  const element = find(id);
  element.textContent = text;
  element.hidden = text === "";
}

function sentence(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1) + (text.endsWith(".") ? "" : ".");
}

// The reason a person can act on, for whatever went wrong.
// Wi\u2011Fi has a hyphen that does not break, so it stays on one line.
function explain(error: unknown): string {
  if (error instanceof TicketError) {
    return "That is not the text on the sticker. Check it and try again.";
  }
  if (error instanceof NotTheExpectedDevice) {
    return "This is not the device on the sticker. Your phone may be connected to another device's Wi\u2011Fi network.";
  }
  if (error instanceof DeviceRefused) {
    if (error.reason === "auth_failed") {
      return "The device did not accept the setup code. Check the sticker and try again.";
    }
    if (error.reason === "locked") {
      const minutes = Math.max(1, Math.ceil(error.retryAfter / 60));
      return `The device is locked after too many wrong codes. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`;
    }
    return "The device is busy with another phone. Try again in a moment.";
  }
  if (error instanceof TransportClosed) {
    const name = ticket === null ? "its own" : accessPointName(ticket.deviceId);
    return `Cannot reach the device. Is your phone connected to the Wi\u2011Fi network ${name}?`;
  }
  if (error instanceof DeviceUnreachable) {
    return "The device did not answer. Try again.";
  }
  if (error instanceof ProtocolProblem) {
    return "The device sent something unexpected. Try again.";
  }
  if (error instanceof MessageError) {
    return sentence(error.message);
  }
  return "Something went wrong. Try again.";
}

const FAILURES: Record<Failure, (ssid: string) => [string, string]> = {
  wrong_password: (ssid) => [`${ssid} did not accept the password`, "Check the password and try again."],
  network_not_found: (ssid) => [`The device cannot see ${ssid}`, "Check that it is in range and that the name is right."],
  no_address: (ssid) => [`${ssid} did not give the device an address`, "The network may refuse new devices. Ask whoever runs it."],
  timeout: (ssid) => [`${ssid} did not answer in time`, "Try again in a moment."],
  unsupported: (ssid) => [`${ssid} is not a kind of network this device can join`, "Choose another network."],
  other: () => ["Something went wrong on the device", "Try again."],
};

// The device stops talking once it has joined a network, so there is nothing to continue.
function startAgain(): void {
  location.reload();
}

function showResult(tone: "ok" | "bad", tag: string, title: string, text: string, action: string, onAction: () => void): void {
  const label = find("result-tag");
  label.textContent = tag;
  label.classList.toggle("ok", tone === "ok");
  find("result-title").textContent = title;
  find("result-text").textContent = text;
  const button = find<HTMLButtonElement>("result-action");
  button.textContent = action;
  button.onclick = onAction;
  show("result");
}

// ---------------------------------------------------------------- talking to the device

function socketUrl(): string {
  return `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`;
}

async function openSession(): Promise<Configurator> {
  if (ticket === null) {
    throw new TicketError("no ticket");
  }
  phone?.close();
  phone = null;
  const session = new Configurator(ticket, await WebSocketTransport.open(socketUrl()));
  await session.open();
  phone = session;
  return session;
}

async function connect(text: string): Promise<void> {
  const button = find<HTMLButtonElement>("connect");
  setText("sticker-error", "");
  button.disabled = true;
  button.textContent = "Connecting…";
  try {
    // A QR code on a sticker may hold a link to this page with the ticket after the #.
    const start = text.indexOf("wifiprov://");
    ticket = parseTicket(start >= 0 ? text.slice(start) : text);
    find("device-id").textContent = ticket.deviceId;
    networks = await (await openSession()).scan();
    find<HTMLTextAreaElement>("sticker-text").value = ""; // the setup code does not stay on screen
    showNetworks();
  } catch (error) {
    setText("sticker-error", explain(error));
  } finally {
    button.disabled = false;
    button.textContent = "Connect";
  }
}

// ---------------------------------------------------------------- choosing a network

function bars(signal: number): HTMLElement {
  const lit = signal >= 75 ? 4 : signal >= 50 ? 3 : signal >= 25 ? 2 : 1;
  const holder = document.createElement("span");
  holder.className = "bars";
  for (let index = 0; index < 4; index++) {
    const bar = document.createElement("i");
    bar.className = index < lit ? "" : "off";
    holder.append(bar);
  }
  return holder;
}

function showNetworks(): void {
  const list = find("networks");
  joinForm.hidden = true;
  find("view-network").insertBefore(joinForm, find("other-network").parentElement); // keep it out of the list
  list.replaceChildren();
  for (const network of networks) {
    const item = document.createElement("li");
    const row = document.createElement("button");
    row.type = "button";
    row.className = "row";
    row.setAttribute("aria-pressed", "false");

    const name = document.createElement("span");
    name.textContent = network.ssid;
    const meta = document.createElement("span");
    meta.className = "meta";
    const kind = document.createElement("span");
    const supported = network.security === "open" || network.security === "wpa-psk";
    kind.textContent = !supported ? "not supported" : network.security === "open" ? "open" : "password";
    meta.append(bars(network.signal), kind);
    row.append(name, meta);
    row.disabled = !supported;
    row.onclick = () => choose(network.ssid, network.security === "wpa-psk", item, row);

    item.append(row);
    list.append(item);
  }
  show("network");
}

function openJoinForm(label: string, secured: boolean): void {
  find("name-field").hidden = !typedName;
  find("password-field").hidden = !secured;
  find("password-label").textContent = typedName ? "Password, empty for an open network" : "Password";
  find<HTMLInputElement>("join-password").value = "";
  setText("join-error", "");
  joinForm.hidden = false;
  find("join-button").textContent = label;
}

function choose(ssid: string, secured: boolean, item: HTMLElement, row: HTMLElement): void {
  typedName = false;
  chosenSsid = ssid;
  chosenSecured = secured;
  for (const other of document.querySelectorAll(".row")) {
    other.setAttribute("aria-pressed", String(other === row));
  }
  item.append(joinForm);
  openJoinForm(`Join ${ssid}`, secured);
  (secured ? find("join-password") : find("join-button")).focus();
}

function chooseTyped(): void {
  typedName = true;
  chosenSecured = true;
  for (const other of document.querySelectorAll(".row")) {
    other.setAttribute("aria-pressed", "false");
  }
  find("networks").after(joinForm);
  find<HTMLInputElement>("join-name").value = "";
  openJoinForm("Join", true);
  find("join-name").focus();
}

// ---------------------------------------------------------------- joining

async function join(): Promise<void> {
  const ssid = typedName ? find<HTMLInputElement>("join-name").value : chosenSsid;
  const typedPassword = find<HTMLInputElement>("join-password").value;
  const open = !chosenSecured || (typedName && typedPassword === "");
  const password = open ? undefined : typedPassword;
  setText("join-error", "");
  try {
    checkSsid(ssid);
    if (password !== undefined) {
      checkPassphrase(password);
    }
  } catch (error) {
    setText("join-error", explain(error));
    return;
  }
  const button = find<HTMLButtonElement>("join-button");
  button.disabled = true;
  try {
    const session = phone ?? (await openSession());
    const result = await session.join(ssid, password);
    if (result === null) {
      // The device left its own network to join the other one, so no result can come back.
      showSent(ssid);
    } else if (result.connected) {
      showResult("ok", "Joined", `The device joined ${ssid}`, `Its address is ${result.ip ?? "unknown"}.`, "Start again", startAgain);
    } else {
      const [title, advice] = FAILURES[result.failure ?? "other"](ssid);
      showResult("bad", "Not joined", title, advice, "Try again", () => show("network"));
    }
  } catch (error) {
    if (error instanceof DeviceUnreachable) {
      phone?.close();
      phone = null; // the next try starts a new conversation
    }
    setText("join-error", explain(error));
  } finally {
    button.disabled = false;
  }
}

function showSent(ssid: string): void {
  find("sent-title").textContent = `Sent. The device is joining ${ssid}`;
  find("own-network").textContent = ticket === null ? "its own network" : accessPointName(ticket.deviceId);
  setText("sent-error", "");
  show("sent");
}

// After the phone is back on the device's own network: ask how the last attempt went.
async function check(): Promise<void> {
  const button = find<HTMLButtonElement>("check");
  setText("sent-error", "");
  button.disabled = true;
  button.textContent = "Checking…";
  try {
    const session = await openSession();
    const status = await session.status();
    if (status.result === undefined || status.ssid === undefined) {
      setText("sent-error", "The device has not tried to join a network yet.");
    } else if (status.result.connected) {
      showResult("ok", "Joined", `The device joined ${status.ssid}`, `Its address is ${status.result.ip ?? "unknown"}.`, "Start again", startAgain);
    } else {
      const [title, advice] = FAILURES[status.result.failure ?? "other"](status.ssid);
      showResult("bad", "Not joined", title, `The device is back on its own network. ${advice}`, "Try again", () => retry(session));
    }
  } catch (error) {
    if (error instanceof TransportClosed) {
      const own = ticket === null ? "its own network" : accessPointName(ticket.deviceId);
      setText("sent-error", `Cannot reach the device. If ${own} is gone from your Wi\u2011Fi list, the device has probably joined the network. If it is there, connect to it and check again.`);
    } else {
      setText("sent-error", explain(error));
    }
  } finally {
    button.disabled = false;
    button.textContent = "Check result";
  }
}

async function retry(session: Configurator): Promise<void> {
  try {
    networks = await session.scan();
    showNetworks();
  } catch (error) {
    show("sticker");
    setText("sticker-error", explain(error));
  }
}

// ---------------------------------------------------------------- start

find<HTMLFormElement>("sticker-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void connect(find<HTMLTextAreaElement>("sticker-text").value);
});
joinForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void join();
});
find("other-network").addEventListener("click", chooseTyped);
find("show-password").addEventListener("click", () => {
  const field = find<HTMLInputElement>("join-password");
  const hidden = field.type === "password";
  field.type = hidden ? "text" : "password";
  find("show-password").textContent = hidden ? "Hide" : "Show";
});
find("check").addEventListener("click", () => void check());
window.addEventListener("pagehide", () => phone?.close());

// A QR code on the sticker opens this page with the ticket after the #. It is used at once, and
// taken out of the address, so it does not stay in the history of the browser.
function addressText(): string {
  try {
    return decodeURIComponent(location.hash.slice(1));
  } catch {
    return "";
  }
}

const fromAddress = addressText();
if (fromAddress.includes("wifiprov://")) {
  history.replaceState(null, "", location.pathname + location.search);
  find<HTMLTextAreaElement>("sticker-text").value = fromAddress;
  void connect(fromAddress);
}
