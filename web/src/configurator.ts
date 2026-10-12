// The configurator's side of provisioning: open a session with the device on the sticker,
// look at the networks it can see, and send the password of the one the person picks.

import { ConfiguratorHandshake, HandshakeError, WrongDevice } from "./handshake.ts";
import {
  decodeResponse,
  encodeRequest,
  MessageError,
  type Network,
  type Request,
  type Response,
  type Result,
} from "./messages.ts";
import { Session, SessionError } from "./session.ts";
import type { Ticket } from "./ticket.ts";
import { TransportClosed, TransportTimeout, type Transport } from "./transport.ts";
import { decodeReject, MessageType, WireError, type RejectReason } from "./wire.ts";

// Something went wrong that the person holding the phone should hear about.
export class ProvisioningError extends Error {}

// The device would not continue: it is locked, busy, or did not accept the setup code.
export class DeviceRefused extends ProvisioningError {
  readonly reason: RejectReason;
  readonly retryAfter: number;

  constructor(reason: RejectReason, retryAfter: number) {
    super(reason);
    this.reason = reason;
    this.retryAfter = retryAfter;
  }
}

// Whatever answered is not the device on the sticker.
export class NotTheExpectedDevice extends ProvisioningError {}

// The device did not answer in time, or the connection broke.
export class DeviceUnreachable extends ProvisioningError {}

// The device sent something that does not make sense.
export class ProtocolProblem extends ProvisioningError {}

export interface Options {
  timeoutMs?: number; // how long to wait for an answer
  joinTimeoutMs?: number; // joining a network can take a while
  ephemeralSecret?: Uint8Array; // only for test vectors
}

export interface Status {
  ssid?: string;
  result?: Result;
}

export class Configurator {
  private readonly ticket: Ticket;
  private readonly transport: Transport;
  private readonly timeoutMs: number;
  private readonly joinTimeoutMs: number;
  private readonly ephemeralSecret: Uint8Array | undefined;
  private session: Session | null = null;
  private confirmed = false; // has the device answered at least once?

  constructor(ticket: Ticket, transport: Transport, options: Options = {}) {
    this.ticket = ticket;
    this.transport = transport;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.joinTimeoutMs = options.joinTimeoutMs ?? 90_000;
    this.ephemeralSecret = options.ephemeralSecret;
  }

  // Runs the handshake. Fails if the device refuses or is not the one on the sticker.
  async open(): Promise<void> {
    const first = await this.receive(this.timeoutMs);
    throwIfRefusal(first);
    try {
      const handshake = new ConfiguratorHandshake(this.ticket, this.ephemeralSecret);
      const { keyshare, session } = handshake.accept(first);
      this.session = session;
      this.send(keyshare);
    } catch (error) {
      if (error instanceof WrongDevice) {
        throw new NotTheExpectedDevice("that is not the device on the sticker");
      }
      if (error instanceof HandshakeError) {
        throw new ProtocolProblem(error.message);
      }
      throw error;
    }
  }

  // The networks the device can see, strongest first.
  async scan(): Promise<Network[]> {
    const reply = await this.ask({ kind: "scan" }, this.timeoutMs);
    if (reply.kind !== "networks") {
      throw new ProtocolProblem("the device answered a scan with something else");
    }
    return reply.networks;
  }

  // Asks the device to join a network. The result is null when the device took the details
  // but the link went away before it could say how it went. That is normal when the two talk
  // over the device's own Wi-Fi network. Use status() when the device is reachable again.
  async join(ssid: string, password?: string): Promise<Result | null> {
    if (!this.confirmed) {
      await this.scan();
    }
    const request: Request =
      password === undefined ? { kind: "provision", ssid } : { kind: "provision", ssid, password };
    const accepted = await this.ask(request, this.timeoutMs);
    if (accepted.kind !== "accepted") {
      throw new ProtocolProblem("the device answered a join request with something else");
    }
    if (accepted.dropsLink) {
      return null;
    }
    let result: Response;
    try {
      result = await this.read(this.joinTimeoutMs);
    } catch (error) {
      if (error instanceof DeviceUnreachable) {
        return null;
      }
      throw error;
    }
    if (result.kind !== "result") {
      throw new ProtocolProblem("the device answered a join request with something else");
    }
    return { connected: result.connected, failure: result.failure, ip: result.ip };
  }

  // How the last attempt to join a network went, as the device remembers it.
  async status(): Promise<Status> {
    const reply = await this.ask({ kind: "status" }, this.timeoutMs);
    if (reply.kind !== "last_attempt") {
      throw new ProtocolProblem("the device answered a status request with something else");
    }
    return { ssid: reply.ssid, result: reply.result };
  }

  close(): void {
    this.transport.close();
  }

  private async ask(request: Request, timeoutMs: number): Promise<Response> {
    if (this.session === null) {
      throw new Error("call open() before sending requests");
    }
    this.send(this.session.encrypt(encodeRequest(request)));
    return this.read(timeoutMs);
  }

  private async read(timeoutMs: number): Promise<Response> {
    if (this.session === null) {
      throw new Error("call open() before sending requests");
    }
    const data = await this.receive(timeoutMs);
    throwIfRefusal(data);
    let reply: Response;
    try {
      reply = decodeResponse(this.session.decrypt(data));
    } catch (error) {
      if (error instanceof SessionError || error instanceof MessageError) {
        throw new ProtocolProblem("the device sent a message that could not be read");
      }
      throw error;
    }
    this.confirmed = true;
    return reply;
  }

  private send(message: Uint8Array): void {
    try {
      this.transport.send(message);
    } catch (error) {
      if (error instanceof TransportClosed) {
        throw new DeviceUnreachable("the connection to the device was closed");
      }
      throw error;
    }
  }

  private async receive(timeoutMs: number): Promise<Uint8Array> {
    try {
      return await this.transport.receive(timeoutMs);
    } catch (error) {
      if (error instanceof TransportTimeout) {
        throw new DeviceUnreachable("the device did not answer in time");
      }
      if (error instanceof TransportClosed) {
        throw new DeviceUnreachable("the connection to the device was closed");
      }
      throw error;
    }
  }
}

function throwIfRefusal(data: Uint8Array): void {
  if (data[0] !== MessageType.REJECT) {
    return;
  }
  try {
    const { reason, retryAfter } = decodeReject(data);
    throw new DeviceRefused(reason, retryAfter);
  } catch (error) {
    if (error instanceof WireError) {
      throw new ProtocolProblem("the device sent a refusal that could not be read");
    }
    throw error;
  }
}
