// Constants shared by the messages of the protocol.

export const VERSION = 1;

// The first byte of every message.
export const MessageType = {
  HELLO: 1, // device to configurator: a fresh public key, signed by the device
  KEYSHARE: 2, // configurator to device: the configurator's own fresh public key
  DATA: 3, // either direction: an encrypted message
  REJECT: 4, // device to configurator, not encrypted: the device will not go on
} as const;

export type RejectReason = "auth_failed" | "locked" | "busy";

const REASONS: Record<number, RejectReason> = { 1: "auth_failed", 2: "locked", 3: "busy" };

export class WireError extends Error {}

// A refusal: type, reason, and how many seconds to wait before trying again.
export function decodeReject(message: Uint8Array): { reason: RejectReason; retryAfter: number } {
  if (message.length !== 4 || message[0] !== MessageType.REJECT) {
    throw new WireError("not a reject message");
  }
  const reason = REASONS[message[1] ?? 0];
  if (reason === undefined) {
    throw new WireError("unknown reject reason");
  }
  return { reason, retryAfter: ((message[2] ?? 0) << 8) | (message[3] ?? 0) };
}
