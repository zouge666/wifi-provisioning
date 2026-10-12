// Small helpers for working with bytes.

import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";

export { bytesToHex as toHex, concatBytes as concat, hexToBytes as fromHex };

const encoder = new TextEncoder();

export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

export function isAllZero(data: Uint8Array): boolean {
  return data.every((byte) => byte === 0);
}
