// Unpadded base64url: how binary data is written in the text of the sticker.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function encode(data: Uint8Array): string {
  let text = "";
  let bits = 0;
  let value = 0;
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      text += ALPHABET[(value >> bits) & 63];
    }
    value &= (1 << bits) - 1; // keep only the bits that are not written yet
  }
  if (bits > 0) {
    text += ALPHABET[(value << (6 - bits)) & 63];
  }
  return text;
}

// Only the canonical spelling is accepted: text from a camera or a keyboard
// deserves a strict reader.
export function decode(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    throw new Error("not valid base64url");
  }
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const character of text) {
    value = (value << 6) | ALPHABET.indexOf(character);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 255);
      value &= (1 << bits) - 1;
    }
  }
  const data = Uint8Array.from(bytes);
  if (encode(data) !== text) {
    throw new Error("not canonical unpadded base64url");
  }
  return data;
}
