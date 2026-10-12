// Crockford base32: an alphabet without the characters people mix up (no I, L, O, U).

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function encode(data: Uint8Array): string {
  let text = "";
  let bits = 0;
  let value = 0;
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      text += ALPHABET[(value >> bits) & 31];
    }
    value &= (1 << bits) - 1; // keep only the bits that are not written yet
  }
  if (bits > 0) {
    text += ALPHABET[(value << (5 - bits)) & 31];
  }
  return text;
}

// The canonical form: case is ignored, spaces and hyphens are dropped, and look-alike
// letters become the digit they resemble (O is 0, I and L are 1).
export function normalize(text: string): string {
  if (!/^[\x00-\x7f]*$/.test(text)) {
    throw new Error("contains non-ASCII characters");
  }
  const canonical = text
    .toUpperCase()
    .replace(/[ -]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  for (const character of canonical) {
    if (!ALPHABET.includes(character)) {
      throw new Error("contains characters outside the alphabet");
    }
  }
  return canonical;
}
