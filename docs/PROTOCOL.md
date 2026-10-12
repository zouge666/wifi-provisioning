# The wifiprov protocol, version 1

This is the byte-level description of how a configurator (a phone, a laptop) hands the
credentials of a Wi-Fi network to a device, so that nobody listening can read them.

The Python code in `src/wifiprov` is the device and a command-line configurator. The
TypeScript code in `web/src` is the configurator for a browser. Both reproduce every case in
[`protocol/vectors.json`](../protocol/vectors.json), which is made by the Python code.

## 1. What it is for

A new device has no network. A technician with a phone is next to it. Between them there is
only the air, and anyone nearby can listen to it. The protocol has to give three things
without any shared network or server:

- The technician knows it is the device on the sticker, and not another one.
- Only someone who has read the sticker can talk to the device.
- The Wi-Fi password never travels in a form that a listener can read.

It does not depend on what carries the bytes. Link-layer encryption, if there is any, is
treated as a bonus and not relied on.

## 2. The sticker

Every device has a public key (Ed25519) and a setup code. Both are printed on the sticker,
as text and as a QR code, in one URI:

```text
wifiprov://v1/K7Q3ZXD2?pk=<public key, base64url>&code=7K3Q-9ZXD
```

- `K7Q3ZXD2` is the device id: the first 5 bytes of SHA-256 of the public key, written in
  Crockford base32. It is a label for people. It is checked against the key, never used alone.
- `pk` is the 32-byte public key, in unpadded base64url. Only the canonical spelling is read.
- `code` is the setup code: 8 symbols of Crockford base32, which is 40 bits. It is read
  forgivingly (case, spaces and hyphens are ignored, `O` means `0`, `I` and `L` mean `1`) and
  written as `XXXX-XXXX`.
- A reader accepts exactly this: scheme `wifiprov`, version `v1`, no fragment, exactly one
  `pk` and one `code`, and a device id that matches the key. Anything else is refused.

The device keeps the private key and the setup code. The setup code is a secret.

The QR code can hold a link to the page of the device, with the URI after a `#`:
`http://10.42.0.1:8080/#wifiprov://v1/...`. What follows `#` is not sent to a server. The
page reads the URI from it and takes it out of the address bar.

## 3. The transport

The protocol needs a way to send whole messages, in order and without loss, in both
directions. Each message is a byte string of at most 4096 bytes of application data, plus
what the layers below add.

Over TCP, which is what the device and the command-line configurator use, a message is sent
as a 4-byte big-endian length followed by the message. A length above 65536 is refused.

Over a WebSocket, which is what a browser uses, one message is one binary WebSocket
message, with no length of its own. The device accepts the WebSocket at `/ws` on the same
port that serves its page. A message above 65536 bytes, or a text message, closes the
connection.

## 4. The first byte

Every message starts with a type byte:

| Byte | Name     | Direction                | Meaning                                         |
| ---- | -------- | ------------------------ | ----------------------------------------------- |
| 1    | HELLO    | device to configurator   | a fresh public key, signed by the device        |
| 2    | KEYSHARE | configurator to device   | the configurator's own fresh public key         |
| 3    | DATA     | both                     | an encrypted message                            |
| 4    | REJECT   | device to configurator   | not encrypted: the device will not go on        |

## 5. The handshake

```text
device                                   configurator
  |  HELLO: fresh public key, signed        |
  |---------------------------------------->|  checks the signature against the sticker
  |  KEYSHARE: its own fresh public key     |
  |<----------------------------------------|
  |  both derive the same session keys      |
```

**HELLO** is 98 bytes: `01 01 | E_d (32) | S (64)`. The second byte is the protocol version.
`E_d` is a fresh X25519 public key. `S` is the Ed25519 signature, by the device key, of
`"wifiprov/v1/hello" || E_d` (the label is ASCII).

The configurator checks `S` against the public key on the sticker. If it does not verify,
the answering device is not the one on the sticker, and the configurator stops.

**KEYSHARE** is 33 bytes: `02 | E_c (32)`, a fresh X25519 public key of the configurator.

Both sides compute `shared = X25519(own secret, other public)`. If it is all zero, the key
was one of the few that force the secret, and the handshake stops.

Then both compute, with SHA-256 and HKDF (RFC 5869) with SHA-256:

```text
transcript = SHA-256(device public key || HELLO || KEYSHARE)
material   = HKDF(ikm  = shared || setup code symbols (8 ASCII bytes, no hyphen),
                  salt = transcript,
                  info = "wifiprov/v1/session",
                  length = 64)
configurator to device key = material[0:32]
device to configurator key = material[32:64]
```

The setup code goes into the key, not into a separate proof. A configurator with the wrong
code ends up with different keys, and nothing it sends opens. The transcript is the salt, so
a change to any handshake byte changes the keys. The fresh private keys are used once and
dropped.

## 6. Encrypted messages

`DATA` is `03 | ciphertext || tag (16)`, made with ChaCha20-Poly1305 (RFC 8439).

- Each direction has its own key and its own counter, starting at 0.
- The nonce is 4 zero bytes followed by the counter as 8 bytes, big-endian. It is not sent.
- The additional data is the single byte `03`.
- A message that fails to open is dropped and the counters stay where they were.

**The configurator speaks first.** The device sends nothing encrypted until one message from
the configurator has opened. If it answered earlier, with keys that depend on the setup code,
anyone who merely connects could try codes one after another and see which one makes the
reply open. That would turn the device into a place to test guesses offline.

## 7. REJECT

`04 | reason (1) | seconds (2, big-endian)`. It is sent when there is no session to encrypt
with. It only helps the person holding the phone, and nothing depends on trusting it.

| Reason | Name        | Meaning                                                       |
| ------ | ----------- | ------------------------------------------------------------- |
| 1      | AUTH_FAILED | the first message did not open: wrong code, or damaged        |
| 2      | LOCKED      | too many failed attempts; `seconds` says how long to wait     |
| 3      | BUSY        | the device is already talking to another configurator         |

After five failed first messages the device refuses everyone for 300 seconds. It talks to
one configurator at a time.

## 8. The conversation inside DATA

Every message is one compact JSON object (no spaces, UTF-8) with a `"type"`, at most 4096
bytes. Readers are strict: other keys, missing keys and wrong types are refused.

Requests, from the configurator:

```json
{"type":"scan"}
{"type":"status"}
{"type":"provision","ssid":"Hospital","password":"correct horse"}
```

`password` is left out for an open network. Limits: the network name is 1 to 32 bytes of
UTF-8; the password is 8 to 63 printable ASCII characters, or 64 hexadecimal digits, and does
not start or end with a space.

Responses, from the device:

```json
{"type":"networks","networks":[{"ssid":"Hospital","signal":80,"security":"wpa-psk"}]}
{"type":"accepted"}
{"type":"accepted","drops_link":true}
{"type":"result","connected":true,"ip":"192.168.1.50"}
{"type":"result","connected":false,"failure":"wrong_password"}
{"type":"last_attempt"}
{"type":"last_attempt","ssid":"Hospital","connected":false,"failure":"wrong_password"}
```

- `networks` has at most 32 entries. `signal` is a whole number from 0 to 100. `security` is
  `open`, `wpa-psk`, `enterprise` or `other`.
- `failure` is one of `network_not_found`, `wrong_password`, `no_address`, `timeout`,
  `unsupported`, `other`.
- `last_attempt` answers `status`. It carries the network name and the result of the last
  attempt, or nothing if there was none.

For `provision` the device answers `accepted` first, and only then tries the network. If
`drops_link` is true, the device is about to leave the network it talks to the configurator
on, so no result will arrive on this link. The configurator can reconnect later, run a new
handshake, and ask with `status`. Otherwise the result follows on the same link.

## 9. What the protocol does not do

- It does not hide that a conversation happens, how long it is, or how big the messages are.
- The setup code has 40 bits. The lockout limits guessing through the device, but a person
  who has seen the sticker can do everything the technician can.
- The handshake is put together from standard parts, not taken from a standard. It has not
  been audited by anyone else.
- Anyone in range can occupy the device with a connection, or fill the lockout with wrong
  codes. The device closes its door when it is not provisioning.
- The page of the device comes over plain http, and the protocol cannot protect a person
  who is shown another page. A look-alike network can serve a page that sends the setup code
  and the Wi-Fi password somewhere else. The command-line configurator does not have this
  problem, because it does not load code from the device.
- The browser reads a response with `JSON.parse`. It does not refuse repeated keys, does not
  tell `5.0` from `5`, and only roughly checks that an IPv6 address is written in its usual
  form. The messages are authenticated and come from the device, and the page only shows them.

## 10. The test vectors

`protocol/vectors.json` has fixed keys, the bytes of both handshake messages, the session
keys, sealed and opened messages, strings that must be refused, and the exact JSON of every
message. All keys in it are made from labels with SHA-256 and protect nothing.

```bash
uv run python protocol/generate_vectors.py           # write the file
uv run python protocol/generate_vectors.py --check   # fail if the file is out of date
uv run pytest                                        # includes the check
cd web && npm ci && npm test                         # the TypeScript code against the file
```
