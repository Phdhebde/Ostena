// TOTP codes (RFC 6238, HMAC-SHA-1, six digits, 30 s) for the end-to-end
// tests only: what the authenticator application of a user would show.
// Never part of the portal. CLI: `node tests/totp.mjs SECRET [OFFSET_STEPS]`.
import { createHmac } from "node:crypto";

function base32(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const out = [];
  for (const c of text.replace(/=+$/, "")) {
    const v = alphabet.indexOf(c);
    if (v < 0) {
      throw new Error("base32 invalide");
    }
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

/** The code of the step `offset` steps away from now. */
export function totp(secret, offset = 0) {
  const step = BigInt(Math.floor(Date.now() / 1000 / 30) + offset);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(step);
  const mac = createHmac("sha1", base32(secret)).update(counter).digest();
  const at = mac[mac.length - 1] & 0x0f;
  const code = (mac.readUInt32BE(at) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, "0");
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  process.stdout.write(`${totp(process.argv[2], Number(process.argv[3] ?? 0))}\n`);
}
