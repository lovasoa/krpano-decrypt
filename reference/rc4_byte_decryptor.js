// Deobfuscated: krpano RC4-like byte decryptor (shared by ClassicZ & ClassicB).
// Source: extracted from krpano viewer engines (2013–2024). See PLAN.md §4.1.
// Rust port: crates/krpano-decrypt/src/crypto.rs (`decrypt_bytes`).
//
// Four phases:
//   1. Key mixing    — first 128 ciphertext bytes interleave with key bytes
//                       to seed the first half of a 256-entry state array.
//   2. KSA           — standard RC4 key-scheduling over the full 256 bytes.
//   3. Discard       — the first 256 PRGA bytes are thrown away.
//   4. Decrypt       — from `encryptedStart`, XOR remaining bytes with keystream.

/**
 * @param {number[]|Uint8Array} input  full ciphertext (incl. 128-byte key-mix prefix)
 * @param {number[]|string}     key    decryption key (byte array or string)
 * @param {boolean}             widenedKeyIndex  true for 128-byte protected keys
 *                                              (key mask widened from 15 to 127)
 * @returns {number[]} decrypted body bytes (key-mix prefix dropped)
 */
function decryptBytes(input, key, widenedKeyIndex) {
  const KEY_MASK_BASE = 15;                     // f = 15
  const PREFIX_LEN = 1 << (KEY_MASK_BASE >> 1); // 128
  if (input.length < PREFIX_LEN || key.length === 0) {
    throw new Error("invalid byte-cipher input");
  }

  // JS engines index the key-mix offset via input['A'.charCodeAt(0)] (== 65).
  // encryptedStart = 128 + (input[65] & (15 >> 1))   // mask is always 15 here
  const encryptedStart =
    PREFIX_LEN + (input['A'.charCodeAt(0)] & (KEY_MASK_BASE >> 1));

  // The key index mask used during KSA. 15 for the 16-byte default key;
  // widened to 127 (15 | (15 << 3)) for 128-byte protected keys.
  const keyMask = widenedKeyIndex
    ? KEY_MASK_BASE | (KEY_MASK_BASE << 3)   // 127
    : KEY_MASK_BASE;                          // 15

  // Phase 1 — build a 256-entry mixed-key table. The first 128 entries are
  // (ciphertext[i], key[i & mask]) pairs; entries 128..255 are sequential.
  // NOTE: when i & mask exceeds the key length, charCodeAt returns NaN, which
  // the bitwise ops below coerce to 0 — matching the JS engine exactly.
  const mixedKey = new Array(PREFIX_LEN * 2);
  let out = 0;
  for (let i = 0; i < PREFIX_LEN; i++) {
    mixedKey[out] = input[i];
    mixedKey[out + 1] = keyCharCodeAt(key, i & keyMask);
    out += 2;
  }

  // Phase 2 — KSA over 256 entries, seeded by mixedKey.
  const state = new Array(256);
  for (let i = 0; i < 256; i++) state[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    // mixedKey[i] is undefined past the prefix -> treated as 0 by `| 0`.
    j = (j + state[i] + (mixedKey[i] | 0)) & 255;
    swap(state, i, j);
  }

  // Phase 3 — discard the first 256 keystream bytes (i, j carry forward).
  let i = 0;
  for (let n = 0; n < 256; n++) {
    i = (i + 1) & 255;
    j = (j + state[i]) & 255;
    swap(state, i, j);
  }

  // Phase 4 — decrypt from encryptedStart onward.
  const decrypted = [];
  for (let p = encryptedStart; p < input.length; p++) {
    i = (i + 1) & 255;
    j = (j + state[i]) & 255;
    const keyByte = state[(state[i] + state[j]) & 255];
    decrypted.push(input[p] ^ keyByte);
    swap(state, i, j);
  }
  return decrypted;
}

function keyCharCodeAt(key, idx) {
  if (typeof key === "string") return key.charCodeAt(idx);
  return key[idx]; // number[], undefined -> NaN (becomes 0 in bitwise ops)
}
function swap(a, i, j) { const t = a[i]; a[i] = a[j]; a[j] = t; }

// Self-test: round-trip a short plaintext with a 16-byte key.
if (typeof require !== "undefined" && require.main === module) {
  const key = "test-key";
  const plain = "plain krpano bytes";
  const prefix = new Array(128).fill(0);
  // Generate the keystream by decrypting an all-zero body, then XOR plaintext.
  const zeros = prefix.concat(new Array(plain.length).fill(0));
  const keystream = decryptBytes(zeros, key, true);
  const cipher = prefix.slice();
  for (let k = 0; k < plain.length; k++) cipher.push(plain.charCodeAt(k) ^ keystream[k]);
  const back = decryptBytes(cipher, key, true);
  console.log(String.fromCharCode(...back) === plain ? "OK" : "FAIL");
}
