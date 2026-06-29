// Deobfuscated: we.subdiv branch-5 decompressor (Subdiv cipher). See PLAN.md §4.4.
// Rust port: crates/krpano-decrypt/src/modern_engine.rs
//   (`subdiv_branch5_decode`, `build_mf_table`, `krpano_utf8_decode`).
//
// The Subdiv cipher replaces the configured token ("z") with "\" (0x5C), then
// sends the body to we.subdiv branch 5. The first two bytes select the path:
//   f = body[0] - g   where  g = row["krpano"][5] / 3   (g = 37 in all fixtures)
//     f =  0  -> Public                  (no key mixing)
//     f =  1  -> Protected, 2023/2024    (pk= side-record trie mixing)
//     f = -1  -> Protected, 1.24         (Mf table mixing, key-id prefix at body[3..])
//
// Constants are derived from the "krpano" row. Keys are read 2 per g, mixed,
// then the body is decompressed 5 input bytes -> 4 output bytes, cycling
// through g keys. All arithmetic is signed 32-bit (JS ToInt32). The output is
// then krpano-UTF-8-decoded (skip leading zeros / BOM).

/**
 * @param {string} input              body after token replacement
 * @param {number[]} krpanoRow        the "krpano" we.subdiv row
 * @param {string|null} protectionKey pk= key (f=1 path), or null
 * @param {Object<string,number[]>|null} mfTable  Mf map (f=-1 path), or null
 * @returns {string} plaintext
 */
function subdivBranch5Decode(input, krpanoRow, protectionKey, mfTable) {
  const d = [];
  for (let i = 0; i < input.length; i++) d.push(input.charCodeAt(i));
  if (d.length < 2 || krpanoRow.length <= 5) throw new Error("unsupported");

  const g = (krpanoRow[5] / 3) | 0;
  if (g <= 0) throw new Error("unsupported");
  const f = d[0] - g;
  let h = d[1] - g;
  if (f !== 0 && f * f !== 1) throw new Error("unsupported");
  if (h <= 0) throw new Error("unsupported");

  let k = 2, m = 3;
  let v = h + k;
  const q = Math.floor((v * h + h) / h);
  const t = v + h * k;
  const w = t * t * h;
  const p = w * t * h;
  const bigB = p * h * h;
  const bigF = bigB * v * h;
  const coeffX = (p + w) * (g - k) + k * v * (g + v - 1);
  const a = Math.floor((p * m) / w);

  // f < 0 (RR 1.24): read the key-id prefix length, advance stream.
  let rrC = 0;
  if (f < 0) {
    rrC = d[2] - g - (t + q);
    k += 1 + rrC;
  }

  const keyCount = g;
  let stream = k;
  const keys = new Array(keyCount).fill(0);
  for (let i = 0; i < keyCount; i++) {
    keys[i] = bigB * d[stream] * v + (d[stream + 1] - g + h) * w;
    stream += 2;
  }

  if (f !== 0) {
    const mask = a * (1 + (a + 1) * (1 + (a + 1) * (1 + (a + 1))));
    if (f < 0 && rrC > 2) {
      // RR 1.24: mix via Mf table keyed by body[3..3+rrC].
      const mfKey = String.fromCharCode(...d.slice(3, 3 + rrC));
      const mix = mfTable[mfKey];
      if (!mix) throw new Error("missing Mf key");
      const mixOffset = -g;
      const mixLen = mix.length;
      for (let i = 0; i < keyCount; i++) {
        let val = keys[i]
          + v * (mix[i % mixLen] + mixOffset)
          + coeffX * (mix[(2 * t + i) % mixLen] + mixOffset)
          + t * (mix[(q * q + i) % mixLen] + mixOffset)
          - a * (mix[(2 * q * q - 1 - i) % mixLen] + mixOffset);
        keys[i] = val & mask;   // JS & -> i32
      }
    } else {
      // f=1 (2023/2024): mix via the pk= protection-key trie.
      const trieX = 1;
      const trie = [];
      for (const byte of protectionKey) trie.push(byte.charCodeAt(0) + trieX);
      k = -trieX;
      for (let r = 0; r < keyCount; r++) {
        let val = keys[r]
          + coeffX * (trie[v + r] + k)
          + t * (trie[t * m + r] + k)
          - a * (trie[t * v - r] + k);
        keys[r] = val & mask;
      }
    }
  }

  // Decompress: 5 input bytes -> 4 output bytes, cycling through keys.
  const ba = d.length;
  const rLen = Math.floor(((ba - stream) * q / h) >> 1);
  const rbuf = new Array(rLen).fill(0);
  let outA = 0, outB = 2, e = 0;
  while (stream < d.length) {
    const safe = (off) => (off < d.length ? d[off] : 0);
    let b = t * (safe(stream) * bigB - bigF)
          + safe(stream + 1)
          + h * (safe(stream + 2) * w + safe(stream + 3) * p + safe(stream + 4) * t - coeffX);
    const key = keys[e];
    b = b + key - 2 * (b & key);
    v = b >> q;          // JS signed shift
    e = (e + 1) % keyCount;
    const nn = v >> q;
    stream += 5;
    const f3 = nn >> q;
    while (Math.max(outA, outB) + 1 >= rbuf.length) rbuf.push(0);
    rbuf[outA] = f3; rbuf[outA + 1] = nn & a;
    rbuf[outB] = v & a; rbuf[outB + 1] = b & a;
    outA += 4; outB += 4;
  }

  // Second pass: literal/copy decode into the final output buffer.
  const nBase = a + 1;
  const halfQ = q >> 1;
  const outLen = rbuf[0] + rbuf[1] * nBase + rbuf[2] * nBase * nBase + rbuf[3] * nBase * nBase * nBase;
  const out = new Array(outLen).fill(0);
  let ba2 = rbuf[halfQ] + q + (rbuf[halfQ + 1] + nBase * (rbuf[halfQ + 2] + nBase * rbuf[halfQ + 3])) * nBase;
  const n = a - t + 2;
  let read = q, write = 0;
  while (read < ba2) {
    v = rbuf[read++];
    k = v >> halfQ;
    m = k + n;
    while (m === a) { m = rbuf[read++]; k += m; }
    for (let i = 0; i < k; i++) out[write++] = rbuf[read++];
    if (read < ba2) {
      const offset = rbuf[read] | (rbuf[read + 1] << q);
      read += 2;
      h = write - offset;
      k = v & (t - 2);
      m = k + n;
      while (m === a) { m = rbuf[read++]; k += m; }
      for (let i = 0; i < k + halfQ; i++) out[write++] = out[h++];
    }
  }
  return krpanoUtf8Decode(out);
}

/** krpano's hand-rolled UTF-8 decoder: skip leading zeros, skip BOM (U+FEFF). */
function krpanoUtf8Decode(input) {
  let out = "";
  let i = 0;
  while (i < input.length) {
    const d0 = input[i];
    if (d0 < 128) { if (d0 > 0) out += String.fromCharCode(d0); i += 1; }
    else if (d0 > 191 && d0 < 224) {
      const code = ((d0 & 31) << 6) | (input[i + 1] & 63); out += String.fromCharCode(code); i += 2;
    } else {
      const code = ((d0 & 15) << 12) | ((input[i + 1] & 63) << 6) | (input[i + 2] & 63);
      if (code !== 0xfeff) out += String.fromCharCode(code); i += 3;
    }
  }
  return out;
}
