// Deobfuscated: modern-engine wrapper (`krp:`) unpack. See PLAN.md §3.4.
// Rust port: crates/krpano-decrypt/src/modern_engine.rs
//   (`find_startup_iife`, `compute_checksum`, `build_lf_shuffle`, `unpack_krp_payload`).
//
// Modern engines (2018+) do not store keys in source text. A startup IIFE
// reconstructs them at page load by unpacking the `krp:` wrapper string:
//   1. Compute a `qf` checksum of the IIFE body. The checksum CONSTANT varies
//      by subfamily (observed: 22248, 22557, 23293). n = constant - checksum.
//   2. Build the `lf` shuffle array from the `Ma` browser-name table
//      (Ma[0]="krpano", Ma[6]="Internet Explorer").
//   3. Unpack `krp:` into we.subdiv rows + side data (Base64-decoded then
//      krpano-UTF-8-decoded; semicolon-separated key=value records, e.g.
//      `pk=` protection key, `uk=` mixing data).
//
// All arithmetic is 32-bit signed to match JavaScript. After unpacking, rows
// are searched BY VALUE: "actions overflow" -> default key, "krpano" ->
// branch-5 constants. Row IDs differ per build, so the value-based search is
// what makes this version-agnostic. Subdiv bodies use "z" as a fixed escape
// marker.

const MA = ["krpano", "Android Browser", "Chrome", "Firefox",
            "Gecko", "Safari", "Internet Explorer", "linux"];

/** qf checksum: sum of char codes, skipping a specific set of ranges. */
function computeChecksum(source) {
  let c = 0;
  for (let i = 0; i < source.length; i++) {
    const d = source.charCodeAt(i);
    const g = d - 36;
    const skip = g === 0 || (12 <= g && g <= 21) || (28 <= g && g <= 54) || (61 <= g && g <= 86);
    if (!skip) c = (c + d) | 0;
  }
  return c >>> 0;
}

/** Build the lf shuffle array (port of Lf/buildLf). */
function buildLfShuffle() {
  const a = MA[0].length;            // 6
  const ma6 = MA[a];                 // "Internet Explorer"
  const baseC = ma6.charCodeAt(8) - 1; // 32 - 1 = 31
  const b = baseC * (a >> 1);        // 93
  const base = baseC + a - 1;        // 36
  const c = baseC >> 2;              // 7
  const f = [];
  for (let g = 0; g < b; g++) f.push(g);
  for (let g = 0; g < b; g++) {
    const ch = ma6[g & c];
    const digit = parseInt(ch, base) || 0;
    const t = (g * c + digit) % b;
    const tmp = f[g]; f[g] = f[t]; f[t] = tmp;
  }
  const m = new Array(b);
  for (let g = 0; g < b; g++) m[f[g]] = g;
  return m;
}

/**
 * Unpack a `krp:` wrapper key into we.subdiv rows + side data.
 * @param {string} key           the `krp:...` wrapper string
 * @param {string} startupBody   the IIFE body text
 * @param {number} startupConstant  the checksum constant for this engine
 * @returns {{ rows: number[][], side: number[] }}
 */
function unpackKrpPayload(key, startupBody, startupConstant) {
  const lf = buildLfShuffle();
  const body = functionBody(startupBody);
  const k = computeChecksum(body);
  const n = (startupConstant - k) | 0;          // i32
  const q = (n - 1) >> 3;                        // signed shift
  const zOrig = 1 | (n >> q);
  const bVal = zOrig | q;
  const v = (1 << bVal) - 1;
  const x = (n - 1) * q - 1;

  // E (modulus) = (v << (B+1)) + ((n-q)*z + x)  — all 32-bit wrapping.
  const w = ((v << (bVal + 1)) + ((n - q) * zOrig + x)) | 0;

  const r = [];
  for (let d = 0; d <= v; d++) r.push(d - (d > 1) - (d > 59));

  const u = charcodesOffset("<" + MA[0] + ">", 0); // "<krpano>"
  const keyBytes = key;
  const dLen = keyBytes.length - q;
  let t = keyBytes.charCodeAt(zOrig - 1);
  let d = zOrig;
  const rows = [];
  const side = [];
  let current = [];
  let eFlag = 1;
  let h = 0;

  while (d < dLen) {
    const keyChar = keyBytes.charCodeAt(d);
    const rIdx = (keyChar - n) & v;
    const rv = r[rIdx];
    const ud = u[d & bVal];
    const lfIdx = ((rv + d * q + ud + t) % (x + 1) + (x + 1)) % (x + 1);
    const g = lf[lfIdx];
    t = (((t << (q + 1)) + t * bVal + g) % w + w) % w;

    if (g === x) {
      if (eFlag === 0) {
        h = (h + 1) & 1;
      } else if (h !== 0) {
        h = 0;
      } else {
        rows.push(current);
        current = [];
        eFlag = 0;
      }
    } else {
      const gv = g + n;
      if (h === 0) current.push(gv);
      else side.push(gv);
      eFlag += 1;
    }
    d += 1;
  }
  if (eFlag > 0) rows.push(current);

  // Final checksum (q more bytes) using ORIGINAL z (before widening).
  let gv = 0;
  for (let d2 = 0; d2 < q; d2++) {
    gv = (gv << (zOrig & 31)) | (keyBytes.charCodeAt(d++) - (10 * zOrig + q));
  }
  if (gv !== t) throw new Error("krp checksum mismatch");
  return { rows, side };
}

function functionBody(source) {
  const start = source.indexOf("{") + 1;
  const end = source.lastIndexOf("}");
  let s = start, e = end - 1;
  while (s < source.length && source.charCodeAt(s) <= 32) s++;
  while (e > s && source.charCodeAt(e) <= 32) e--;
  if (source.charCodeAt(e) === 59 /* ';' */) e--;
  return source.slice(s, e + 1);
}
function charcodesOffset(s, offset) {
  const out = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i) + offset);
  return out;
}
