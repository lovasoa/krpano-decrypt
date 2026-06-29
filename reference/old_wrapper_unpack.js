// Deobfuscated: old-engine wrapper (`krp:`) unpack. See PLAN.md §3.3.
// Rust port: src/old_engine.rs (`unpack_old_wrapper`).
//
// The `krp:` wrapper string is an obfuscated payload. A reverse-substitution
// cipher with a per-fixture salt (byte 4) and a rolling checksum unpacks it
// into two structures:
//   - rows[]      : a table of pipe-delimited string records (`_[]` in the engine)
//   - licenseBlob : a Base64-encoded string interleaved between the rows
//
// The last 3 bytes carry a checksum the engine verifies against the rolling
// state. The license blob holds semicolon-separated `key=value` records; the
// `ek=` (or whichever tag row 188 names) record feeds the `case 7` protected
// key derivation: Base64-decode, validate `ck=` checksum, map each byte through
// charCodeAt & 255, pad to 128 by cycling.

/**
 * @param {string} wrapperKey  the `krp:...` string
 * @returns {{ rows: string[], licenseBlob: string }}
 */
function unpackOldWrapper(wrapperKey) {
  const bytes = wrapperKey;
  if (bytes.length < 8 || !wrapperKey.startsWith("krp:")) {
    throw new Error("invalid wrapper key");
  }
  const rows = [];
  let current = "";
  let licenseBlob = "";
  let rowRunLen = 1;
  let hiddenToggle = 0;
  const salt = bytes.charCodeAt(4);
  let rolling = salt;
  const SHUFFLE = [1, 48, 55, 53, 38, 51, 52, 3];

  const payloadEnd = bytes.length - 3;
  for (let idx = 5; idx < payloadEnd; idx++) {
    let value = bytes.charCodeAt(idx);
    if (value >= 92) value -= 1;   // skip backslash
    if (value >= 34) value -= 1;
    value -= 32;
    // All arithmetic is 32-bit signed (JS `| 0`), with positive modulo.
    value = ((value + 3 * idx + 59 + SHUFFLE[idx & 7] + rolling) % 93 + 93) % 93;
    rolling = ((23 * rolling + value) % 32749 + 32749) % 32749;
    value += 32;

    if (value === 124 /* '|' */) {
      if (rowRunLen === 0) {
        hiddenToggle ^= 1;
      } else if (hiddenToggle === 1) {
        hiddenToggle = 0;
      } else {
        rows.push(current);
        current = "";
        rowRunLen = 0;
      }
      continue;
    }
    if (hiddenToggle === 0) current += String.fromCharCode(value);
    else licenseBlob += String.fromCharCode(value);
    rowRunLen += 1;
  }
  if (rowRunLen > 0) rows.push(current);

  // Checksum: last 3 bytes, base-32ish, must equal the rolling state.
  let checksum = 0;
  for (let i = payloadEnd; i < bytes.length; i++) {
    checksum = (checksum << 5) | (bytes.charCodeAt(i) - 53);
  }
  if (checksum !== rolling) throw new Error("wrapper checksum mismatch");
  return { rows, licenseBlob };
}
