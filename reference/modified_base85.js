// Deobfuscated: krpano modified-Base85 decoder (used to unpack the viewer JS
// and the ClassicZ body). See PLAN.md §3.1.
// Rust port: crates/krpano-decrypt/src/codecs.rs (`decode_modified_base85*`).
//
// Groups of 5 ASCII characters decode to one 32-bit integer. krpano's variant
// skips code point 92 (backslash) in the value table, so digits > 56 are
// shifted by one. Pre-1.24 engines are big-endian (>>> 24 byte order);
// 1.24+ engines are little-endian. The correct endianness is chosen by
// validating the resulting LZ4 header, not by a version flag.

/**
 * @param {string} input     Base85 text (length a multiple of 5)
 * @param {boolean} littleEndian  false for pre-1.24 (BE), true for 1.24+ (LE)
 * @returns {number[]} decoded bytes
 */
function decodeModifiedBase85(input, littleEndian) {
  const completeLen = Math.floor(input.length / 5) * 5;
  const out = [];
  for (let g = 0; g < completeLen; g += 5) {
    let value = 0;
    for (let c = 0; c < 5; c++) {
      let digit = input.charCodeAt(g + c) - 35;
      if (digit > 56) digit -= 1;   // skip backslash (code 92)
      if (digit >= 85) throw new Error("invalid base85 byte");
      value = value * 85 + digit;
    }
    // JS engine writes the 32-bit value as 4 bytes; byte order differs by era.
    if (littleEndian) {
      out.push(value & 0xff, (value >>> 8) & 0xff,
               (value >>> 16) & 0xff, (value >>> 24) & 0xff);
    } else {
      out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff,
               (value >>> 8) & 0xff, value & 0xff);
    }
  }
  return out;
}

if (typeof require !== "undefined" && require.main === module) {
  // "7vgt." -> 0x41424344 -> "ABCD" (big-endian)
  console.log(String.fromCharCode(...decodeModifiedBase85("7vgt.", false)) === "ABCD" ? "OK" : "FAIL");
}
