// Deobfuscated: krpano LZ4 block decompression (krpano-specific framing, not
// the standard LZ4 frame format). See PLAN.md §3.1.
// Rust port: crates/krpano-decrypt/src/codecs.rs (`lz4_decompress_block`).
//
// The packed viewer JS and the ClassicZ body both wrap an LZ4 block in an
// 8-byte header:
//   bytes 0..3  decompressed length (3-byte LE)
//   byte  3    unused
//   bytes 4..7 compressed length  (3-byte LE)
//   byte  7    unused
// `decodePackedLz4Payload` strips that header; this function decompresses the
// raw LZ4 block that follows.

/**
 * @param {number[]|Uint8Array} input          compressed block
 * @param {number}              decompressedLen  expected output length
 * @param {number}              compressedEnd   end of compressed data in input
 * @returns {number[]} decompressed bytes
 */
function lz4DecompressBlock(input, decompressedLen, compressedEnd) {
  let src = 0;
  const output = [];
  while (src < compressedEnd) {
    const token = input[src++];
    let literalLen = token >> 4;
    if (literalLen === 15) {
      do { literalLen += input[src++]; } while (input[src - 1] === 255);
    }
    for (let k = 0; k < literalLen; k++) output.push(input[src++]);
    if (src === compressedEnd) break;

    const offset = input[src] | (input[src + 1] << 8);
    src += 2;
    let matchLen = (token & 0x0f) + 4;
    if ((token & 0x0f) === 15) {
      do { matchLen += input[src++]; } while (input[src - 1] === 255);
    }
    let copyFrom = output.length - offset;
    for (let k = 0; k < matchLen; k++) output.push(output[copyFrom++]);
  }
  return output;
}

if (typeof require !== "undefined" && require.main === module) {
  // literal-only: token 0x30, then "abc"
  console.log(String.fromCharCode(...lz4DecompressBlock([0x30, 97, 98, 99], 3, 4)) === "abc" ? "OK" : "FAIL");
}
