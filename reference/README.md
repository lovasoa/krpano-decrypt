# Reference JavaScript — deobfuscated krpano functions

This directory contains **checked-in, deobfuscated** versions of the most
important krpano JavaScript functions, with meaningful variable names and
comments. They are **not executed** by the decryption library; they exist to:

1. document the obfuscated algorithms in their original language, and
2. serve as a ground-truth cross-check when porting behavior to Rust.

Each file names the Rust module that implements the same logic. See
[`AGENTS.md §4`](../AGENTS.md) for how these fit into the reverse-engineering
workflow.

## Files

| File | Implements | PLAN.md | Rust module |
|------|------------|---------|-------------|
| `rc4_byte_decryptor.js` | RC4-like byte decryptor (key-mix prefix, KSA, 256-byte discard, PRGA) | §4.1 | `crypto.rs` |
| `modified_base85.js` | 5-char → 32-bit modified Base85 decode (BE + LE) | §3.1 | `codecs.rs` |
| `lz4_block.js` | krpano LZ4 block decompression (8-byte header) | §3.1 | `codecs.rs` |
| `old_wrapper_unpack.js` | Old-engine `krp:` reverse-substitution unpack → `_[]` rows + license blob | §3.3 | `old_engine.rs` |
| `modern_krp_unpack.js` | Modern-engine startup IIFE: checksum, `lf` shuffle, `krp:` → `we.subdiv` rows + side | §3.4 | `modern_engine.rs` |
| `subdiv_branch5.js` | `we.subdiv` branch-5 decompressor (PP + RR-2023 + RR-1.24 paths) | §4.4 | `modern_engine.rs` |

## Running the self-tests

Each file has a small `if (require.main === module)` self-test that round-trips
a known vector. Run with Node:

```sh
node rc4_byte_decryptor.js
node modified_base85.js
node lz4_block.js
```

## Updating these files

When a new krpano version changes an algorithm, the workflow is:
1. Use the dynamic tools in [`../tools/`](../tools/) to extract the new obfuscated function.
2. Diff against the existing reference file here to see what moved.
3. Update this file with meaningful names + a comment noting the version delta.
4. Port the delta into the corresponding Rust module; keep the i32 arithmetic identical.
5. Add a fixture + test; `cargo test` must stay green.

> The reference files describe *krpano's* algorithms, which krpano licenses
> under its own terms. These deobfuscated descriptions are for interoperability
> and reverse-engineering documentation.
