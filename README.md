# krpano-decrypt

A standalone toolkit for **decrypting encrypted krpano tour XML and obfuscated
viewer JavaScript**, without running any JavaScript.

[krpano](https://krpano.com) is a panoramic-image viewer. It ships virtual-tour
projects as an encrypted `tour.xml` paired with an obfuscated `tour.js`. The XML
specifies the *transform*; the JS holds the *key*. This project reverse-engineers
the on-disk format and decrypts the XML by static analysis of the decoded engine
— the engine is **never executed**.

This is a clean, dependency-light Rust **library** plus a versatile **CLI**, kept
completely independent of any host application.

---

## What's in this repository

| Path | What it is |
|------|------------|
| **`crates/krpano-decrypt/`** | The reusable Rust library. Entry point: `decrypt_xml()`. |
| **`crates/krpano-decrypt-cli/`** | The `krpano-decrypt` command-line tool. |
| **`PLAN.md`** | Implementation-independent documentation of the encrypted format. Start here. |
| **`AGENTS.md`** | Architecture of the crate, mapping code modules to the format docs, plus the reverse-engineering workflow. |
| **`reference/`** | Checked-in, deobfuscated versions of the most important krpano JS functions (with meaningful names). |
| **`tools/`** | Node & browser dynamic-analysis tools that *execute* and instrument krpano code to help reverse-engineer new versions. |
| **`testdata/encrypted/`** | Fixture corpus: 27 real tours (2013–2026) with golden plaintext. |

### Context

krpano encrypts tours to protect authoring work. The format has evolved across
many engine versions (old engines 2013–2017, modern engines 2018+, a
transitional 1.19-pr16 family, and the 1.24 family). Each ships the decryption
key material *inside* the obfuscated `tour.js` itself — wrapped in a `krp:`
payload that is unpacked at runtime. `krpano-decrypt` recovers the keys by
statically analyzing that payload, so it works offline on the two files alone.

The supported pipeline families are:

| Cipher | Mode | Pipeline |
|--------|------|----------|
| **ClassicZ** | Public / Protected | Modified Base85 → RC4 → LZ4 → UTF-8 |
| **ClassicB** | Public / Protected | Custom Base64 → RC4 → UTF-8 |
| **Subdiv** | Public / Protected | token-replace → `we.subdiv` branch-5 decompressor |

All observed combinations across the 2013–2026 fixture corpus decrypt
end-to-end. See [`PLAN.md §7`](./PLAN.md) for the full corpus table.

---

## Install

```sh
cargo install --path crates/krpano-decrypt-cli   # installs the `krpano-decrypt` binary
```

Or build from source:

```sh
cargo build --release   # binary at target/release/krpano-decrypt
```

---

## CLI usage

```sh
# Decrypt an encrypted tour.xml using its tour.js when needed
krpano-decrypt decrypt tour.xml tour.js -o tour.decrypted.xml

# Some public ClassicB / ClassicZ payloads can be decrypted without JS
krpano-decrypt decrypt tour.xml -o tour.decrypted.xml

# Decode just the packed/obfuscated viewer engine from tour.js
krpano-decrypt decode-viewer tour.js -o decoded.js

# Print the krp:/ptp: wrapper key embedded in tour.js
krpano-decrypt wrapper-key tour.js

# Inspect an encrypted payload (header, cipher, mode, engine family) without decrypting
krpano-decrypt inspect tour.xml tour.js
```

Run `krpano-decrypt --help` for full options. `-v` / `-vv` enable info/debug logs.

---

## Library usage

```toml
# Cargo.toml
[dependencies]
krpano-decrypt = "0.1"
```

```rust
use krpano_decrypt::decrypt_xml;

let xml = std::fs::read("tour.xml")?;
let js  = std::fs::read("tour.js")?;
let plaintext = decrypt_xml(&xml, Some(&js))?;
std::fs::write("tour.decrypted.xml", plaintext)?;
```

The library API surface:

- `decrypt_xml(contents, viewer_data)` → `Result<Vec<u8>, KrpanoDecryptError>`
- `decrypt_xml_to_string(...)` → `Result<String, _>`
- `inspect(contents)` → header/cipher/mode without decrypting
- `extract_key_from_viewer_js`, `extract_decoded_viewer_js`, `detect_engine`
- `KencHeader`, `BodyCipher`, `CipherMode`, `EngineFamily`, `KrpanoDecryptError`

The library depends only on `base64`, `regex`, `thiserror`, and `log`.

---

## Design principles

1. **No JavaScript execution.** Keys are recovered by static analysis of the
   decoded engine source. Decryption is a pure function of the two input files.
2. **Value-based identification.** Constants are located by stable semantic
   value (`"actions overflow"`, `"z"`, `"krpano"`), never by hardcoded minified
   identifiers — so the same code handles engines from 2018 through 2026.
3. **Deterministic & offline.** No network, no JS runtime, no host application.

See [`AGENTS.md §3`](./AGENTS.md) for the full reverse-engineering principles.

---

## Reverse-engineering a new krpano version

When a new krpano build appears that the library can't decrypt yet:

1. Drop the tour into `testdata/encrypted/`.
2. Use the **dynamic tools** in `tools/` (which *do* execute krpano JS in a
   sandbox) to extract and trace the new obfuscated functions.
3. Deobfuscate the changed functions into `reference/` (diff against the
   existing reference to see what moved).
4. Port the delta into the Rust modules, preserving the exact i32 arithmetic
   the engine uses.
5. Add a fixture test + golden `plaintext.xml`; `cargo test` must stay green.

[`AGENTS.md §7`](./AGENTS.md) walks through this in detail.

> The dynamic tools run real, third-party krpano code. Use them on fixtures you
> control, not on arbitrary untrusted tours.

---

## Testing

The suite is self-contained (no network):

```sh
cargo test
```

Every fixture with both an XML and a JS is decrypted end-to-end and validated
as XML; golden `plaintext.xml` files are compared byte-for-byte (CRLF-normalized
for cross-platform CI). The static Rust extractor is cross-checked against
`rows.json` produced by `tools/extract_modern_rows.mjs`.

---

## License

GPL-3.0-only. See [`LICENSE`](./LICENSE).

## Acknowledgements

Extracted from [dezoomify-rs](https://github.com/lovasoa/dezoomify-rs), where
the krpano decryption was originally developed and reverse-engineered.
