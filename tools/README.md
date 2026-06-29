# Dynamic analysis tools

These tools **execute real krpano JavaScript** and instrument it to help
reverse-engineer new krpano versions. They are the dynamic counterpart to the
Rust library's static analysis.

> The Rust library NEVER executes JavaScript — it recovers keys by static
> analysis of the decoded engine source. These tools DO execute krpano code, in
> a controlled Node sandbox or a browser, to observe runtime behavior and to
> produce ground-truth data (decoded engine, `we.subdiv` rows, decrypt traces)
> that the Rust port is cross-checked against.
>
> **Safety.** These tools run real, third-party krpano code. Run them on fixtures
> you control, not on arbitrary untrusted tours.

## Setup

Node.js >= 18. No dependencies — the tools use only Node built-ins (`node:vm`,
`node:fs`). Just run them directly.

## Tools

### `sandbox.mjs` — the foundation

A reusable Node `vm` sandbox that provides a minimal browser environment
(`document`, `navigator`, `window`, …) and intercepts `Function`/`eval` so the
krpano loader's decoded engine source is **captured** instead of executed.

`loadEngine(tourJsSource)` runs the real loader and returns:
- `engine` — the decoded engine source (captured by intercepting the loader's
  `new Function(src)` call; for old/transitional engines that ship the engine
  directly, the file itself).
- `wrapperKey` — the `krp:`/`ptp:` wrapper key (captured from the loader's
  `engine(params, wrapperKey)` call).

All other tools build on this.

### `capture_engine.mjs` — dump the decoded engine

```sh
node capture_engine.mjs tour.js --out decoded.js
```

Runs the real loader and writes the decoded engine source. Dynamic counterpart
of the Rust `extract_decoded_viewer_js`.

### `inspect.mjs` — triage a new tour (run this first)

```sh
node inspect.mjs tour.js [tour.xml]
```

Reports: version, engine family (old/modern/transitional), structural markers
(`KENC`, `b64u8`, `we.subdiv`, `decryptData`, …), the `krp:`/`ptp:` wrapper key,
key-function offsets, and the XML's `KENC` header (cipher + mode). This is the
first tool to run on an unknown `tour.js`.

### `extract_rows.mjs` — dump `we.subdiv` rows (dynamic)

```sh
node extract_rows.mjs tour.js --out rows.json
```

Executes the real engine's startup IIFE (with the real wrapper key) and captures
the `we.subdiv` rows and side data just before they are consumed, writing them
as `rows.json` (`{ rows: { idx: hex }, values: { idx: string }, side_hex }`).

**Two-pass technique.** The startup IIFE checksums its own source text
(`k = qf(Rd(c))`), so any source patch inside the IIFE body breaks the unpack.
Pass 1 captures the correct `k` by prepending an assignment *outside* the IIFE
body (the IIFE returns `k`). Pass 2 replaces the checksum call with the literal
`k` and captures the rows.

Supports modern engines (1.21+, where the loader passes `krp:` to the engine).
Old/transitional engines embed the wrapper key differently; use `inspect.mjs`
and `capture_engine.mjs` for those.

### `trace_decrypt.mjs` — trace the unpack

```sh
node trace_decrypt.mjs tour.js [--stage unpack|keys|all]
```

Instruments the real engine's wrapper-unpack and prints the rolling checksum
`t`, the verify value `g`, the row/side counts, and the locations of key rows
(`krpano`, `actions overflow`, `z`, `KENC`). Use it to compare against the Rust
pipeline stage-by-stage when debugging a failing fixture.

### `run_snippet.mjs` — execute arbitrary JS against the engine

```sh
node run_snippet.mjs tour.js --eval 'ENGINE.indexOf("we.subdiv")'
node run_snippet.mjs tour.js --file probe.js
```

Loads the engine into a sandbox (with capture hooks OFF, so the engine's own
`new Function` runs for real) and evaluates a snippet. `ENGINE` is the decoded
engine source; `loadFn()` compiles it as a real Function. Use this to probe
engine internals, test what an obfuscated function returns for a given input,
or dump data structures the engine populates.

### `browser/instrument.html` — browser harness

Open in a browser (via a static server or `file://`). Loads a REAL krpano viewer,
intercepts `XMLHttpRequest`/`fetch` to feed a chosen encrypted XML, captures the
decoded engine via `Function`/`eval` hooks, and logs decrypt entry-point
activity. Use it for behavior that only manifests with a full DOM/WebGL (e.g.
1.20+ key embedding, runtime-only paths).

## Smoke tests

```sh
npm test --prefix tools
```

Runs the tools against the checked-in fixtures and asserts they produce sane
output (engine captured, rows contain `krpano`/`actions overflow`/`z`).

## Reverse-engineering workflow

When a new krpano version appears:

1. `inspect.mjs tour.js tour.xml` — triage. Note the version, family, markers.
2. `capture_engine.mjs tour.js --out decoded.js` — dump the decoded engine.
3. `extract_rows.mjs tour.js --out rows.json` — dump `we.subdiv` rows.
4. Diff the decoded engine / rows against a known version to see what moved.
5. `run_snippet.mjs` / `trace_decrypt.mjs` to probe and confirm hypotheses.
6. Port the delta into the Rust library; add a fixture + test; `cargo test`.

See [`../AGENTS.md §7`](../AGENTS.md) for the full workflow.
