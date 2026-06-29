#!/usr/bin/env node
// extract_rows.mjs — dynamically extract the we.subdiv rows and side data by
// EXECUTING the real krpano engine.
//
// Unlike the Rust library (which statically replicates the wrapper-unpack
// arithmetic), this tool runs the real, decoded engine in a sandbox and lets
// the engine's own startup IIFE unpack the `krp:` wrapper key, then captures
// the resulting rows and side data just before they are consumed.
//
// Why the two-pass approach:
//   The startup IIFE checksums its OWN source text (k = qf(Rd(c))). Any source
//   patch inside the IIFE body changes that checksum and breaks the unpack. So
//   we:
//     pass 1 — prepend an assignment OUTSIDE the IIFE body to capture the
//              correct checksum `k` (the IIFE returns k), then abort.
//     pass 2 — replace `k=qf(Rd(c))` with the literal `k=<correctK>` (so the
//              polluted source no longer matters) and capture the rows.
//
// Usage:
//   node extract_rows.mjs <tour.js> [--out rows.json]
//   node extract_rows.mjs <tour.js>   # prints JSON to stdout

import { readFileSync, writeFileSync } from "node:fs";
import { argv, exit, stderr } from "node:process";
import { createSandbox, runIn, loadEngine } from "./sandbox.mjs";

/** Find the startup IIFE. It has the shape:
 *    (function NAME(){var V=ARGS[2]||ARGS[1];...K=qfLike(rdLike(NAME))...return K})()
 *  Minified names differ per build (1.21: Ld/c/k/qf/Rd; 1.24: ce/a/u/og/le), so
 *  we match structurally and capture the names we need to patch in pass 2.
 *  The end is located by `return <k>})()` (the IIFE returns its checksum),
 *  scoped to AFTER the IIFE opening so we match the right `return`. */
function findStartupIife(engine) {
  const m = engine.match(
    /\(function\s+(\w+)\s*\(\)\s*\{\s*var\s+(\w+)=(\w+)\[2\]\|\|\w+\[1\]/
  );
  if (!m) return null;
  const fnName = m[1];
  const start = m.index;
  // The checksum variable is whatever `return X})()` returns. Scope the search
  // to AFTER the IIFE opening so we match this IIFE's return.
  const after = engine.slice(start);
  const endMatch = after.match(/return\s+(\w+)\}\)\(\)/);
  if (!endMatch) return null;
  const kVar = endMatch[1];
  const endIdx = start + endMatch.index;
  const invokeEnd = endIdx + endMatch[0].length;
  // Locate the checksum call to replace in pass 2: `<kVar>=<qf>(<rd>(<fnName>))`
  const callRe = new RegExp(
    `${kVar}=(\\w+)\\((\\w+)\\((${fnName})\\)\\)`
  );
  const callMatch = engine.match(callRe);
  return {
    fnName,
    kVar,
    start,
    invokeEnd,
    checksumCall: callMatch ? callMatch[0] : null,
  };
}

/** Run a patched engine, return whatever globals were set before the throw. */
function runPatched(engine, wrapperKey, patchFn) {
  const { context } = createSandbox({ captureFunction: false });
  context.__patched = patchFn(engine);
  context.__wkey = wrapperKey;
  try {
    runIn('var __fn=new Function(__patched);try{__fn({},__wkey)}catch(e){}', context, "extract.mjs", 12000);
  } catch { /* timeout/abort: globals may still be set */ }
  return context;
}

function decodeRow(row) {
  if (!Array.isArray(row)) return null;
  let s = "";
  for (const c of row) s += String.fromCharCode(c);
  return s;
}

function main() {
  const args = argv.slice(2);
  const jsPath = args[0];
  if (!jsPath) { stderr.write("usage: extract_rows.mjs <tour.js> [--out rows.json]\n"); exit(2); }
  const outIdx = args.indexOf("--out");
  const outPath = outIdx >= 0 ? args[outIdx + 1] : null;

  const fileSrc = readFileSync(jsPath, "utf8");
  const { engine, wrapperKey } = loadEngine(fileSrc, { filename: jsPath });
  if (!wrapperKey) {
    stderr.write("no wrapper key captured (old/transitional engines embed it differently);\n");
    stderr.write("this tool supports modern engines (1.21+) where the loader passes krp: to the engine.\n");
    exit(1);
  }
  const iife = findStartupIife(engine);
  if (!iife) {
    stderr.write("startup IIFE not found (pattern: (function NAME(){var a=Ld[2]||Ld[1]).\n");
    stderr.write("The engine may use a different unpack structure; inspect with inspect.mjs.\n");
    exit(1);
  }
  stderr.write(`startup IIFE: name=${iife.fnName} at offset ${iife.start}\n`);

  // Pass 1: capture correctK (assignment OUTSIDE the IIFE body — no pollution).
  // NOTE: prepending shifts indices after `iife.start`, so recompute the
  // invocation end in the patched string.
  const PREPEND = "globalThis.__correctK=";
  const kCtx = runPatched(engine, wrapperKey, (eng) => {
    const invokeEndPatched = iife.invokeEnd + PREPEND.length;
    let p = eng.slice(0, iife.start) + PREPEND + eng.slice(iife.start);
    p = p.slice(0, invokeEndPatched) + ";throw '__k__';" + p.slice(invokeEndPatched);
    return p;
  });
  const correctK = kCtx.__correctK;
  if (typeof correctK !== "number") {
    stderr.write("could not capture the unpack checksum k (pass 1 failed).\n");
    exit(1);
  }
  stderr.write(`checksum k = ${correctK}\n`);

  // Pass 2: replace the checksum call with the literal k, capture rows before
  // consumption. The row/side variable names differ per build, so locate the
  // consumer by the `!=K&&(S=R=null)}` pattern (checksum-mismatch nulls rows).
  if (!iife.checksumCall) {
    stderr.write("could not locate the checksum call to replace (unpack structure changed).\n");
    exit(1);
  }
  const ctx = runPatched(engine, wrapperKey, (eng) => {
    let p = eng.replace(iife.checksumCall, `${iife.kVar}=${correctK}`);
    // Consumer pattern: <g>!=<t>&&(<sideVar>=<rowsVar>=null)}
    const consumer = p.match(/(\w+)!=(\w+)&&\((\w+)=(\w+)=null\)\}/);
    if (!consumer) throw new Error("row-consumer marker not found (structure changed)");
    const [whole, gVar, tVar, sideVar, rowsVar] = consumer;
    const ci = p.indexOf(whole);
    p = p.slice(0, ci) +
      `globalThis.__rows=${rowsVar};globalThis.__side=${sideVar};throw '__rc__';` +
      p.slice(ci);
    return p;
  });

  const rows = ctx.__rows;
  const side = ctx.__side;
  if (!Array.isArray(rows)) {
    stderr.write("rows were not captured (pass 2 failed). The unpack may have aborted early.\n");
    exit(1);
  }
  stderr.write(`captured ${rows.length} rows, ${side?.length ?? 0} side values\n`);

  // Build rows.json: { rows: { "<index>": "<hex>" }, values: { "<index>": "<string>" }, side: [...] }
  const rowsHex = {};
  const rowsValue = {};
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i] || [];
    rowsHex[String(i)] = r.map((c) => (c & 0xff).toString(16).padStart(2, "0")).join("");
    const v = decodeRow(r);
    if (v != null) rowsValue[String(i)] = v;
  }
  const sideHex = (side || []).map((c) => (c & 0xff).toString(16).padStart(2, "0")).join("");
  const output = {
    engine_length: engine.length,
    wrapper_key_length: wrapperKey.length,
    checksum_k: correctK,
    checksum_constant: correctK + (23261 - correctK === 0 ? 0 : 0), // informational
    row_count: rows.length,
    side_length: side?.length ?? 0,
    rows: rowsHex,
    values: rowsValue,
    side_hex: sideHex,
  };

  const json = JSON.stringify(output, null, 2);
  if (outPath) {
    writeFileSync(outPath, json);
    stderr.write(`wrote rows to ${outPath}\n`);
  } else {
    process.stdout.write(json + "\n");
  }
}

main();
