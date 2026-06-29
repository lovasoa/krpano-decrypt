#!/usr/bin/env node
// capture_engine.mjs — capture the decoded krpano engine by EXECUTING the real
// loader.
//
// Unlike the Rust library (which statically parses the packed payload), this
// tool runs the real krpano loader code under a sandbox and intercepts the
// `Function`/`eval` call that compiles the decoded engine, capturing the source
// string. This is the dynamic counterpart to `extract_decoded_viewer_js` and is
// the first step for any other dynamic analysis: it gives you the real, decoded
// engine source to inspect or execute.
//
// Usage:
//   node capture_engine.mjs <tour.js> [--out decoded.js]
//   node capture_engine.mjs <tour.js>   # prints to stdout

import { readFileSync, writeFileSync } from "node:fs";
import { argv, exit, stderr } from "node:process";
import { loadEngine } from "./sandbox.mjs";

function main() {
  const args = argv.slice(2);
  if (args.length < 1) {
    stderr.write("usage: capture_engine.mjs <tour.js> [--out decoded.js]\n");
    exit(2);
  }
  const jsPath = args[0];
  const outIdx = args.indexOf("--out");
  const outPath = outIdx >= 0 ? args[outIdx + 1] : null;

  const src = readFileSync(jsPath, "utf8");
  const { engine, captured } = loadEngine(src, { filename: jsPath });
  if (captured) {
    stderr.write(`captured decoded engine via real loader: ${engine.length} bytes\n`);
  } else {
    stderr.write(`no packed loader detected; file is the engine directly: ${engine.length} bytes\n`);
  }
  if (outPath) {
    writeFileSync(outPath, engine);
    stderr.write(`wrote ${engine.length} bytes to ${outPath}\n`);
  } else {
    process.stdout.write(engine);
  }
}

main();
