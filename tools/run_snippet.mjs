#!/usr/bin/env node
// run_snippet.mjs — execute arbitrary JavaScript against the real, decoded
// krpano engine.
//
// This loads the engine (captured by running the real loader) into a sandbox
// WITHOUT the Function/eval capture hooks, then evaluates a user-provided
// snippet in that context. The engine source is available as a string bound to
// `ENGINE`. You can use this to:
//   - extract and execute a specific function from the engine,
//   - probe what an obfuscated function returns for a given input,
//   - dump internal data structures the engine populates at load time.
//
// The engine is loaded as a Function created from its source (real krpano
// code), so any IIFEs / top-level setup in the engine run for real. The viewer
// itself does not boot because the host DOM is stubbed.
//
// Usage:
//   node run_snippet.mjs <tour.js> --eval '<JS expression>'
//   node run_snippet.mjs <tour.js> --file snippet.js
//   node run_snippet.mjs <tour.js> --eval 'ENGINE.length'
//   node run_snippet.mjs <tour.js> --eval 'ENGINE.indexOf("we.subdiv")'
//
// Inside the snippet:
//   ENGINE  — the decoded engine source string
//   SRC     — the original tour.js source
//   console — for output
//   loadFn(name)  — compile the engine as a Function and return it (so you can
//                   call engine entry points, e.g. loadFn()(params, 'krp:...'))

import { readFileSync } from "node:fs";
import { argv, exit } from "node:process";
import { createSandbox, runIn, loadEngine } from "./sandbox.mjs";

function main() {
  const args = argv.slice(2);
  const jsPath = args[0];
  if (!jsPath) {
    console.error("usage: run_snippet.mjs <tour.js> --eval '<expr>' | --file <snippet.js>");
    exit(2);
  }
  const fileSrc = readFileSync(jsPath, "utf8");
  const { engine } = loadEngine(fileSrc, { filename: jsPath });

  let snippet;
  const ei = args.indexOf("--eval");
  const fi = args.indexOf("--file");
  if (ei >= 0) snippet = `return (${args[ei + 1]});`;
  else if (fi >= 0) snippet = readFileSync(args[fi + 1], "utf8");
  else {
    console.error("provide --eval '<expr>' or --file <snippet.js>");
    exit(2);
  }

  // A fresh sandbox with hooks OFF so the engine's own Function/eval run for real.
  const { context } = createSandbox({ captureFunction: false });
  context.ENGINE = engine;
  context.SRC = fileSrc;
  // loadFn: compile the engine source into a real Function (as the loader does).
  context.loadFn = () => {
    // The engine source is `function embedhtml5(...){...}` or similar. Wrap it
    // so it evaluates and returns the top-level function.
    return runIn(`(function(){ ${engine}; return typeof embedpano==='function'?embedpano:(typeof embedhtml5==='function'?embedhtml5:(typeof createPanoViewer==='function'?createPanoViewer:null)); })()`, context, "engine.mjs");
  };

  const wrapped = `(function(){ ${snippet} })()`;
  try {
    const result = runIn(wrapped, context, "snippet.mjs");
    console.log(typeof result === "string" ? result : JSON.stringify(result, null, 2));
  } catch (err) {
    console.error("snippet error:", err.message);
    exit(1);
  }
}

main();
