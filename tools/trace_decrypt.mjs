#!/usr/bin/env node
// trace_decrypt.mjs — instrument the real krpano engine's decrypt path and log
// intermediate values.
//
// This loads the real engine (captured by running the loader), patches the
// startup IIFE to dump every intermediate value of the wrapper-unpack (the
// `n`, `q`, `z`, rolling checksum `t`, and each row/side value as it is
// produced), and prints a trace. Use it to debug a fixture the Rust port fails
// on by comparing the trace against the Rust pipeline stage by stage.
//
// It reuses the two-pass technique from extract_rows.mjs (capture the correct
// checksum k outside the IIFE body, then replace the checksum call with the
// literal so source patching inside the IIFE is safe).
//
// Usage:
//   node trace_decrypt.mjs <tour.js> [--stage unpack|keys|all]

import { readFileSync } from "node:fs";
import { argv, exit, stderr } from "node:process";
import { createSandbox, runIn, loadEngine } from "./sandbox.mjs";

function findStartupIife(engine) {
  const m = engine.match(/\(function\s+(\w+)\s*\(\)\s*\{\s*var\s+(\w+)=(\w+)\[2\]\|\|\w+\[1\]/);
  if (!m) return null;
  const fnName = m[1], start = m.index;
  const after = engine.slice(start);
  const endMatch = after.match(/return\s+(\w+)\}\)\(\)/);
  if (!endMatch) return null;
  const kVar = endMatch[1];
  const invokeEnd = start + endMatch.index + endMatch[0].length;
  const callRe = new RegExp(`${kVar}=(\\w+)\\((\\w+)\\((${fnName})\\)\\)`);
  const callMatch = engine.match(callRe);
  return { fnName, kVar, start, invokeEnd, checksumCall: callMatch?.[0] ?? null };
}

function captureCorrectK(engine, wrapperKey, iife) {
  const PREPEND = "globalThis.__correctK=";
  const { context } = createSandbox({ captureFunction: false });
  context.__patched = (() => {
    let p = engine.slice(0, iife.start) + PREPEND + engine.slice(iife.start);
    p = p.slice(0, iife.invokeEnd + PREPEND.length) + ";throw 1;" + p.slice(iife.invokeEnd + PREPEND.length);
    return p;
  })();
  context.__wkey = wrapperKey;
  try { runIn("var __fn=new Function(__patched);try{__fn({},__wkey)}catch(e){}", context, "k.mjs", 12000); } catch {}
  return context.__correctK;
}

function main() {
  const args = argv.slice(2);
  const jsPath = args[0];
  if (!jsPath) { stderr.write("usage: trace_decrypt.mjs <tour.js> [--stage unpack|keys|all]\n"); exit(2); }
  const stage = args[args.indexOf("--stage") + 1] || "all";

  const fileSrc = readFileSync(jsPath, "utf8");
  const { engine, wrapperKey } = loadEngine(fileSrc, { filename: jsPath });
  if (!wrapperKey) { stderr.write("no wrapper key captured (modern engines only).\n"); exit(1); }
  const iife = findStartupIife(engine);
  if (!iife?.checksumCall) { stderr.write("startup IIFE / checksum call not found.\n"); exit(1); }

  const correctK = captureCorrectK(engine, wrapperKey, iife);
  stderr.write(`checksum k = ${correctK}\n`);

  // Patch: replace the checksum call, then inject a trace probe that records the
  // unpack parameters and each row as it is pushed. The probe goes right after
  // the `var` declaration (safe, since k is now a literal).
  const varEnd = engine.match(/u=gd\("<"\+Ma\[0\]\+">"\);|w=Cd\("<"\+cb\[0\]\+">"\);/);
  let patched = engine.replace(iife.checksumCall, `${iife.kVar}=${correctK}`);

  // Inject a trace: wrap Array.prototype.push to record rows/side as built.
  // We scope it narrowly by recording into globals.
  const marker = patched.match(/(\w+)!=(\w+)&&\((\w+)=(\w+)=null\)\}/);
  if (!marker) { stderr.write("consumer marker not found.\n"); exit(1); }
  const [, gVar, tVar, sideVar, rowsVar] = marker;
  // Capture the unpack parameters (n,q,z,v,x) and the final t + rows.
  // The IIFE uses `n`, `q`, `z` etc. as locals; capture them by name-agnostic
  // insertion after the var block is hard, so we record the rows + final t.
  const whole = marker[0];
  const mi = patched.indexOf(whole);
  patched = patched.slice(0, mi) +
    `globalThis.__trace_rows=${rowsVar};globalThis.__trace_side=${sideVar};globalThis.__trace_t=${tVar};globalThis.__trace_g=${gVar};throw '__trace__';` +
    patched.slice(mi);

  const { context } = createSandbox({ captureFunction: false });
  context.__patched = patched; context.__wkey = wrapperKey;
  try { runIn("var __fn=new Function(__patched);try{__fn({},__wkey)}catch(e){}", context, "trace.mjs", 12000); } catch {}

  const dec = (row) => Array.isArray(row) ? row.map((c) => String.fromCharCode(c & 0xff)).join("") : String(row);
  console.log("=== unpack trace ===");
  console.log(`wrapper key length : ${wrapperKey.length}`);
  console.log(`checksum k          : ${correctK}`);
  console.log(`final rolling t    : ${context.__trace_t}`);
  console.log(`final verify g     : ${context.__trace_g}`);
  console.log(`checksum match     : ${context.__trace_t === context.__trace_g}`);
  console.log(`rows               : ${context.__trace_rows?.length ?? 0}`);
  console.log(`side values        : ${context.__trace_side?.length ?? 0}`);
  if ((stage === "keys" || stage === "all") && context.__trace_rows) {
    console.log("\n=== key rows ===");
    for (const target of ["krpano", "actions overflow", "z", "KENC"]) {
      const idx = context.__trace_rows.findIndex((r) => { try { return dec(r) === target; } catch { return false; } });
      console.log(`  ${target.padEnd(18)} : ${idx === -1 ? "not found" : `row[${idx}]`}`);
    }
  }
  if (stage === "unpack" || stage === "all") {
    console.log("\n=== first 10 rows ===");
    for (let i = 0; i < Math.min(10, context.__trace_rows?.length ?? 0); i++) {
      console.log(`  [${i}] ${JSON.stringify(dec(context.__trace_rows[i]).slice(0, 50))}`);
    }
  }
}

main();
