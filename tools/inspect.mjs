#!/usr/bin/env node
// inspect.mjs — triage a new krpano tour.
//
// Runs the real loader to capture the decoded engine, then reports everything
// you need to start reverse-engineering: version, engine family markers, the
// KENC header of the XML, the wrapper key, structural features, and the
// location of key functions (startup IIFE, b64u8, we.subdiv, decrypt entry).
//
// This is the FIRST tool to run on a new tour.js / tour.xml pair.
//
// Usage:
//   node inspect.mjs <tour.js> [tour.xml]

import { readFileSync } from "node:fs";
import { argv, exit } from "node:process";
import { loadEngine } from "./sandbox.mjs";

function findVersion(engine, fileSrc) {
  const m = fileSrc.match(/krpano\s+([\d.]+\s*\(build\s*[\d-]+\)|[\d.]+)/i)
    || engine.match(/version\s*[:=]\s*['"]([\d.\w-]+)['"]/i);
  return m ? m[1].replace(/\s+/g, " ") : "unknown";
}

function locate(engine, needle, context = 60) {
  const i = engine.indexOf(needle);
  if (i === -1) return null;
  const s = Math.max(0, i - context);
  const e = Math.min(engine.length, i + needle.length + context);
  return { offset: i, snippet: engine.slice(s, e) };
}

function findWrapperKey(engine, fileSrc) {
  // The wrapper key lives in the loader (fileSrc) for modern engines, and in
  // the engine source for old engines. Scan both for a krp:/ptp: string literal.
  for (const text of [fileSrc, engine]) {
    const m = text.match(/['"]((?:krp|ptp):[^'"]{4,})['"]/);
    if (m) return m[1];
  }
  return null;
}

function parseKencHeader(xml) {
  const m = xml.match(/<encrypted>(?:<!\[CDATA\[)?(KENC.{4})/s);
  if (!m) return null;
  const h = m[1];
  const K = 80;
  const modeChar = h.charCodeAt(4), cipherChar = h.charCodeAt(6);
  const modeVal = (modeChar - K) >> 1;
  const cipherVal = cipherChar - K;
  const cipher = cipherVal === 10 ? "ClassicZ" : cipherVal === -14 ? "ClassicB" : (cipherVal === 0 || cipherVal === 2) ? "Subdiv" : "Unknown";
  const mode = modeVal === 0 ? "Public" : modeVal === 1 ? "Protected" : "Unknown";
  return { header: h, cipher, mode };
}

function findFunctionName(engine, marker) {
  // Find `function NAME(` or `NAME=function(` nearest to a marker.
  const i = engine.indexOf(marker);
  if (i === -1) return null;
  const before = engine.slice(0, i);
  const m1 = before.match(/function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{[^}]*$/);
  if (m1) return m1[1];
  const m2 = before.match(/([A-Za-z_$][\w$]*)=function\s*\([^)]*\)\s*\{[^}]*$/);
  if (m2) return m2[1];
  return null;
}

function main() {
  const [jsPath, xmlPath] = argv.slice(2);
  if (!jsPath) {
    console.error("usage: inspect.mjs <tour.js> [tour.xml]");
    exit(2);
  }
  const fileSrc = readFileSync(jsPath, "utf8");
  const { engine, captured } = loadEngine(fileSrc, { filename: jsPath });
  const xml = xmlPath ? readFileSync(xmlPath, "utf8") : null;

  console.log("=== krpano tour triage ===\n");
  console.log(`viewer JS:  ${jsPath}`);
  console.log(`version:    ${findVersion(engine, fileSrc)}`);
  console.log(`loader:     ${captured ? "packed (decoded engine captured by running real loader)" : "none (file is the engine directly)"}`);
  console.log(`engine:     ${engine.length} bytes`);

  // Engine family markers
  const markers = {
    KENC: engine.includes("KENC"),
    "b64u8=function": engine.includes("b64u8=function"),
    "we.subdiv": engine.includes("we.subdiv"),
    "String(e).charCodeAt": engine.includes("String(e).charCodeAt"),
    "String(h).charCodeAt": engine.includes("String(h).charCodeAt"),
    "actions overflow": engine.includes("actions overflow"),
    decryptData: engine.includes("decryptData"),
    decodeLicense: engine.includes("decodeLicense"),
    "(function ": engine.includes("(function "), // startup IIFE candidate
  };
  const family = markers["KENC"] || markers["b64u8=function"]
    ? "OLD (KENC literal / b64u8 decoder)"
    : markers["we.subdiv"] ? "MODERN (we.subdiv)" : "UNKNOWN / TRANSITIONAL";
  console.log(`\nengine family: ${family}`);
  console.log("markers:");
  for (const [k, v] of Object.entries(markers)) console.log(`  ${v ? "✓" : "✗"} ${k}`);

  // Wrapper key
  const wkey = findWrapperKey(engine, fileSrc);
  console.log(`\nwrapper key: ${wkey ? `${wkey.slice(0, 30)}... (${wkey.length} chars, prefix ${wkey.slice(0, 4)})` : "NOT FOUND (1.20+ may embed differently)"}`);

  // Key function locations
  console.log("\nkey function locations:");
  for (const needle of ["b64u8=function", "we.subdiv", "decryptData", "decodeLicense", "(function "]) {
    const loc = locate(engine, needle, 40);
    if (loc) console.log(`  ${needle.padEnd(22)} @ ${loc.offset}`);
  }

  // XML header
  if (xml) {
    console.log(`\nencrypted XML: ${xmlPath}`);
    const h = parseKencHeader(xml);
    if (h) {
      console.log(`KENC header: ${h.header}`);
      console.log(`cipher:      ${h.cipher}`);
      console.log(`mode:        ${h.mode}`);
    } else {
      const enc = /<encrypted>/.test(xml);
      console.log(enc ? "has <encrypted> but no KENC header parsed" : "not an encrypted krpano XML");
    }
  }

  console.log("\nnext steps:");
  console.log("  - node capture_engine.mjs <tour.js> --out decoded.js  # dump the engine");
  if (markers["we.subdiv"]) console.log("  - node extract_rows.mjs <tour.js> --out rows.json     # dump we.subdiv rows");
  console.log("  - node run_snippet.mjs <tour.js> --eval '<expr>'      # probe engine internals");
}

main();
