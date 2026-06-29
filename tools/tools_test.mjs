import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

import { loadEngine } from "./sandbox.mjs";

const FIXTURE = "../testdata/encrypted/2026-06-25-pp-01_minimal/tour.js";

test("sandbox captures decoded engine and wrapper key", () => {
  const source = readFileSync(new URL(FIXTURE, import.meta.url), "utf8");
  const { engine, wrapperKey } = loadEngine(source, { filename: FIXTURE });

  assert.ok(engine.length > 100_000);
  assert.match(engine, /krpano/);
  assert.match(wrapperKey, /^krp:/);
});

test("extract_rows captures stable modern rows", () => {
  const output = execFileSync(
    process.execPath,
    ["extract_rows.mjs", FIXTURE],
    {
      cwd: new URL(".", import.meta.url),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const rows = JSON.parse(output);
  const values = Object.values(rows.values);

  assert.ok(values.includes("krpano"));
  assert.ok(values.includes("actions overflow"));
});
