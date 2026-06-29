// sandbox.mjs — a minimal browser-environment sandbox for executing real
// krpano viewer JavaScript under Node.js.
//
// The krpano loader (`tour.js`) and decoded engine expect a handful of browser
// globals (document, navigator, window, Function, Uint8Array, ...). This module
// provides just enough of a shim to let the loader's *decode* code run, and to
// let targeted snippets of the decoded engine execute, WITHOUT booting the full
// WebGL/DOM viewer.
//
// Two hooks make this useful for reverse engineering:
//   - `Function` is wrapped: any engine source the loader tries to compile via
//     `new Function(src)` / `Function(src)` is captured (so we can inspect the
//     decoded engine instead of executing it).
//   - `eval` is wrapped the same way.
//
// Everything runs inside Node's `vm` module, isolated from the host process.

import vm from "node:vm";

/**
 * Build a sandbox context suitable for running krpano JS.
 * @param {object} [opts]
 * @param {boolean} [opts.captureFunction=true]  intercept `Function`/`eval` and
 *        record the source string they receive, returning a no-op function.
 * @param {string} [opts.scriptSrc]              value for `document.currentScript.src`.
 * @returns {{ context: object, captured: string[] }}
 */
export function createSandbox(opts = {}) {
  const { captureFunction = true, scriptSrc = "tour.js" } = opts;
  const captured = [];
  const callArgs = []; // string args passed to each hooked Function call (e.g. wrapper key)

  // Minimal DOM stub. krpano only touches a few properties at load/decode time.
  const fakeScript = { src: scriptSrc, type: "text/javascript" };
  const documentStub = {
    currentScript: fakeScript,
    getElementsByTagName: () => [fakeScript],
    createElement: () => ({ style: {}, setAttribute() {}, appendChild() {}, src: "" }),
    getElementById: () => null,
    body: {},
    documentElement: {},
    location: { href: "https://example.com/tour.html", search: "", hash: "" },
    readyState: "complete",
    addEventListener() {},
    removeEventListener() {},
  };
  const navigatorStub = {
    userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    platform: "Linux x86_64",
    language: "en",
  };
  const locationStub = { href: "https://example.com/tour.html", search: "", hash: "", protocol: "https:" };

  // The Function interceptor: when the loader compiles the decoded engine, we
  // grab the source instead of running it. Returning a function keeps the
  // loader's control flow intact.
  const realFunction = Function;
  const functionHook = captureFunction
    ? function (...args) {
        const body = args[args.length - 1];
        if (typeof body === "string" && body.length > 100) captured.push(body);
        // Record string args passed both to Function() (e.g. param names) and to
        // the returned engine function (the loader calls engine(params, wrapperKey)).
        callArgs.push(args.filter((a) => typeof a === "string").map((a) => a.slice(0, 8000)));
        return function (...invocationArgs) {
          callArgs.push(invocationArgs.filter((a) => typeof a === "string").map((a) => a.slice(0, 8000)));
          /* no-op: viewer not booted */
        };
      }
    : realFunction;

  const context = {
    // Real JS built-ins the decode loop needs.
    Array, Uint8Array, Int8Array, Uint16Array, Int16Array, Uint32Array, Int32Array,
    Float32Array, Float64Array, ArrayBuffer, DataView,
    Math, Date, JSON, String, Number, Boolean, Object, RegExp, Error, TypeError,
    parseInt, parseFloat, isNaN, isFinite, encodeURIComponent, decodeURIComponent,
    encodeURI, decodeURI, escape, unescape,
    setTimeout: () => 0, clearTimeout: () => {}, setInterval: () => 0, clearInterval: () => {},
    console,
    // Browser globals.
    document: documentStub,
    navigator: navigatorStub,
    location: locationStub,
    window: null, // set below (self-reference)
    self: null,
    globalThis: null,
    // Hooks. When captureFunction is false we leave Function/eval as the
    // context's own built-ins (set below) so that `new Function()` bodies
    // execute in the sandbox realm and see these stubbed globals.
    ...(captureFunction
      ? { Function: functionHook,
          eval: (src) => { if (typeof src === "string" && src.length > 100) captured.push(src); return undefined; } }
      : {}),
  };
  context.window = context;
  context.self = context;
  context.globalThis = context;

  vm.createContext(context);
  return { context, captured, callArgs };
}

/**
 * Run a script string in a sandbox.
 * @param {string} code
 * @param {object} context  a context from createSandbox()
 * @param {string} [filename]
 * @returns {unknown} the script's last expression value
 */
export function runIn(code, context, filename = "krpano.js", timeout = 10000) {
  return vm.runInContext(code, context, { filename, timeout });
}

/**
 * Read a file and run it in a sandbox, returning whatever the loader captured
 * via the Function/eval hooks. If nothing was captured (old/transitional engines
 * that ship the engine source directly), returns the file contents.
 *
 * @param {string} jsSource  the raw tour.js / krpano.js source
 * @param {object} [opts]
 * @returns {{ engine: string, captured: boolean, capturedSources: string[] }}
 */
export function loadEngine(jsSource, opts = {}) {
  const { context, captured, callArgs } = createSandbox(opts);
  // Modern loaders (1.21+, "var krpanoJS = { embedpano: function(){...}() }")
  // decode the packed engine *lazily*: the IIFE only sets up a wrapper, and the
  // actual Base85+LZ4 decode + `new Function(src)` happens the first time
  // `embedpano(params)` is called. Trigger it so the Function hook captures the
  // decoded engine source. The hook returns a no-op, so the viewer never boots.
  const triggerCalls = opts.triggerCalls ?? ["embedpano", "krpanoJS.embedpano", "embedpanoJS", "createPanoViewer"];
  try {
    runIn(jsSource, context, opts.filename ?? "tour.js");
  } catch (err) {
    if (captured.length === 0 && !looksLikeEngineSource(jsSource)) throw err;
  }
  if (captured.length === 0) {
    for (const call of triggerCalls) {
      try {
        runIn(`(${call}) && typeof ${call} === "function" && ${call}({});`, context, "trigger.mjs");
      } catch {
        // The no-op engine may throw when the host page isn't real; the
        // captured source is already recorded by then.
      }
      if (captured.length > 0) break;
    }
  }
  if (captured.length > 0) {
    // The largest captured source is the decoded engine.
    const engine = captured.reduce((a, b) => (b.length > a.length ? b : a));
    const flat = callArgs.flat();
   const wrapperKey = flat.filter((a) => typeof a === "string" && /^(krp|ptp):/.test(a)).sort((a, b) => b.length - a.length)[0] ?? null;
   return { engine, captured: true, capturedSources: captured, wrapperKey };
  }
  // Old/transitional engines ship the engine source directly.
  return { engine: jsSource, captured: false, capturedSources: [], wrapperKey: null };
}

/** Heuristic: does this text look like a krpano decoded engine? */
export function looksLikeEngineSource(text) {
  if (typeof text !== "string" || text.length < 1000) return false;
  const stripped = text.replace(/^\uFEFF/, "").trimStart();
  if (!/^(function |var |\/\*)/.test(stripped)) return false;
  return (
    text.includes("loadpano") ||
    text.includes("embedhtml5") ||
    text.includes("embedpano") ||
    text.includes("createPanoViewer") ||
    text.includes("krpano") ||
    text.includes("KENC") ||
    text.includes("we.subdiv") ||
    text.includes("b64u8")
  );
}
