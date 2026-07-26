#!/usr/bin/env node
/**
 * understand-anything-viewer — serve a generated knowledge graph in the
 * dashboard UI with nothing but Node.js. Read-only, no Claude Code, no LLM.
 *
 * Usage:
 *     understand-anything-viewer [project-dir] [--port <n>] [--no-open]
 *
 * The project directory (default: cwd) must contain a data directory —
 * `.ua/` or legacy `.understand-anything/` — with a knowledge-graph.json
 * produced by /understand.
 *
 * Security model mirrors the dashboard dev server (vite.config.ts):
 *   - binds to 127.0.0.1 only
 *   - every data endpoint requires the one-time ?token= printed at startup
 *   - graph JSON is served with node filePaths relativised to the project
 *   - /file-content.json only serves files listed in the graph, capped at
 *     1 MB, never binary
 */
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getGraphFreshnessBatch } from "./dist/staleness.js";

const DIST_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist");
const MAX_SOURCE_FILE_BYTES = 1024 * 1024;
// Legacy directory first — projects analyzed before the `.ua` rename keep
// their existing `.understand-anything/` data.
const UA_DIR_CANDIDATES = [".understand-anything", ".ua"];

// ── CLI args ───────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
let projectRoot = process.cwd();
let port = 5173;
let portExplicit = false;
let openBrowser = true;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--port") {
    port = Number(args[++i]);
    portExplicit = true;
    // 0 asks the OS for any free port.
    if (!Number.isInteger(port) || port < 0 || port > 65535) {
      console.error("Error: --port must be an integer between 0 and 65535");
      process.exit(1);
    }
  } else if (a === "--no-open") {
    openBrowser = false;
  } else if (a === "--help" || a === "-h") {
    console.log("Usage: understand-anything-viewer [project-dir] [--port <n>] [--no-open]");
    process.exit(0);
  } else if (!a.startsWith("-")) {
    projectRoot = path.resolve(a);
  } else {
    console.error(`Error: unknown option ${a}`);
    process.exit(1);
  }
}

if (!fs.existsSync(DIST_DIR)) {
  console.error(
    "Error: embedded dashboard build not found. This tarball was packed " +
    "without running the build — run `pnpm --filter understand-anything-viewer build` first.",
  );
  process.exit(1);
}

const graphDir = UA_DIR_CANDIDATES
  .map((d) => path.join(projectRoot, d))
  .find((d) => fs.existsSync(path.join(d, "knowledge-graph.json")));

if (!graphDir) {
  console.error(
    `Error: no knowledge graph found under ${projectRoot}\n` +
    "Expected .ua/knowledge-graph.json (or legacy .understand-anything/). " +
    "Generate one with /understand first, or pass the project directory as an argument.",
  );
  process.exit(1);
}

// Canonical project root, resolved once at startup. Every /file-content.json
// request re-verifies containment against THIS path rather than the lexical
// `projectRoot`, so an in-project symlink cannot be used to read outside the
// project. See readSourceFile().
// NIST SP 800-53 Rev.5 AC-3 (Access Enforcement); CWE-59 (Link Following).
const PROJECT_ROOT_REAL = fs.realpathSync(projectRoot);

// NIST SP 800-53 Rev.5 IA-5(1) (Authenticator Management — complexity).
// The generated default carries 128 bits of entropy. An operator-supplied
// override must not silently weaken that: refuse to serve local source code
// behind a short or guessable shared secret.
const TOKEN_OVERRIDE = process.env.UNDERSTAND_ACCESS_TOKEN;
if (TOKEN_OVERRIDE !== undefined && !/^[A-Za-z0-9_-]{32,128}$/.test(TOKEN_OVERRIDE)) {
  console.error(
    "Error: UNDERSTAND_ACCESS_TOKEN must be 32-128 characters drawn from [A-Za-z0-9_-].\n" +
    "Unset it to use a securely generated 128-bit token.",
  );
  process.exit(1);
}
const ACCESS_TOKEN = TOKEN_OVERRIDE || crypto.randomBytes(16).toString("hex");

// ── Helpers (mirroring vite.config.ts) ────────────────────────────────────

function sendJson(res, statusCode, payload) {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(payload));
}

/**
 * Constant-time bearer-token comparison.
 *
 * NIST SP 800-53 Rev.5 IA-5 (Authenticator Management), SC-13 (Cryptographic
 * Protection). CWE-208 (Observable Timing Discrepancy): a plain `!==` on
 * strings short-circuits at the first differing byte, which leaks the token
 * one byte at a time to anyone who can time responses on the loopback
 * interface. Compare in constant time and keep the timing profile flat even
 * when the supplied length is wrong.
 */
function tokenMatches(supplied) {
  const a = Buffer.from(String(supplied ?? ""), "utf8");
  const b = Buffer.from(ACCESS_TOKEN, "utf8");
  if (a.length !== b.length) {
    crypto.timingSafeEqual(b, b);
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

function normalizeGraphPath(filePath) {
  const rawPath = path.isAbsolute(filePath)
    ? filePath.startsWith(projectRoot)
      ? path.relative(projectRoot, filePath)
      : null
    : filePath;
  if (rawPath === null) return null;
  const normalized = path.normalize(rawPath);
  if (
    !normalized ||
    normalized === "." ||
    normalized.includes("\0") ||
    normalized === ".." ||
    normalized.startsWith(`..${path.sep}`) ||
    path.isAbsolute(normalized)
  ) {
    return null;
  }
  return normalized.split(path.sep).join("/");
}

function graphFilePathSet() {
  const allowed = new Set();
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(graphDir, "knowledge-graph.json"), "utf-8"));
    for (const node of raw.nodes ?? []) {
      if (typeof node.filePath !== "string") continue;
      const normalized = normalizeGraphPath(node.filePath);
      if (normalized) allowed.add(normalized);
    }
  } catch {
    return allowed;
  }
  return allowed;
}

function detectLanguage(filePath) {
  const ext = path.extname(filePath).slice(1).toLowerCase();
  const byExt = {
    bash: "bash", c: "c", cc: "cpp", cpp: "cpp", cs: "csharp", css: "css",
    go: "go", h: "c", hpp: "cpp", html: "markup", java: "java",
    js: "javascript", jsx: "jsx", json: "json", md: "markdown",
    mjs: "javascript", py: "python", rb: "ruby", rs: "rust", sh: "bash",
    ts: "typescript", tsx: "tsx", txt: "text", yaml: "yaml", yml: "yaml",
  };
  return byExt[ext] ?? "text";
}

function readSourceFile(url) {
  const reject = (message, statusCode = 400) => ({ statusCode, payload: { error: message } });
  const requestedPath = url.searchParams.get("path") ?? "";
  if (!requestedPath) return reject("Missing path");
  if (requestedPath.includes("\0")) return reject("Invalid path");
  if (path.isAbsolute(requestedPath)) return reject("Absolute paths are not allowed");

  const normalizedPath = path.normalize(requestedPath);
  if (
    normalizedPath === "." ||
    normalizedPath.startsWith(`..${path.sep}`) ||
    normalizedPath === ".." ||
    path.isAbsolute(normalizedPath)
  ) {
    return reject("Path must stay inside the project");
  }

  const absoluteFile = path.resolve(projectRoot, normalizedPath);
  const relativeToRoot = path.relative(projectRoot, absoluteFile);
  if (
    !relativeToRoot ||
    relativeToRoot.startsWith(`..${path.sep}`) ||
    relativeToRoot === ".." ||
    path.isAbsolute(relativeToRoot)
  ) {
    return reject("Path must stay inside the project");
  }
  const safeRelativePath = relativeToRoot.split(path.sep).join("/");
  if (!graphFilePathSet().has(safeRelativePath)) {
    return reject("File is not in the knowledge graph", 404);
  }

  // ── Canonical-path enforcement (do not remove) ──────────────────────────
  // NIST SP 800-53 Rev.5 AC-3 (Access Enforcement), SI-10 (Information Input
  // Validation). CWE-59 (Link Following) / CWE-22 (Path Traversal).
  //
  // Every check above this line is LEXICAL: path.resolve() and path.relative()
  // never touch the filesystem, whereas fs.statSync()/fs.readFileSync() DO
  // follow symbolic links. A graph node naming an in-project symlink that
  // points outside the project therefore satisfies the allow-list and is then
  // read *through* the link, returning arbitrary local files to the browser.
  //
  // The knowledge graph is untrusted input — this viewer exists precisely to
  // serve a graph committed inside the analyzed repository — so allow-list
  // membership is not by itself an access-control decision. Resolve the real
  // inode, refuse symlinks outright, and re-verify containment against
  // canonical paths. scan-project.mjs applies the same lstat rejection when
  // building the graph; this keeps the read path consistent with the scan path.
  let linkStat;
  try {
    linkStat = fs.lstatSync(absoluteFile);
  } catch {
    return reject("File not found", 404);
  }
  if (linkStat.isSymbolicLink()) return reject("Symbolic links are not served", 403);

  let realFile;
  try {
    realFile = fs.realpathSync(absoluteFile);
  } catch {
    return reject("File not found", 404);
  }
  const realRelative = path.relative(PROJECT_ROOT_REAL, realFile);
  if (
    !realRelative ||
    realRelative === ".." ||
    realRelative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(realRelative)
  ) {
    return reject("Path must stay inside the project", 403);
  }

  let stat;
  try {
    stat = fs.statSync(realFile);
  } catch {
    return reject("File not found", 404);
  }
  // Regular files only: FIFOs and device nodes can block the event loop or
  // stream unbounded data (NIST SP 800-53 SC-5, Denial-of-Service Protection).
  if (!stat.isFile()) return reject("Path is not a file");
  if (stat.size > MAX_SOURCE_FILE_BYTES) return reject("File is too large to preview", 413);

  const buffer = fs.readFileSync(realFile);
  if (buffer.includes(0)) return reject("Binary files cannot be previewed", 415);

  const content = buffer.toString("utf8");
  return {
    statusCode: 200,
    payload: {
      path: safeRelativePath,
      language: detectLanguage(relativeToRoot),
      content,
      sizeBytes: buffer.byteLength,
      lineCount: content.length === 0 ? 0 : content.split(/\r\n|\n|\r/).length,
    },
  };
}

function serveGraphJson(res, fileName) {
  const candidate = path.join(graphDir, fileName);
  if (fs.existsSync(candidate)) {
    try {
      const raw = JSON.parse(fs.readFileSync(candidate, "utf-8"));
      // Sanitise absolute node filePaths so the developer's directory
      // layout is never sent to the browser.
      if (Array.isArray(raw.nodes)) {
        raw.nodes = raw.nodes.map((node) => {
          if (typeof node.filePath !== "string") return node;
          const abs = node.filePath;
          const rel = abs.startsWith(projectRoot)
            ? abs.slice(projectRoot.length).replace(/^[\\/]/, "")
            : path.isAbsolute(abs)
              ? path.basename(abs)
              : abs;
          return { ...node, filePath: rel };
        });
      }
      sendJson(res, 200, raw);
    } catch {
      sendJson(res, 500, { error: "Failed to read graph file" });
    }
    return;
  }
  if (fileName === "knowledge-graph.json") {
    sendJson(res, 404, { error: "No knowledge graph found. Run /understand first." });
  } else {
    res.statusCode = 404;
    res.end();
  }
}

function readGraphMetadata(fileName) {
  const graph = JSON.parse(
    fs.readFileSync(path.join(graphDir, fileName), "utf-8"),
  );
  return {
    graphCommitHash:
      typeof graph.project?.gitCommitHash === "string"
        ? graph.project.gitCommitHash
        : undefined,
    lastAnalyzedAt:
      typeof graph.project?.analyzedAt === "string"
        ? graph.project.analyzedAt
        : undefined,
  };
}

async function readGraphFreshness() {
  const knowledgeGraph = path.join(graphDir, "knowledge-graph.json");
  if (!fs.existsSync(knowledgeGraph)) {
    return {
      statusCode: 404,
      payload: { error: "No knowledge graph found. Run /understand first." },
    };
  }

  const domainGraph = path.join(graphDir, "domain-graph.json");
  let inputs;
  try {
    inputs = {
      knowledge: readGraphMetadata("knowledge-graph.json"),
      ...(fs.existsSync(domainGraph)
        ? { domain: readGraphMetadata("domain-graph.json") }
        : {}),
    };
  } catch {
    return {
      statusCode: 500,
      payload: { error: "Failed to read graph file" },
    };
  }

  return {
    statusCode: 200,
    payload: {
      graphs: await getGraphFreshnessBatch(projectRoot, inputs),
    },
  };
}

const CONTENT_TYPES = {
  ".css": "text/css", ".html": "text/html", ".ico": "image/x-icon",
  ".js": "text/javascript", ".json": "application/json", ".map": "application/json",
  ".png": "image/png", ".svg": "image/svg+xml", ".txt": "text/plain",
  ".wasm": "application/wasm", ".woff": "font/woff", ".woff2": "font/woff2",
};

function serveStatic(res, pathname) {
  const relative = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const absolute = path.resolve(DIST_DIR, relative);
  if (absolute !== DIST_DIR && !absolute.startsWith(DIST_DIR + path.sep)) {
    res.statusCode = 403;
    res.end("Forbidden");
    return;
  }
  if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) {
    res.statusCode = 404;
    res.end("Not found");
    return;
  }
  res.setHeader("Content-Type", CONTENT_TYPES[path.extname(absolute).toLowerCase()] ?? "application/octet-stream");
  res.end(fs.readFileSync(absolute));
}

// ── Server ────────────────────────────────────────────────────────────────

const PROTECTED = new Set([
  "/knowledge-graph.json",
  "/domain-graph.json",
  "/diff-overlay.json",
  "/meta.json",
  "/config.json",
  "/file-content.json",
  "/staleness.json",
]);

const server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  const pathname = url.pathname;

  if (pathname === "/staleness.json") {
    res.setHeader("Cache-Control", "no-store");
  }

  // Baseline response hardening on every route.
  // NIST SP 800-53 Rev.5 SC-7 (Boundary Protection), SC-18 (Mobile Code).
  // no-referrer keeps the bootstrap `?token=` out of the Referer header on any
  // outbound request; the frame/sniff headers contain the blast radius of any
  // future rendering regression.
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");

  if (!PROTECTED.has(pathname)) {
    serveStatic(res, pathname);
    return;
  }

  if (!tokenMatches(url.searchParams.get("token"))) {
    sendJson(res, 403, { error: "Forbidden: missing or invalid token" });
    return;
  }

  if (pathname === "/file-content.json") {
    const result = readSourceFile(url);
    sendJson(res, result.statusCode, result.payload);
    return;
  }

  if (pathname === "/staleness.json") {
    void readGraphFreshness()
      .then((result) => sendJson(res, result.statusCode, result.payload))
      .catch(() => {
        sendJson(res, 500, { error: "Failed to read graph freshness" });
      });
    return;
  }

  if (pathname === "/config.json") {
    const candidate = path.join(graphDir, "config.json");
    if (fs.existsSync(candidate)) {
      try {
        sendJson(res, 200, JSON.parse(fs.readFileSync(candidate, "utf-8")));
      } catch {
        sendJson(res, 500, { error: "Failed to read config file" });
      }
      return;
    }
    sendJson(res, 200, { autoUpdate: false, outputLanguage: "en" });
    return;
  }

  serveGraphJson(res, pathname.slice(1));
});

function listen(attemptPort, attemptsLeft) {
  server.once("error", (err) => {
    if (err.code === "EADDRINUSE" && !portExplicit && attemptsLeft > 0) {
      listen(attemptPort + 1, attemptsLeft - 1);
    } else {
      console.error(`Error: could not bind 127.0.0.1:${attemptPort} — ${err.message}`);
      process.exit(1);
    }
  });
  server.listen(attemptPort, "127.0.0.1", () => {
    const address = server.address();
    const boundPort = typeof address === "object" && address ? address.port : attemptPort;
    const dashboardUrl = `http://127.0.0.1:${boundPort}/?token=${ACCESS_TOKEN}`;
    console.log(`\n  Serving graph from ${graphDir}`);
    console.log(`  🔑  Dashboard URL: ${dashboardUrl}\n`);
    if (openBrowser) {
      // NIST SP 800-53 Rev.5 SI-10 (Information Input Validation); CWE-78
      // (OS Command Injection). The previous form passed the URL to `start`
      // with { shell: true } on Windows, handing an operator-influenced value
      // (UNDERSTAND_ACCESS_TOKEN feeds the URL) to cmd.exe for parsing. Use
      // rundll32's FileProtocolHandler instead so no shell is involved on any
      // platform and the URL is delivered as a single argv entry.
      const [opener, openerArgs] =
        process.platform === "darwin"
          ? ["open", [dashboardUrl]]
          : process.platform === "win32"
            ? ["rundll32", ["url.dll,FileProtocolHandler", dashboardUrl]]
            : ["xdg-open", [dashboardUrl]];
      spawn(opener, openerArgs, { stdio: "ignore", detached: true }).unref();
    }
  });
}

listen(port, 10);
