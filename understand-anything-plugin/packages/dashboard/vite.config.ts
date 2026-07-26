/// <reference types="vitest" />
import { defineConfig, type UserConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import type { IncomingMessage, ServerResponse } from "http";
import {
  getGraphFreshnessBatch,
  type GraphFreshnessInput,
  type GraphFreshnessResult,
} from "../core/src/staleness";

// Generate a one-time token when the server process starts.
// This token is printed to the terminal and must be in the URL
// to fetch knowledge-graph.json or diff-overlay.json.
// NIST SP 800-53 Rev.5 IA-5(1) (Authenticator Management — complexity).
// The generated default carries 128 bits of entropy. An operator-supplied
// override must not silently weaken it: refuse to serve local source code
// behind a short or guessable shared secret.
const TOKEN_OVERRIDE = process.env.UNDERSTAND_ACCESS_TOKEN;
if (TOKEN_OVERRIDE !== undefined && !/^[A-Za-z0-9_-]{32,128}$/.test(TOKEN_OVERRIDE)) {
  throw new Error(
    "UNDERSTAND_ACCESS_TOKEN must be 32-128 characters drawn from [A-Za-z0-9_-]. " +
      "Unset it to use a securely generated 128-bit token.",
  );
}
const ACCESS_TOKEN = TOKEN_OVERRIDE || crypto.randomBytes(16).toString("hex");
const MAX_SOURCE_FILE_BYTES = 1024 * 1024;

/**
 * Constant-time bearer-token comparison.
 *
 * NIST SP 800-53 Rev.5 IA-5 (Authenticator Management), SC-13 (Cryptographic
 * Protection). CWE-208 (Observable Timing Discrepancy): a plain `!==` on
 * strings short-circuits at the first differing byte, leaking the token one
 * byte at a time to anyone able to time responses on the loopback interface.
 */
export function tokenMatches(supplied: string | null, expected: string): boolean {
  const a = Buffer.from(String(supplied ?? ""), "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) {
    crypto.timingSafeEqual(b, b);
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

// Legacy directory first — projects analyzed before the `.ua` rename keep
// their existing `.understand-anything/` data.
const UA_DIR_CANDIDATES = [".understand-anything", ".ua"];

function graphFileCandidates(fileName: string): string[] {
  const graphDir = process.env.GRAPH_DIR;
  const roots = [
    ...(graphDir ? [graphDir] : []),
    process.cwd(),
    path.resolve(process.cwd(), "../../.."),
  ];
  return roots.flatMap((root) =>
    UA_DIR_CANDIDATES.map((dir) => path.resolve(root, dir, fileName)),
  );
}

function findGraphFile(fileName: string): string | null {
  return graphFileCandidates(fileName).find((candidate) => fs.existsSync(candidate)) ?? null;
}

function projectRootFromGraphFile(candidate: string): string {
  return path.dirname(path.dirname(candidate));
}

function normalizeGraphPath(filePath: string, projectRoot: string): string | null {
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

function graphFilePathSet(graphFile: string, projectRoot: string): Set<string> {
  const allowed = new Set<string>();
  try {
    const raw = JSON.parse(fs.readFileSync(graphFile, "utf-8")) as {
      nodes?: Array<Record<string, unknown>>;
    };
    for (const node of raw.nodes ?? []) {
      if (typeof node.filePath !== "string") continue;
      const normalized = normalizeGraphPath(node.filePath, projectRoot);
      if (normalized) allowed.add(normalized);
    }
  } catch {
    return allowed;
  }
  return allowed;
}

function detectLanguage(filePath: string): string {
  const ext = path.extname(filePath).slice(1).toLowerCase();
  const byExt: Record<string, string> = {
    bash: "bash",
    c: "c",
    cc: "cpp",
    cpp: "cpp",
    cs: "csharp",
    css: "css",
    go: "go",
    h: "c",
    hpp: "cpp",
    html: "markup",
    java: "java",
    js: "javascript",
    jsx: "jsx",
    json: "json",
    md: "markdown",
    mjs: "javascript",
    py: "python",
    rb: "ruby",
    rs: "rust",
    sh: "bash",
    ts: "typescript",
    tsx: "tsx",
    txt: "text",
    yaml: "yaml",
    yml: "yaml",
  };
  return byExt[ext] ?? "text";
}

function sendJson(res: import("http").ServerResponse, statusCode: number, payload: unknown) {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(payload));
}

function rejectFileRequest(message: string, statusCode = 400) {
  return { statusCode, payload: { error: message } };
}

function readSourceFile(url: URL) {
  const requestedPath = url.searchParams.get("path") ?? "";
  if (!requestedPath) return rejectFileRequest("Missing path");
  if (requestedPath.includes("\0")) return rejectFileRequest("Invalid path");
  if (path.isAbsolute(requestedPath)) return rejectFileRequest("Absolute paths are not allowed");

  const normalizedPath = path.normalize(requestedPath);
  if (
    normalizedPath === "." ||
    normalizedPath.startsWith(`..${path.sep}`) ||
    normalizedPath === ".." ||
    path.isAbsolute(normalizedPath)
  ) {
    return rejectFileRequest("Path must stay inside the project");
  }

  const graphFile = findGraphFile("knowledge-graph.json");
  if (!graphFile) {
    return rejectFileRequest("No knowledge graph found. Run /understand first.", 404);
  }

  const projectRoot = projectRootFromGraphFile(graphFile);
  const absoluteFile = path.resolve(projectRoot, normalizedPath);
  const relativeToRoot = path.relative(projectRoot, absoluteFile);
  if (
    !relativeToRoot ||
    relativeToRoot.startsWith(`..${path.sep}`) ||
    relativeToRoot === ".." ||
    path.isAbsolute(relativeToRoot)
  ) {
    return rejectFileRequest("Path must stay inside the project");
  }
  const safeRelativePath = relativeToRoot.split(path.sep).join("/");
  if (!graphFilePathSet(graphFile, projectRoot).has(safeRelativePath)) {
    return rejectFileRequest("File is not in the knowledge graph", 404);
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
  // The knowledge graph is untrusted input (it can ship inside the analyzed
  // repository), so allow-list membership is not by itself an access-control
  // decision. Resolve the real inode, refuse symlinks, and re-verify
  // containment against canonical paths. Mirrors bin/viewer.mjs, and matches
  // the lstat rejection scan-project.mjs already applies when building graphs.
  let linkStat: fs.Stats;
  try {
    linkStat = fs.lstatSync(absoluteFile);
  } catch {
    return rejectFileRequest("File not found", 404);
  }
  if (linkStat.isSymbolicLink()) {
    return rejectFileRequest("Symbolic links are not served", 403);
  }

  let realRoot: string;
  let realFile: string;
  try {
    realRoot = fs.realpathSync(projectRoot);
    realFile = fs.realpathSync(absoluteFile);
  } catch {
    return rejectFileRequest("File not found", 404);
  }
  const realRelative = path.relative(realRoot, realFile);
  if (
    !realRelative ||
    realRelative === ".." ||
    realRelative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(realRelative)
  ) {
    return rejectFileRequest("Path must stay inside the project", 403);
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(realFile);
  } catch {
    return rejectFileRequest("File not found", 404);
  }

  // Regular files only: FIFOs and device nodes can block the event loop or
  // stream unbounded data (NIST SP 800-53 Rev.5 SC-5, DoS Protection).
  if (!stat.isFile()) return rejectFileRequest("Path is not a file");
  if (stat.size > MAX_SOURCE_FILE_BYTES) {
    return rejectFileRequest("File is too large to preview", 413);
  }

  const buffer = fs.readFileSync(realFile);
  if (buffer.includes(0)) return rejectFileRequest("Binary files cannot be previewed", 415);

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

export interface DashboardFreshnessReport {
  graphs: {
    knowledge: GraphFreshnessResult;
    domain?: GraphFreshnessResult;
  };
}

function readGraphMetadata(graphFile: string): GraphFreshnessInput {
  const graph = JSON.parse(fs.readFileSync(graphFile, "utf-8")) as {
    project?: {
      gitCommitHash?: unknown;
      analyzedAt?: unknown;
    };
  };
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

export async function readGraphFreshness() {
  const graphFile = findGraphFile("knowledge-graph.json");
  if (!graphFile) {
    return rejectFileRequest("No knowledge graph found. Run /understand first.", 404);
  }

  const domainGraphFile = path.join(path.dirname(graphFile), "domain-graph.json");
  let knowledgeInput: GraphFreshnessInput;
  let domainInput: GraphFreshnessInput | undefined;
  try {
    knowledgeInput = readGraphMetadata(graphFile);
    domainInput = fs.existsSync(domainGraphFile)
      ? readGraphMetadata(domainGraphFile)
      : undefined;
  } catch {
    return rejectFileRequest("Failed to read graph file", 500);
  }

  const projectRoot = projectRootFromGraphFile(graphFile);
  let graphs: DashboardFreshnessReport["graphs"];
  if (domainInput) {
    graphs = await getGraphFreshnessBatch(projectRoot, {
      knowledge: knowledgeInput,
      domain: domainInput,
    });
  } else {
    const result = await getGraphFreshnessBatch(projectRoot, {
      knowledge: knowledgeInput,
    });
    graphs = { knowledge: result.knowledge };
  }

  return {
    statusCode: 200,
    payload: { graphs } satisfies DashboardFreshnessReport,
  };
}

type DashboardDataMiddleware = (
  req: IncomingMessage,
  res: ServerResponse,
  next: () => void,
) => void;

export function createDashboardDataMiddleware(
  accessToken: string,
): DashboardDataMiddleware {
  return (req, res, next) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1:5173");
    if (url.pathname !== "/staleness.json") {
      next();
      return;
    }

    res.setHeader("Cache-Control", "no-store");

    if (!tokenMatches(url.searchParams.get("token"), accessToken)) {
      sendJson(res, 403, { error: "Forbidden: missing or invalid token" });
      return;
    }

    void readGraphFreshness()
      .then((result) => sendJson(res, result.statusCode, result.payload))
      .catch(() => {
        sendJson(res, 500, { error: "Failed to read graph freshness" });
      });
  };
}

type DashboardViteConfig = UserConfig & {
  test: {
    environment: "node";
    include: string[];
  };
};

const config: DashboardViteConfig = {
  test: {
    environment: "node",
    include: ["src/**/__tests__/**/*.test.ts"],
  },

  // FIX 1 — bind only to localhost, not 0.0.0.0
  // This blocks access from any other device on the same LAN / WiFi.
  //
  // The cors/allowedHosts/fs settings below are pinned EXPLICITLY rather than
  // inherited from Vite's defaults. This server exposes local source code, and
  // the dependency is caret-ranged (`vite: ^6.4.2`), so a future minor upgrade
  // must not be able to silently relax the posture.
  // NIST SP 800-53 Rev.5 SC-7 (Boundary Protection), CM-6 (Configuration
  // Settings), CM-7 (Least Functionality). CISA Secure by Design: secure defaults.
  server: {
    host: "127.0.0.1",
    port: 5173,
    // Reject cross-origin reads outright: no web page should be able to pull
    // graph or file content out of the dev server.
    cors: false,
    // Defeats DNS rebinding — only these Host headers are honoured.
    allowedHosts: ["127.0.0.1", "localhost"],
    fs: {
      strict: true,
      allow: [path.resolve(__dirname)],
      // Defence in depth for the /@fs/ route: never serve credential material
      // or git internals even if something above is misconfigured.
      deny: [
        "**/.env",
        "**/.env.*",
        "**/*.pem",
        "**/*.key",
        "**/id_rsa",
        "**/id_ed25519",
        "**/.npmrc",
        "**/.netrc",
        "**/.git/**",
      ],
    },
    open: `/?token=${ACCESS_TOKEN}`,
  },

  resolve: {
    alias: {
      "@understand-anything/core/schema": path.resolve(__dirname, "../core/dist/schema.js"),
      "@understand-anything/core/search": path.resolve(__dirname, "../core/dist/search.js"),
      "@understand-anything/core/types": path.resolve(__dirname, "../core/dist/types.js"),
    },
  },

  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return;
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) {
            return "react-vendor";
          }
          if (id.includes("node_modules/@xyflow/")) return "xyflow";
          // ELK is ~1.6MB raw — split into its own chunk so it doesn't
          // bloat the main bundle. graphology is similarly large.
          if (id.includes("node_modules/elkjs/")) return "elk";
          if (id.includes("node_modules/graphology")) return "graphology";
          if (
            id.includes("node_modules/@dagrejs/") ||
            id.includes("node_modules/d3-force/")
          ) {
            return "graph-layout";
          }
          if (
            id.includes("node_modules/react-markdown/") ||
            id.includes("node_modules/hast-util-to-jsx-runtime/") ||
            /[\\/]node_modules[\\/](remark|rehype|mdast|hast|unist|micromark|decode-named-character-reference|property-information|space-separated-tokens|comma-separated-tokens|html-url-attributes|devlop|bail|ccount|character-entities|is-plain-obj|trim-lines|trough|unified|vfile|zwitch)/.test(id)
          ) {
            return "markdown";
          }
        },
      },
    },
  },

  plugins: [
    react(),
    tailwindcss(),
    {
      name: "serve-knowledge-graph",
      configureServer(server) {
        // Print the access URL once so the developer can open it.
        server.httpServer?.once("listening", () => {
          const address = server.httpServer?.address();
          const port = typeof address === "object" && address ? address.port : 5173;
          console.log(
            `\n  🔑  Dashboard URL: http://127.0.0.1:${port}/?token=${ACCESS_TOKEN}\n`
          );
        });

        server.middlewares.use(createDashboardDataMiddleware(ACCESS_TOKEN));

        server.middlewares.use((req, res, next) => {
          const url = new URL(req.url ?? "/", "http://127.0.0.1:5173");
          const pathname = url.pathname;
          const isProtectedEndpoint =
            pathname === "/knowledge-graph.json" ||
            pathname === "/domain-graph.json" ||
            pathname === "/diff-overlay.json" ||
            pathname === "/meta.json" ||
            pathname === "/config.json" ||
            pathname === "/file-content.json";

          // Baseline response hardening on every route.
          // NIST SP 800-53 Rev.5 SC-7 (Boundary Protection), SC-18 (Mobile Code).
          // no-referrer keeps the bootstrap `?token=` out of the Referer header
          // on outbound requests; the frame/sniff headers bound the blast radius
          // of any future rendering regression.
          res.setHeader("Referrer-Policy", "no-referrer");
          res.setHeader("X-Content-Type-Options", "nosniff");
          res.setHeader("X-Frame-Options", "DENY");

          if (!isProtectedEndpoint) {
            next();
            return;
          }

          // FIX 3 — require the one-time token on all data endpoints.
          // Requests without a matching ?token= get a 403. Compared in constant
          // time (NIST SP 800-53 Rev.5 IA-5, SC-13; CWE-208).
          if (!tokenMatches(url.searchParams.get("token"), ACCESS_TOKEN)) {
            sendJson(res, 403, { error: "Forbidden: missing or invalid token" });
            return;
          }

          if (pathname === "/file-content.json") {
            const result = readSourceFile(url);
            sendJson(res, result.statusCode, result.payload);
            return;
          }

          if (pathname === "/config.json") {
            const configCandidates = graphFileCandidates("config.json");
            for (const candidate of configCandidates) {
              if (fs.existsSync(candidate)) {
                try {
                  const raw = JSON.parse(fs.readFileSync(candidate, "utf-8"));
                  sendJson(res, 200, raw);
                  return;
                } catch {
                  sendJson(res, 500, { error: "Failed to read config file" });
                  return;
                }
              }
            }
            sendJson(res, 200, { autoUpdate: false, outputLanguage: "en" });
            return;
          }

          const fileName =
            pathname === "/diff-overlay.json"
              ? "diff-overlay.json"
              : pathname === "/meta.json"
              ? "meta.json"
              : pathname === "/domain-graph.json"
              ? "domain-graph.json"
              : "knowledge-graph.json";

          const candidates = graphFileCandidates(fileName);

          for (const candidate of candidates) {
            if (!fs.existsSync(candidate)) continue;

            // FIX 2 — sanitise absolute file paths before sending the JSON.
            // Nodes can contain filePath values like /Users/alice/company/src/auth.ts.
            // We convert those to relative paths (src/auth.ts) so the developer's
            // home directory and company directory layout are not leaked.
            try {
              const raw = JSON.parse(fs.readFileSync(candidate, "utf-8")) as {
                nodes?: Array<Record<string, unknown>>;
                [key: string]: unknown;
              };

              // Derive the project root from the candidate path so we can
              // make file paths relative to it.
              const projectRoot = projectRootFromGraphFile(candidate);

              if (Array.isArray(raw.nodes)) {
                raw.nodes = raw.nodes.map((node) => {
                  if (typeof node.filePath !== "string") return node;
                  const abs = node.filePath;
                  // Only relativise paths that actually sit inside projectRoot.
                  // Leave external or already-relative paths untouched.
                  const rel = abs.startsWith(projectRoot)
                    ? abs.slice(projectRoot.length).replace(/^[\\/]/, "")
                    : path.isAbsolute(abs)
                    ? path.basename(abs) // absolute but outside root — use filename only
                    : abs;              // already relative — keep as-is
                  return { ...node, filePath: rel };
                });
              }

              res.setHeader("Content-Type", "application/json");
              res.end(JSON.stringify(raw));
            } catch (err) {
              // If we cannot parse or sanitise the file, refuse to serve it
              // rather than accidentally leaking raw content.
              console.error("[understand-anything] Failed to sanitise graph file:", err);
              res.statusCode = 500;
              res.setHeader("Content-Type", "application/json");
              res.end(JSON.stringify({ error: "Failed to read graph file" }));
            }
            return;
          }

          // No matching file found on disk.
          res.statusCode = 404;
          if (pathname === "/knowledge-graph.json") {
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ error: "No knowledge graph found. Run /understand first." }));
          } else {
            res.end();
          }
        });
      },
    },
  ],
};

export default defineConfig(config);
