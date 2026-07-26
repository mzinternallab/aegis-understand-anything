import ignore, { type Ignore } from "ignore";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { resolveUaDir } from "./persistence/index.js";

/**
 * Hardcoded default ignore patterns matching the project-scanner agent's
 * exclusion rules, plus bin/obj for .NET projects.
 */
export const DEFAULT_IGNORE_PATTERNS: string[] = [
  // Dependency directories
  "node_modules/",
  ".git/",
  "vendor/",
  "venv/",
  ".venv/",
  "__pycache__/",

  // Build output
  "dist/",
  "build/",
  "out/",
  "coverage/",
  ".next/",
  ".cache/",
  ".turbo/",
  "target/",
  "obj/",

  // Lock files
  "*.lock",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",

  // Binary/asset files
  "*.png",
  "*.jpg",
  "*.jpeg",
  "*.gif",
  "*.svg",
  "*.ico",
  "*.woff",
  "*.woff2",
  "*.ttf",
  "*.eot",
  "*.mp3",
  "*.mp4",
  "*.pdf",
  "*.zip",
  "*.tar",
  "*.gz",

  // Generated files
  "*.min.js",
  "*.min.css",
  "*.map",
  "*.generated.*",

  // IDE/editor
  ".idea/",
  ".vscode/",

  // Misc
  "LICENSE",
  ".gitignore",
  ".editorconfig",
  ".prettierrc",
  ".eslintrc*",
  "*.log",

  // ── Credential material ────────────────────────────────────────────────
  // NIST SP 800-53 Rev.5 SC-28 (Protection of Information at Rest), SI-12
  // (Information Handling and Retention), AC-4 (Information Flow Enforcement).
  //
  // Analyzed file contents are read into LLM prompts and their summaries are
  // persisted into knowledge-graph.json, which is then served over HTTP and is
  // frequently committed. Secrets must never enter that pipeline: once content
  // leaves the host there is no way to recall it, so exclusion is the only
  // reliable control.
  //
  // This matters even though scan-project.mjs prefers `git ls-files
  // --exclude-standard` (which honours .gitignore): the recursive walker used
  // when git is unavailable has no .gitignore awareness, and secrets committed
  // by mistake are common enough that GitHub runs a scanning service for them.
  //
  // .env.example is negated back in — it is documentation by convention and
  // carries placeholder values, which is useful context for analysis.
  ".env",
  ".env.*",
  "!.env.example",
  "!.env.sample",
  "!.env.template",
  "*.pem",
  "*.key",
  "*.p12",
  "*.pfx",
  "*.jks",
  "*.keystore",
  "*.asc",
  "*.gpg",
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  "*.ppk",
  ".npmrc",
  ".netrc",
  ".pypirc",
  ".htpasswd",
  "credentials",
  "credentials.json",
  "service-account*.json",
  "*.secret",
  "*.secrets",
  "secrets/",
  ".secrets/",
  ".aws/",
  ".ssh/",
];

export interface IgnoreFilter {
  /** Returns true if the given relative path should be excluded from analysis. */
  isIgnored(relativePath: string): boolean;
}

/**
 * Creates an IgnoreFilter that merges hardcoded defaults with user-defined
 * patterns from .understandignore files and CLI-provided exclude patterns.
 *
 * Pattern load order (later entries can override earlier ones via ! negation):
 * 1. Hardcoded defaults
 * 2. <ua-dir>/.understandignore (if exists — `.ua/`, or the legacy
 *    `.understand-anything/` when that directory already exists)
 * 3. .understandignore at project root (if exists)
 * 4. CLI --exclude patterns (highest priority)
 */
export function createIgnoreFilter(projectRoot: string, extraPatterns: string[] = []): IgnoreFilter {
  const ig: Ignore = ignore();

  // Layer 1: hardcoded defaults
  ig.add(DEFAULT_IGNORE_PATTERNS);

  // Layer 2: <ua-dir>/.understandignore
  const projectIgnorePath = join(resolveUaDir(projectRoot), ".understandignore");
  if (existsSync(projectIgnorePath)) {
    const content = readFileSync(projectIgnorePath, "utf-8");
    ig.add(content);
  }

  // Layer 3: .understandignore at project root
  const rootIgnorePath = join(projectRoot, ".understandignore");
  if (existsSync(rootIgnorePath)) {
    const content = readFileSync(rootIgnorePath, "utf-8");
    ig.add(content);
  }

  // Layer 4: CLI --exclude patterns (highest priority)
  if (extraPatterns.length > 0) {
    ig.add(extraPatterns);
  }

  return {
    isIgnored(relativePath: string): boolean {
      return ig.ignores(relativePath);
    },
  };
}
