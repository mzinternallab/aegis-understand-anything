#!/usr/bin/env node
/**
 * extract-structure.mjs
 *
 * Deterministic structural extraction script for the file-analyzer agent.
 * Uses PluginRegistry (TreeSitterPlugin + non-code parsers) from @understand-anything/core
 * to replace the LLM-generated throwaway regex scripts in Phase 1.
 *
 * Usage:
 *   node extract-structure.mjs <input.json> <output.json>
 *
 * Input JSON:
 *   { projectRoot, batchFiles: [{path, language, sizeLines, fileCategory}], batchImportData }
 *
 * Output JSON:
 *   { scriptCompleted, filesAnalyzed, filesSkipped, results: [...] }
 */

import { createRequire } from 'node:module';
import { dirname, resolve, isAbsolute, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { existsSync, lstatSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import {
  analyzeFileWithOutcomes,
  buildResult as buildExtractResult,
} from './extract-structure-result.mjs';

export {
  analyzeFileWithOutcomes,
  buildResult,
} from './extract-structure-result.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
// skills/understand/ -> plugin root is two dirs up
const pluginRoot = resolve(__dirname, '../..');
const require = createRequire(resolve(pluginRoot, 'package.json'));

// ---------------------------------------------------------------------------
// Resolve @understand-anything/core
//
// Node ESM dynamic import() requires a file:// URL on Windows; passing a raw
// absolute path like "C:\..." throws ERR_UNSUPPORTED_ESM_URL_SCHEME because the
// loader parses "C:" as a URL scheme. Wrap both resolutions in pathToFileURL().
// ---------------------------------------------------------------------------
let core;
try {
  core = await import(pathToFileURL(require.resolve('@understand-anything/core')).href);
} catch {
  // Fallback: direct path for installed plugin cache layouts
  core = await import(pathToFileURL(resolve(pluginRoot, 'packages/core/dist/index.js')).href);
}

const { TreeSitterPlugin, PluginRegistry, builtinLanguageConfigs, registerAllParsers } = core;

// ---------------------------------------------------------------------------
// Path containment
// ---------------------------------------------------------------------------

/**
 * Resolve a batch-supplied relative path against the canonical project root,
 * returning the absolute path only if it provably stays inside that root and
 * is a regular (non-symlink) file. Returns null otherwise.
 *
 * NIST SP 800-53 Rev.5 SI-10 (Information Input Validation), AC-3 (Access
 * Enforcement). CWE-22 (Path Traversal), CWE-59 (Link Following).
 *
 * The lexical checks alone are not sufficient because readFileSync follows
 * symlinks, so containment is re-verified against realpath — the same pattern
 * the dashboard's /file-content.json endpoint uses.
 *
 * @param {string} rootReal canonical (realpath'd) project root
 * @param {unknown} relPath path as supplied in the batch input JSON
 * @returns {string|null} absolute path inside the root, or null if unsafe
 */
export function resolveInsideRoot(rootReal, relPath) {
  if (typeof relPath !== 'string' || relPath.length === 0) return null;
  if (relPath.includes('\0')) return null;
  if (isAbsolute(relPath)) return null;

  const abs = resolve(rootReal, relPath);

  // Lexical containment first — cheap, and rejects the common '../' case
  // before any filesystem call.
  const lexRel = relative(rootReal, abs);
  if (!lexRel || lexRel === '..' || lexRel.startsWith(`..${sep}`) || isAbsolute(lexRel)) {
    return null;
  }

  // Reject symlinks outright, then confirm the canonical path is still inside.
  let linkStat;
  try {
    linkStat = lstatSync(abs);
  } catch {
    return null;
  }
  if (linkStat.isSymbolicLink() || !linkStat.isFile()) return null;

  let real;
  try {
    real = realpathSync(abs);
  } catch {
    return null;
  }
  const realRel = relative(rootReal, real);
  if (!realRel || realRel === '..' || realRel.startsWith(`..${sep}`) || isAbsolute(realRel)) {
    return null;
  }
  return real;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const [,, inputPath, outputPath] = process.argv;
  if (!inputPath || !outputPath) {
    process.stderr.write('Usage: node extract-structure.mjs <input.json> <output.json>\n');
    process.exit(1);
  }

  // Read input
  const inputRaw = readFileSync(inputPath, 'utf-8');
  const input = JSON.parse(inputRaw);
  const { projectRoot, batchFiles, batchImportData } = input;

  if (!projectRoot || !Array.isArray(batchFiles)) {
    throw new Error('Invalid input: must contain projectRoot and batchFiles array');
  }

  // Create tree-sitter plugin with all configs that have WASM grammars
  const tsConfigs = builtinLanguageConfigs.filter(c => c.treeSitter);
  const tsPlugin = new TreeSitterPlugin(tsConfigs);
  await tsPlugin.init();

  // Create registry and register tree-sitter + all non-code parsers
  const registry = new PluginRegistry();
  registry.register(tsPlugin);
  registerAllParsers(registry);

  const results = [];
  const filesSkipped = [];
  const analysisOutcomes = {
    structure: { succeeded: 0, failed: 0 },
    callGraph: { succeeded: 0, failed: 0, skipped: 0 },
  };

  // Canonical project root — every batch path is re-verified against this.
  // NIST SP 800-53 Rev.5 AC-3 (Access Enforcement).
  let projectRootReal;
  try {
    projectRootReal = realpathSync(projectRoot);
  } catch {
    throw new Error(`projectRoot does not exist or is not readable: ${projectRoot}`);
  }

  for (const file of batchFiles) {
    // ── Path containment (do not remove) ──────────────────────────────────
    // NIST SP 800-53 Rev.5 SI-10 (Information Input Validation), AC-3 (Access
    // Enforcement). CWE-22 (Path Traversal) / CWE-59 (Link Following).
    //
    // `file.path` arrives from ua-file-analyzer-input-<n>.json, which is
    // written by an LLM agent whose context contains untrusted repository
    // content. A bare join() would happily escape the project on '../../..',
    // and readFileSync follows symlinks. Treat every path in that file as
    // hostile: reject absolute paths, NUL bytes, and symlinks, then confirm the
    // canonical target still sits inside the project.
    const absolutePath = resolveInsideRoot(projectRootReal, file.path);
    if (absolutePath === null) {
      process.stderr.write(
        `Warning: extract-structure: ${String(file.path)} — path escapes the ` +
        `project root or is a symlink — file skipped\n`,
      );
      filesSkipped.push(file.path);
      continue;
    }

    // Read file content
    let content;
    try {
      content = readFileSync(absolutePath, 'utf-8');
    } catch {
      filesSkipped.push(file.path);
      continue;
    }

    // Line counts. POSIX text files end in a trailing newline, which makes
    // `split('\n')` produce one extra empty element. Match `wc -l` semantics
    // (used by the project scanner for `sizeLines`) so the two counts agree.
    const lines = content.split('\n');
    const totalLines = content.endsWith('\n') ? Math.max(0, lines.length - 1) : lines.length;
    const nonEmptyLines = lines.filter(l => l.trim().length > 0).length;

    const { analysis, callGraph, structureOutcome, callGraphOutcome } =
      analyzeFileWithOutcomes(registry, file, content);

    if (structureOutcome === 'skipped') {
      filesSkipped.push(file.path);
      continue;
    }

    analysisOutcomes.structure[structureOutcome] += 1;
    analysisOutcomes.callGraph[callGraphOutcome] += 1;

    // Build result object
    const result = buildExtractResult(file, totalLines, nonEmptyLines, analysis, callGraph, batchImportData);
    results.push(result);
  }

  // Write output
  const output = {
    scriptCompleted: true,
    filesAnalyzed: results.length,
    filesSkipped,
    analysisOutcomes,
    results,
  };

  writeFileSync(outputPath, JSON.stringify(output, null, 2), 'utf-8');

  if (!existsSync(outputPath)) {
    throw new Error(`output file missing after write: ${outputPath}`);
  }
}

// ---------------------------------------------------------------------------
// Run only when executed directly as a CLI; importing the module (e.g. from
// tests) must not trigger main().
//
// Canonicalize both sides through realpathSync. Node ESM resolves
// import.meta.url through symlinks but pathToFileURL(process.argv[1]) preserves
// them, so a raw equality check silently no-ops when the script is invoked via
// a symlinked plugin install path (the default in Claude Code / Copilot CLI
// caches). See GitHub issue #162.
// ---------------------------------------------------------------------------
function isCliEntry() {
  if (!process.argv[1]) return false;
  try {
    const modulePath = realpathSync(fileURLToPath(import.meta.url));
    const argvPath = realpathSync(process.argv[1]);
    return modulePath === argvPath;
  } catch {
    return false;
  }
}

if (isCliEntry()) {
  try {
    await main();
  } catch (err) {
    process.stderr.write(`extract-structure.mjs failed: ${err.message}\n${err.stack}\n`);
    process.exit(1);
  }
}
