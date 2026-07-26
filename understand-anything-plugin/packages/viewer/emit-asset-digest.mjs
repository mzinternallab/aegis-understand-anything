#!/usr/bin/env node
/**
 * emit-asset-digest.mjs
 *
 * Computes the SHA-256 of the packed viewer tarball and writes it to
 * `viewer-asset.sha256` next to this file.
 *
 * Why this exists
 * ---------------
 * NIST SP 800-218 (SSDF) PS.2 — "Provide a mechanism for verifying software
 * release integrity" — and PO.3.2. CISA/NSA *Securing the Software Supply
 * Chain: Recommended Practices for Developers*, artifact-integrity section.
 *
 * `/understand-dashboard` step 4 downloads
 * `understand-anything-viewer.tgz` from the GitHub release and executes it via
 * `npx`. GitHub release assets are MUTABLE: anyone with repository write access
 * — or anyone holding a leaked Actions token or maintainer PAT — can delete and
 * re-upload a different tarball at the same tag. Without a pinned digest, every
 * user on that version silently runs the replacement.
 *
 * The digest is committed inside the plugin, so it is exactly as trustworthy as
 * the plugin install itself. That is the intended trust boundary: compromising
 * the release asset alone is no longer sufficient.
 *
 * Release procedure
 * -----------------
 *   1. pnpm --filter understand-anything-viewer pack:release
 *   2. Commit the regenerated viewer-asset.sha256 together with the version bump.
 *   3. Upload the tarball to the GitHub release as
 *      `understand-anything-viewer.tgz` (exactly that name).
 *
 * Steps 2 and 3 must describe the SAME file. If they drift, the skill's
 * integrity check fails closed and the dashboard falls back to a local build.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

// `npm pack` writes understand-anything-viewer-<version>.tgz into cwd.
const tarballs = readdirSync(here).filter(
  (f) => f.startsWith("understand-anything-viewer-") && f.endsWith(".tgz"),
);

if (tarballs.length === 0) {
  console.error(
    "emit-asset-digest: no packed tarball found in " + here + "\n" +
    "Run `npm pack` first (pack:release does this for you).",
  );
  process.exit(1);
}

// Newest by version-ish name ordering; a clean release dir holds exactly one.
tarballs.sort();
const tarball = tarballs[tarballs.length - 1];

if (tarballs.length > 1) {
  console.error(
    `emit-asset-digest: ${tarballs.length} tarballs present, using ${tarball}.\n` +
    "Remove stale tarballs so the digest cannot be pinned to the wrong build.",
  );
}

const digest = createHash("sha256").update(readFileSync(join(here, tarball))).digest("hex");
const outPath = join(here, "viewer-asset.sha256");
writeFileSync(outPath, digest + "\n", "utf-8");

console.log(`emit-asset-digest: ${tarball}`);
console.log(`  sha256: ${digest}`);
console.log(`  written: ${outPath}`);
console.log("\nCommit viewer-asset.sha256 and upload this exact tarball to the release.");
