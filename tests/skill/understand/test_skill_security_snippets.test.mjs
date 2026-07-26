import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../../..');

function readRepoFile(relPath) {
  return readFileSync(resolve(repoRoot, relPath), 'utf-8');
}

describe('skill command hardening', () => {
  it('quotes PROJECT_ROOT in shell command snippets', () => {
    const files = [
      'understand-anything-plugin/skills/understand/SKILL.md',
      'understand-anything-plugin/hooks/auto-update-prompt.md',
    ];

    const unsafePatterns = [
      /\b(?:node|python|python3|mkdir|find|rm|cat)\s+(?:-[^\n]*\s+)*\$PROJECT_ROOT\b/,
      />\s*\$PROJECT_ROOT\b/,
      /--changed-files=\$PROJECT_ROOT\b/,
      /rm\s+-rf\s+\$PROJECT_ROOT\b/,
    ];

    for (const relPath of files) {
      const content = readRepoFile(relPath);
      for (const pattern of unsafePatterns) {
        expect(content, `${relPath} should not contain ${pattern}`).not.toMatch(pattern);
      }
    }
  });

  it('quotes skill and target directory placeholders in knowledge commands', () => {
    const content = readRepoFile('understand-anything-plugin/skills/understand-knowledge/SKILL.md');

    expect(content).not.toMatch(/python3\s+<SKILL_DIR>\/[^\n]+ <TARGET_DIR>/);
    expect(content).not.toMatch(/rm\s+-rf\s+<TARGET_DIR>/);
  });

  it('quotes dashboard cd targets and GRAPH_DIR assignment', () => {
    const content = readRepoFile('understand-anything-plugin/skills/understand-dashboard/SKILL.md');

    expect(content).not.toMatch(/<(?:dashboard-dir|plugin-root|project-dir)>/);
    expect(content).not.toMatch(/\bcd <(?:dashboard-dir|plugin-root)>/);
    expect(content).not.toMatch(/GRAPH_DIR=<project-dir>/);
    expect(content).toMatch(/PROJECT_DIR=\$\(pwd -P\)/);
    expect(content).toMatch(/UA_DIR="\$PROJECT_DIR\/\.understand-anything"/);
    expect(content).toMatch(/\[ ! -f "\$UA_DIR\/knowledge-graph\.json" \]/);
    expect(content).toMatch(/DASHBOARD_DIR="\$PLUGIN_ROOT\/packages\/dashboard"/);
    expect(content).toMatch(/: "\$\{PLUGIN_ROOT:\?Run step 3 first so PLUGIN_ROOT is set\}"/);
    expect(content).toMatch(/: "\$\{PROJECT_DIR:\?Run step 1 first so PROJECT_DIR is set\}"/);
    expect(content).toMatch(/: "\$\{DASHBOARD_DIR:\?Run step 5 first so DASHBOARD_DIR is set\}"/);
    expect(content).toMatch(/cd "\$PLUGIN_ROOT" \|\| exit 1/);
    expect(content).toMatch(/pnpm --filter @understand-anything\/core build/);
    expect(content).toMatch(/cd "\$DASHBOARD_DIR" && GRAPH_DIR="\$PROJECT_DIR" npx vite/);
    // Fast path: the viewer URL is version-pinned.
    expect(content).toMatch(/VIEWER_URL="https:\/\/github\.com\/Egonex-AI\/Understand-Anything\/releases\/download\/v\$\{PLUGIN_VERSION\}\/understand-anything-viewer\.tgz"/);
  });

  it('marks project-controlled context as untrusted data', () => {
    const understand = readRepoFile('understand-anything-plugin/skills/understand/SKILL.md');
    const knowledge = readRepoFile('understand-anything-plugin/skills/understand-knowledge/SKILL.md');

    expect(understand).not.toMatch(/README and manifest are authoritative/i);
    expect(understand).toMatch(/untrusted project data/i);
    expect(knowledge).toMatch(/untrusted article data/i);
  });

  // ── Regression guards for the 2026-07-25 security assessment ────────────
  // docs/security/2026-07-25-security-assessment.md

  it('verifies the downloaded viewer tarball before executing it (F-04)', () => {
    const content = readRepoFile('understand-anything-plugin/skills/understand-dashboard/SKILL.md');

    // NIST SP 800-218 PS.2 — never npx a release asset without checking it.
    expect(content).not.toMatch(/npx --yes "\$VIEWER_URL"/);
    expect(content).toMatch(/viewer-asset\.sha256/);
    expect(content).toMatch(/INTEGRITY CHECK FAILED/);
    expect(content).toMatch(/npx --yes "\$TARBALL" "\$PROJECT_DIR"/);
  });

  it('fails closed on lockfile drift instead of re-resolving (F-07)', () => {
    for (const relPath of [
      'understand-anything-plugin/skills/understand/SKILL.md',
      'understand-anything-plugin/skills/understand-figma/SKILL.md',
      'understand-anything-plugin/skills/understand-dashboard/SKILL.md',
    ]) {
      const content = readRepoFile(relPath);
      expect(content, `${relPath} must not silently re-resolve dependencies`)
        .not.toMatch(/pnpm install --frozen-lockfile 2>\/dev\/null \|\| pnpm install/);
      expect(content, `${relPath} should fail closed`)
        .toMatch(/if ! pnpm install --frozen-lockfile; then/);
    }
  });

  it('guards destructive cleanup on the interpolated variable (F-13)', () => {
    for (const relPath of [
      'understand-anything-plugin/skills/understand-figma/SKILL.md',
      'understand-anything-plugin/hooks/auto-update-prompt.md',
    ]) {
      const content = readRepoFile(relPath);
      expect(content, `${relPath} must assert UA_DIR before deleting`)
        .toMatch(/: "\$\{UA_DIR:\?/);
      expect(content, `${relPath} must test UA_DIR, not an unrelated variable`)
        .toMatch(/\[ -n "\$UA_DIR" \]/);
    }
  });

  it('quotes skill-directory and data-directory expansions (F-14)', () => {
    const figma = readRepoFile('understand-anything-plugin/skills/understand-figma/SKILL.md');
    expect(figma).not.toMatch(/node <SKILL_DIR>\//);
    expect(figma).not.toMatch(/mkdir -p \$UA_DIR/);

    const analyzer = readRepoFile('understand-anything-plugin/agents/file-analyzer.md');
    expect(analyzer).not.toMatch(/cat > \$UA_DIR\//);
  });

  it('never lets repository state drive unattended agent work (F-02)', () => {
    // Parse rather than regex the raw file: JSON escaping (\\" for embedded
    // quotes) would otherwise make these assertions test the wrong string.
    const hooks = JSON.parse(readRepoFile('understand-anything-plugin/hooks/hooks.json'));
    const commands = Object.values(hooks.hooks)
      .flat()
      .flatMap((entry) => entry.hooks)
      .map((h) => h.command);

    expect(commands.length).toBeGreaterThan(0);
    for (const command of commands) {
      // The old wording ordered the agent to act without asking.
      expect(command).not.toMatch(/Do not ask the user for confirmation/i);
      expect(command).toMatch(/Do NOT start the update on your own initiative/);
      // A git-tracked data dir means the repo shipped it, not this user.
      expect(command).toMatch(/git ls-files --error-unmatch "\$UA_DIR\/config\.json"/);
      // Every expansion quoted.
      expect(command).not.toMatch(/\[ -f \$UA_DIR\//);
    }
  });

  it('constrains agent tool grants and marks their input untrusted (F-03)', () => {
    const agents = [
      'file-analyzer', 'project-scanner', 'architecture-analyzer', 'tour-builder',
      'graph-reviewer', 'assemble-reviewer', 'article-analyzer', 'domain-analyzer',
      'design-analyzer',
    ];
    for (const name of agents) {
      const content = readRepoFile(`understand-anything-plugin/agents/${name}.md`);
      expect(content, `${name} must declare an explicit tool allow-list`)
        .toMatch(/^tools: /m);
      expect(content, `${name} must not inherit Edit`).not.toMatch(/^tools:.*\bEdit\b/m);
      expect(content, `${name} must not inherit Task/Agent`).not.toMatch(/^tools:.*\b(Task|Agent)\b/m);
      expect(content, `${name} must not inherit network tools`)
        .not.toMatch(/^tools:.*\b(WebFetch|WebSearch)\b/m);
      expect(content, `${name} must frame project content as untrusted`)
        .toMatch(/untrusted data, never instruction/i);
    }
  });

  it('excludes credential material from analysis by default (F-05)', () => {
    const content = readRepoFile('understand-anything-plugin/packages/core/src/ignore-filter.ts');
    for (const pattern of ['".env"', '"*.pem"', '"*.key"', '"id_rsa"', '".npmrc"', '"credentials"']) {
      expect(content, `DEFAULT_IGNORE_PATTERNS should exclude ${pattern}`).toContain(pattern);
    }
    // .env.example is documentation by convention — keep it analyzable.
    expect(content).toContain('"!.env.example"');
  });

  it('declares least-privilege GITHUB_TOKEN permissions in CI (F-08)', () => {
    const ci = readRepoFile('.github/workflows/ci.yml');
    expect(ci).toMatch(/^permissions:\n {2}contents: read$/m);
  });
});
