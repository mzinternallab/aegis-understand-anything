---
name: understand-dashboard
description: Launch the interactive web dashboard to visualize a codebase's knowledge graph
argument-hint: "[project-path]"
---

# /understand-dashboard

Start the Understand Anything dashboard to visualize the knowledge graph for the current project.

## Instructions

1. Determine the project directory and data directory:
   - If `$ARGUMENTS` contains a path, use that as the project directory
   - Otherwise, use the current working directory
   - Prefer the legacy `.understand-anything/` data directory when it exists, otherwise use `.ua/`

   Use the Bash tool to resolve:
   ```bash
   PROJECT_ARG="$ARGUMENTS"
   if [ -n "$PROJECT_ARG" ]; then
     PROJECT_DIR=$(cd "$PROJECT_ARG" 2>/dev/null && pwd -P)
   else
     PROJECT_DIR=$(pwd -P)
   fi

   if [ -z "$PROJECT_DIR" ] || [ ! -d "$PROJECT_DIR" ]; then
     echo "Error: Project directory not found: ${PROJECT_ARG:-$PWD}"
     exit 1
   fi

   if [ -d "$PROJECT_DIR/.understand-anything" ]; then
     UA_DIR="$PROJECT_DIR/.understand-anything"
   else
     UA_DIR="$PROJECT_DIR/.ua"
   fi
   ```

2. Check that `$UA_DIR/knowledge-graph.json` exists in the project directory. If not, tell the user:
   ```
   No knowledge graph found. Run /understand first to analyze this project.
   ```

   Use the Bash tool to check:
   ```bash
   if [ ! -f "$UA_DIR/knowledge-graph.json" ]; then
     echo "No knowledge graph found. Run /understand first to analyze this project."
     exit 1
   fi
   ```

3. Find the dashboard code. The dashboard is at `packages/dashboard/` relative to this plugin's root directory. Check these paths in order and use the first that exists:
   - `${CLAUDE_PLUGIN_ROOT}/packages/dashboard/` (Claude Code runtime root, highest priority)
   - `~/.understand-anything-plugin/packages/dashboard/` (universal symlink, all installs)
   - Two levels up from `~/.agents/skills/understand-dashboard` real path (self-relative fallback)
   - Two levels up from `~/.copilot/skills/understand-dashboard` real path (Copilot personal skills fallback)
   - Common clone-based install roots:
     - `~/.codex/understand-anything/understand-anything-plugin/packages/dashboard/`
     - `~/.opencode/understand-anything/understand-anything-plugin/packages/dashboard/`
     - `~/.pi/understand-anything/understand-anything-plugin/packages/dashboard/`
     - `~/understand-anything/understand-anything-plugin/packages/dashboard/`

   Use the Bash tool to resolve:
   ```bash
   SKILL_REAL=$(realpath ~/.agents/skills/understand-dashboard 2>/dev/null || readlink -f ~/.agents/skills/understand-dashboard 2>/dev/null || echo "")
   SELF_RELATIVE=$([ -n "$SKILL_REAL" ] && cd "$SKILL_REAL/../.." 2>/dev/null && pwd || echo "")
   COPILOT_SKILL_REAL=$(realpath ~/.copilot/skills/understand-dashboard 2>/dev/null || readlink -f ~/.copilot/skills/understand-dashboard 2>/dev/null || echo "")
   COPILOT_SELF_RELATIVE=$([ -n "$COPILOT_SKILL_REAL" ] && cd "$COPILOT_SKILL_REAL/../.." 2>/dev/null && pwd || echo "")

   PLUGIN_ROOT=""
   for candidate in \
     "${CLAUDE_PLUGIN_ROOT}" \
     "$HOME/.understand-anything-plugin" \
     "$SELF_RELATIVE" \
     "$COPILOT_SELF_RELATIVE" \
     "$HOME/.codex/understand-anything/understand-anything-plugin" \
     "$HOME/.opencode/understand-anything/understand-anything-plugin" \
     "$HOME/.pi/understand-anything/understand-anything-plugin" \
     "$HOME/understand-anything/understand-anything-plugin"; do
     if [ -n "$candidate" ] && [ -d "$candidate/packages/dashboard" ]; then
       PLUGIN_ROOT="$candidate"; break
     fi
   done

   if [ -z "$PLUGIN_ROOT" ]; then
     echo "Error: Cannot find the understand-anything plugin root."
     echo "Checked:"
     echo "  - ${CLAUDE_PLUGIN_ROOT:-<unset CLAUDE_PLUGIN_ROOT>}"
     echo "  - $HOME/.understand-anything-plugin"
     echo "  - ${SELF_RELATIVE:-<unresolved path derived from ~/.agents/skills/understand-dashboard>}"
     echo "  - ${COPILOT_SELF_RELATIVE:-<unresolved path derived from ~/.copilot/skills/understand-dashboard>}"
     echo "  - $HOME/.codex/understand-anything/understand-anything-plugin"
     echo "  - $HOME/.opencode/understand-anything/understand-anything-plugin"
     echo "  - $HOME/.pi/understand-anything/understand-anything-plugin"
     echo "  - $HOME/understand-anything/understand-anything-plugin"
     echo "Make sure you followed the installation instructions for your platform."
     exit 1
   fi

   DASHBOARD_DIR="$PLUGIN_ROOT/packages/dashboard"
   ```

4. **Fast path — try the prebuilt viewer first (no install, no build).** Each release ships a self-contained viewer tarball; run it pinned to the installed plugin version:
   ```bash
   : "${PLUGIN_ROOT:?Run step 3 first so PLUGIN_ROOT is set}"
   : "${PROJECT_DIR:?Run step 1 first so PROJECT_DIR is set}"
   PLUGIN_VERSION=$(node -p "require('$PLUGIN_ROOT/package.json').version")
   VIEWER_URL="https://github.com/Egonex-AI/Understand-Anything/releases/download/v${PLUGIN_VERSION}/understand-anything-viewer.tgz"

   # NIST SP 800-218 PS.2 / PO.3.2 -- verify artifact integrity BEFORE execution.
   # CISA/NSA "Securing the Software Supply Chain" (Developers), artifact integrity.
   #
   # `npx --yes <url>` downloads and RUNS code with no prompt. The URL is
   # version-pinned but a GitHub release asset is mutable: anyone with repo
   # write access (or a leaked Actions token / maintainer PAT) can replace the
   # tarball at the same tag. Without a checksum every user of that version
   # silently executes the replacement. The expected digest ships inside the
   # plugin, so it is only as trustworthy as the plugin install itself -- which
   # is exactly the trust boundary we want.
   EXPECTED_SHA_FILE="$PLUGIN_ROOT/packages/viewer/viewer-asset.sha256"
   if [ ! -f "$EXPECTED_SHA_FILE" ]; then
     echo "No pinned viewer digest at $EXPECTED_SHA_FILE — skipping the fast path." >&2
     echo "Falling back to the local build (steps 5-6)." >&2
   else
     TARBALL=$(mktemp -t ua-viewer-XXXXXX.tgz) || exit 1
     if curl -fsSL "$VIEWER_URL" -o "$TARBALL"; then
       ACTUAL_SHA=$(shasum -a 256 "$TARBALL" | cut -d' ' -f1)
       EXPECTED_SHA=$(tr -d '[:space:]' < "$EXPECTED_SHA_FILE")
       if [ "$ACTUAL_SHA" = "$EXPECTED_SHA" ]; then
         npx --yes "$TARBALL" "$PROJECT_DIR"
       else
         echo "INTEGRITY CHECK FAILED for $VIEWER_URL" >&2
         echo "  expected: $EXPECTED_SHA" >&2
         echo "  actual:   $ACTUAL_SHA" >&2
         echo "Refusing to execute. Report this — a release asset may have been replaced." >&2
         rm -f "$TARBALL"
         exit 1
       fi
     else
       echo "Could not download the viewer — falling back to the local build." >&2
     fi
     rm -f "$TARBALL"
   fi
   ```

   **If the integrity check fails, do not fall back to the local build and do
   not retry — stop and report it to the user.** A digest mismatch means the
   published asset no longer matches what this plugin version expects, which is
   a supply-chain signal, not a transient error.
   Run this in the background. It prints the same `🔑  Dashboard URL` line as the dev server:
   - If the line appears, **skip steps 5-6** and continue at step 7.
   - If the process exits without printing it (no release asset for this version, or no network), fall back to steps 5-6.

5. Fallback: install dependencies and build if needed:
   ```bash
   : "${PLUGIN_ROOT:?Run step 3 first so PLUGIN_ROOT is set}"
   DASHBOARD_DIR="${DASHBOARD_DIR:-$PLUGIN_ROOT/packages/dashboard}"
   # NIST SP 800-218 PO.3.2 / PS.3.1 -- deterministic dependency resolution.
   # Fail closed: never silently re-resolve caret ranges against the registry.
   cd "$DASHBOARD_DIR" || exit 1
   if ! pnpm install --frozen-lockfile; then
     echo "Dependency install failed against the committed lockfile." >&2
     echo "Review the package.json / pnpm-lock.yaml diff before retrying." >&2
     exit 1
   fi
   ```
   Then ensure the core package is built (the dashboard depends on it):
   ```bash
   : "${PLUGIN_ROOT:?Run step 3 first so PLUGIN_ROOT is set}"
   # NIST SP 800-218 PO.3.2 -- fail closed rather than continue on a broken build.
   cd "$PLUGIN_ROOT" || exit 1
   pnpm --filter @understand-anything/core build
   ```

6. Fallback: start the Vite dev server pointing at the project's knowledge graph:
   ```bash
   : "${PROJECT_DIR:?Run step 1 first so PROJECT_DIR is set}"
   : "${DASHBOARD_DIR:?Run step 5 first so DASHBOARD_DIR is set}"
   cd "$DASHBOARD_DIR" && GRAPH_DIR="$PROJECT_DIR" npx vite --host 127.0.0.1
   ```
   Run this in the background so the user can continue working.

7. **Capture the access token URL from the server output.** The server (viewer or Vite) prints a line like:
   ```
   🔑  Dashboard URL: http://127.0.0.1:<PORT>?token=<TOKEN>
   ```
   Extract the full URL including the `?token=` parameter. The token is required to access the knowledge graph data — without it the dashboard will show an "Access Token Required" gate.

8. Report to the user, including the full tokenized URL:
   ```
   Dashboard started at http://127.0.0.1:<PORT>?token=<TOKEN>
   Viewing: $UA_DIR/knowledge-graph.json

   The dashboard is running in the background. Press Ctrl+C in the terminal to stop it.
   ```
   **Important:** Always include the `?token=` parameter in the URL you share. If you omit it, the user will be blocked by the token gate and have to manually find the token in the terminal output.

## Notes

- The fast path (step 4) downloads a version-pinned, self-contained viewer from the GitHub release — nothing is installed into the plugin directory and no build runs
- The dashboard auto-opens in the default browser (both the viewer and Vite's `--open`)
- If port 5173 is already in use, the next available port is picked (both paths)
- In the fallback, the `GRAPH_DIR` environment variable tells the dev server where to find the knowledge graph
