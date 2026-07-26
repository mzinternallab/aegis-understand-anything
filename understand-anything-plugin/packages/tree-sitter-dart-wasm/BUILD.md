# tree-sitter-dart WASM (vendored)

This directory ships a pre-built `tree-sitter-dart.wasm` because the upstream
npm release does not.

## Why vendored

The published `tree-sitter-dart@1.0.0` (2023-02-24) tarball does include a
`tree-sitter-dart.wasm`, but it was built with a pre-`dylink.0` tree-sitter
CLI. `web-tree-sitter@0.26.x` — the loader this project uses — expects the
newer `dylink.0` custom-section name and refuses to load the older format
(failure surfaces in `getDylinkMetadata`).

Rebuilding the same upstream grammar.js with a current
`tree-sitter-cli@0.26.x` produces a `dylink.0` wasm that loads cleanly.

## How to rebuild

```bash
npm install -g tree-sitter-cli@latest
cd /tmp && npm pack tree-sitter-dart@1.0.0
tar xzf tree-sitter-dart-1.0.0.tgz
cd package
tree-sitter build --wasm
cp tree-sitter-dart.wasm \
   /path/to/understand-anything-plugin/packages/tree-sitter-dart-wasm/
```

Verify the resulting wasm:

```bash
head -c 30 tree-sitter-dart.wasm | xxd | head -1
# Expect: ...dylin / k.0...
```

## Provenance

- Grammar source: `tree-sitter-dart@1.0.0` (publisher: amaanq) — `grammar.js`
  unchanged, only the wasm artifact is regenerated.
- Built with: `tree-sitter-cli@0.26.x`, `wasi-sdk-29-arm64-macos`.
- License: MIT, inherited from tree-sitter-dart@1.0.0 (publisher: amaanq).

## When to remove this package

If amaanq publishes a refreshed `tree-sitter-dart` with a `dylink.0` wasm,
this workspace package can be deleted and the dependency in
`@understand-anything/core` flipped to the upstream package.

## Integrity

NIST SP 800-218 (SSDF) PS.2 — verify the integrity of every included artifact.
CISA/NSA *Securing the Software Supply Chain: Recommended Practices for
Developers*.

`SHA256SUMS` in this directory pins the digest of the committed `.wasm`, so a
reviewer can confirm the binary has not been substituted without rebuilding it:

```bash
shasum -a 256 -c SHA256SUMS
```

After a legitimate rebuild (see "How to rebuild" above), regenerate it:

```bash
shasum -a 256 *.wasm > SHA256SUMS
```

The grammar executes inside the WebAssembly sandbox — no filesystem or network
access — so the blast radius of a substituted binary is confined to
manipulating extracted structure. That is still worth detecting: the knowledge
graph downstream is what users read and trust.
