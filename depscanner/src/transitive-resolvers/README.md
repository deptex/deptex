# Transitive Resolvers

Per-ecosystem resolvers that recover the transitive dependency set when
cdxgen emits a direct-deps-only SBOM. The default cdxgen behavior on
`gomod` and `pypi` is to walk the manifest only — no transitives — which
collapses the reachability classifier's `unreachable` verdict to 0%
because there are no orphan transitive deps to flag.

These resolvers run *after* `parseSbom` in the extraction pipeline and
fold their output back into the in-memory `ParsedSbomDep[]` /
`ParsedSbomRelationship[]` arrays the rest of the pipeline already
consumes. The trigger lives in `src/sbom.ts`.

## Authoring convention

One file per ecosystem. Exported function shape:

```ts
export async function resolveXxxTransitives(
  repoRoot: string,
): Promise<TransitiveResolverResult | null>;
```

Returns:
- `null` — **soft-fail**. Manifest file missing, ecosystem not detected,
  or the resolver isn't appropriate for this repo. The pipeline logs a
  warning and continues with the cdxgen-only SBOM. Surface to operator
  via a structured `transitive_resolver_skipped: { ecosystem, reason }`
  log entry.
- A populated `TransitiveResolverResult` — **success**. The wire-in
  appends every dep not already in the cdxgen output (cdxgen wins on
  version pin per the dedup policy).
- Throws — **hard-fail**. Manifest exists but the resolver tool errored
  out (e.g. `go list` failed because the project doesn't compile). The
  pipeline logs a structured `transitive_resolver_failed: { ecosystem,
  reason, detail }` event and continues with the cdxgen-only SBOM —
  reachability degrades gracefully to the v2 0%-measurable state for
  that scan.

Hard vs soft fail discriminator:
- Soft (return null): no manifest present.
- Hard (throw): manifest present but tool errored.

## Ecosystems shipped

- `go.ts` — `go list -m -json all` parses every module in the build
  graph. Excludes the main module (the project itself).
- `pypi.ts` — `pip install --dry-run --report=-` invokes pip's resolver
  on requirements.txt / pyproject.toml without installing. Falls back
  to `pipdeptree --json` in a throwaway venv for poetry-locked or
  resolver-incompatible projects.

Per-ecosystem v3.1+ candidates (deferred): rubygems, composer, nuget.
The wire-in in `sbom.ts` only triggers for `{gomod, pypi}`; adding a
new ecosystem is one branch + one resolver file.
