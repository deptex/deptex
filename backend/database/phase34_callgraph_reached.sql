-- Reachability v3 / T3.0 — persist callgraph-reach signal on project_dependencies.
--
-- The taint-engine callgraph already walks app source for sources/sinks. v3
-- extends it to extract `usedDependencies: Set<string>` from resolved
-- CallExpressions that cross into dep code (node_modules / site-packages /
-- pkg/mod / etc.). The reachability classifier reads this set in-memory to
-- demote called-but-not-imported transitives from `unreachable` to `module`
-- (the jackson-vs-idna precision fix — `jackson-core` is on the request path
-- via Spring even though the app never `import`s it).
--
-- The signal flows live through `TaintEngineOutput.usedDependencies`. This
-- column is provenance only — populated each run, NULL when the callgraph
-- didn't run for the ecosystem (Ruby/PHP/C# in v3) or the engine was
-- rollout-gated off. Future UI/EPD signals will read the column for a
-- "callgraph-confirmed reach" badge without re-plumbing the pipeline.
--
-- Tri-state semantics:
--   NULL  — callgraph didn't run / ecosystem unsupported / engine rollout-gated off
--   true  — callgraph confirmed this dep is reached by a CallEdge
--   false — callgraph ran AND ecosystem supported AND dep not in usedDependencies
--
-- No index — pipeline writes are scoped by project_id (already indexed) and
-- no read path queries by callgraph_reached today. Add a partial index when a
-- real consumer lands.

ALTER TABLE project_dependencies
  ADD COLUMN IF NOT EXISTS callgraph_reached BOOLEAN NULL;

COMMENT ON COLUMN project_dependencies.callgraph_reached IS
  'v3: taint-engine callgraph confirmed (true) / unconfirmed (false) / not measured (null). Provenance for jackson-vs-idna precision demotions.';
