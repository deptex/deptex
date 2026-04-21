# test-empty — negative fixture

This fixture intentionally has no package manifest (no package.json, requirements.txt, pom.xml, go.mod, etc.). The CLI should refuse to scan it with a clear "no recognized manifest" error.

Kept as a directory of its own so that the snapshot test can assert the "no manifest" error path is stable.
