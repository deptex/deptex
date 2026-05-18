# Express Taint Engine — Fixture Suite

Each subdirectory is a self-contained mini Express-style project demonstrating
a taint pattern. Naming convention: `<vuln_class>-<vuln|safe>`.

The validation harness (`npm run taint-engine:validate -- express`) walks
this directory, runs the propagator with `framework-models/express.yaml`, and
asserts:

- `*-vuln` fixtures must produce ≥1 flow of the corresponding `vuln_class`
- `*-safe` fixtures must produce 0 flows of that `vuln_class`

The fixtures are intentionally minimal — one Express handler per project,
written as untyped `req: any` so we don't need real `@types/express` plumbing
during taint-engine development.
