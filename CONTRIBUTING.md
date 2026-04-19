# Contributing to Deptex

Thank you for your interest in contributing to Deptex. This document explains how to contribute to the open-source core.

---

## Code of Conduct

Please be respectful and constructive in all interactions. We aim for a welcoming environment for everyone.

---

## What You Can Contribute To

Deptex uses an **open-core** model. You can contribute to:

- **`backend/`** — Core API, libs (`ecosystems`, `ghsa`, `semver-affected`, `vuln-counts`, etc.), extraction worker, user profile route
- **`frontend/`** — Dashboard UI
- **`backend/database/`** — Core schema migrations (projects, dependencies, vulnerabilities, etc.)

The **`ee/`** directory contains commercial code (organizations, teams, integrations, Aegis, etc.) and is not open for external contributions. If you have ideas for EE features, please open an issue to discuss.

---

## How to Contribute

1. **Fork the repo** and clone your fork
2. **Create a branch** — `git checkout -b fix/some-bug` or `feature/some-feature`
3. **Make your changes** — See [DEVELOPERS.md](./DEVELOPERS.md) for setup
4. **Run tests** — `cd backend && npm run test`
5. **Open a pull request** — Describe your changes and link any related issues

---

## Adding New Features

When adding a feature, decide whether it belongs in the **core (CE)** or **commercial (EE)** layer:

- **CE**: Dependency/vuln logic, SBOM, ecosystems, analysis — goes in `backend/src/lib/` or `backend/extraction-worker/`
- **EE**: Orgs, teams, integrations, Aegis, queues — goes in `ee/` (internal only)

See the project skill `.cursor/skills/add-new-features/SKILL.md` for details.

---

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Add tests for new behavior
- Update docs if you change public APIs or behavior
- Ensure CI passes (if configured)

---

## Reporting Issues

- **Bugs**: Use [GitHub Issues](https://github.com/deptex/deptex/issues) with steps to reproduce
- **Feature requests**: Open an issue and describe the use case
- **Security**: Do not open public issues for vulnerabilities; contact us directly

---

## Questions?

- Open a [GitHub Discussion](https://github.com/deptex/deptex/discussions) for questions
- Check [DEVELOPERS.md](./DEVELOPERS.md) for setup and architecture
