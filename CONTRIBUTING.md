# Contributing to Deptex

Thank you for your interest in contributing to Deptex. This document explains how to contribute.

---

## Code of Conduct

Please be respectful and constructive in all interactions. We aim for a welcoming environment for everyone.

---

## What You Can Contribute To

- **`backend/`** — Express API, routes under `backend/src/routes/`, libs under `backend/src/lib/`, workers, extraction pipeline
- **`frontend/`** — React dashboard
- **`backend/database/`** — SQL migrations

See [DEVELOPERS.md](./DEVELOPERS.md) for setup and where to add new routes or libs.

---

## How to Contribute

1. **Fork the repo** and clone your fork
2. **Create a branch** — use a `type/short-summary` naming, e.g. `fix/login-redirect`, `feat/policy-editor-autosave`, `chore/dep-bumps`
3. **Make your changes** — See [DEVELOPERS.md](./DEVELOPERS.md) for setup
4. **Run tests** — `cd backend && npm run test` and `cd frontend && npm run test:run` as needed
5. **Open a pull request** — Describe your changes and link any related issues

---

## Commit Message Format

Deptex uses [Conventional Commits](https://www.conventionalcommits.org/). Every commit subject must start with a lowercase type prefix followed by `: `.

**Accepted types:**
- `feat:` — new user-facing feature
- `fix:` — bug fix
- `chore:` — maintenance, tooling, dep bumps, cleanup with no user-facing behavior change
- `refactor:` — code restructuring that doesn't change behavior
- `docs:` — documentation only
- `test:` — tests only
- `perf:` — performance improvement
- `ci:` / `build:` — CI or build-system changes
- `style:` — formatting only

Keep the subject ≤ 72 characters; put details in the body. Example:

```
feat: add SLA breach filter to vulnerability list

Exposes ?sla=breached on /api/organizations/:id/vulnerabilities and adds
a filter chip in the SecurityFilterBar. Closes #412.
```

---

## Adding New Features

- **API routes:** `backend/src/routes/` — register in `backend/src/index.ts`
- **Shared logic:** `backend/src/lib/`
- **Workers / extraction:** `backend/extraction-worker/`, `backend/watchtower-worker/`, `backend/aider-worker/`

See `.cursor/skills/add-new-features/SKILL.md` for placement and patterns.

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
