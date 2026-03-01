---
name: Phase 1 - Multi-Provider Testing
overview: Set up test repos on GitLab/Bitbucket, test extraction across all providers and ecosystems.
todos:
  - id: phase-1-testing
    content: "Phase 1: Multi-Provider Testing - Set up test repos on GitLab/Bitbucket, test extraction across all providers and ecosystems"
    status: pending
isProject: false
---

## Phase 1: Multi-Provider Testing and Stabilization

**Goal:** Validate that the extraction pipeline works across GitHub, GitLab, Bitbucket, and multiple ecosystems/frameworks.

### Test Repository Matrix

Copy these open-source repos to your GitLab and Bitbucket accounts. Keep the GitHub originals for GitHub testing.

**GitHub repos (use originals):**

- `expressjs/express` (npm, ~50 deps, known CVEs)
- `tiangolo/fastapi` (Python/pip, pyproject.toml)
- `gin-gonic/gin` (Go, go.mod)
- `spring-projects/spring-petclinic` (Java/Maven, pom.xml)
- `actix/actix-web` (Rust, Cargo.toml)
- `sinatra/sinatra` (Ruby, Gemfile)

**Fork/copy to GitLab:**

- `expressjs/express` (tests npm on GitLab)
- `tiangolo/fastapi` (tests Python on GitLab)
- `gin-gonic/gin` (tests Go on GitLab)

**Fork/copy to Bitbucket:**

- `expressjs/express` (tests npm on Bitbucket)
- `spring-projects/spring-petclinic` (tests Java on Bitbucket)

### Testing Checklist

For each repo/provider combination:

1. Create a project in Deptex and connect the repo
2. Verify extraction completes (status reaches `ready`)
3. Check dependencies were extracted (count > 0)
4. Check vulnerabilities were found (dep-scan output)
5. Check SBOM was uploaded to storage
6. Check dependency graph edges exist
7. Verify licenses were extracted
8. Export SBOM and Legal Notice - verify correctness

### Known Issues to Watch For

- GitLab/Bitbucket cloning: token format differences in [clone.ts](backend/extraction-worker/src/clone.ts)
- cdxgen ecosystem detection: may fail on some manifest file layouts
- dep-scan `-t` flag: needs correct ecosystem mapping per provider
- SBOM parsing: `devDependencies` detection is incomplete in [sbom.ts](backend/extraction-worker/src/sbom.ts) (line 155 always uses `'dependencies'` for direct deps)

---
