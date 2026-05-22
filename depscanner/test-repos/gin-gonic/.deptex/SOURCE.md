# SOURCE

Standalone copy of upstream taint-engine fixture:

- **Upstream path:** `depscanner/fixtures/test-gin-cmdi-go/`
- **Upstream tree SHA at copy time:** `3bbd1967a08dcb418a916857a80cbcb8ae3f3fac`
- **Files copied:** `go.mod` + `main.go` (modified: module path
  rewritten to `deptex/dogfood/gin-gonic`, listening port 8080→4007 to
  fit the dogfood port scheme, gopkg.in/yaml.v2 unreachable dep
  appended).

Added for the dogfood: Dockerfile + k8s.yaml + .env.example,
`.deptex/{expected.yaml,deploy.sh,SOURCE.md}`, README rewritten. No
malicious-pkg seed for golang — iterated in M4 walkthrough.

Upstream fixture stays byte-stable per Patch B.
