# gin-gonic

Gin handler that shells out via `os/exec` with user-controlled input.
Stand-alone copy of upstream taint-engine fixture
`depscanner/fixtures/test-gin-cmdi-go/` layered with dogfood categories.

- **Ecosystem:** golang
- **Framework:** gin
- **Reachable vuln dep:** `gin v1.7.7` (multiple gin CVEs in this range).
- **Unreachable vuln dep:** `gopkg.in/yaml.v2 v2.2.1` — declared but
  never imported.
- **Reachable handler:** `main.go:runCommand()` — `c.Query("name")` →
  `exec.Command("/bin/sh", "-c", ...)`.
- **Unreachable handler:** `main.go:listFiles()` — `exec.Command("ls",
  "-la")` with constant args.

See `.deptex/SOURCE.md` for provenance.
