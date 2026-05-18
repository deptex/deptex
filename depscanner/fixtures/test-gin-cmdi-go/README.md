# test-gin-cmdi-go

Gin handler that shells out via `os/exec` with user-controlled input.

- **Ecosystem:** golang
- **Framework:** gin
- **Vulnerable shape:** classic OS command injection; not a single CVE
  but a high-confidence Semgrep pattern (`go.lang.security.audit.dangerous-exec-command`).
- **Reachable handler:** `main.go:runCommand()` — `c.Query("name")`
  passed straight to `exec.Command("/bin/sh", "-c", ...)`.
- **Unreachable handler:** `main.go:listFiles()` — `exec.Command("ls",
  "-la")` with constant args.

Expected snapshot: gin entry point, semgrep finding on `runCommand`, no
finding on `listFiles`.
