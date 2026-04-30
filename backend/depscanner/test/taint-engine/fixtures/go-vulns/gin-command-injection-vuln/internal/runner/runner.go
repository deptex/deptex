package runner

import "os/exec"

// Ping passes the user-provided target straight into a shell command —
// canonical CMD-injection: `target` = "google.com; rm -rf /".
func Ping(target string) {
	exec.Command("sh", "-c", "ping "+target).Run()
}
