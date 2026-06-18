package main

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.GET("/run", runCommand)
	r.GET("/files", listFiles)

	r.GET("/users", lookupUser)
	r.GET("/docs/:name", readDoc)
	r.POST("/notes", writeNote)
	r.GET("/fetch", fetchURL)
	r.GET("/proxy", proxyRequest)
	r.GET("/next", redirectNext)
	r.GET("/profile", renderProfile)
	r.GET("/filter", compileFilter)
	r.GET("/audit", auditLog)
	r.POST("/config", loadConfig)
	r.POST("/ping", pingHost)
	r.GET("/records", formatRecord)

	_ = r.Run(":4007")
}

func runCommand(c *gin.Context) {
	// REACHABLE: user input -> shell.
	name := c.Query("name")
	out, err := exec.Command("/bin/sh", "-c", "echo hello "+name).Output()
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.String(http.StatusOK, string(out))
}

func listFiles(c *gin.Context) {
	// UNREACHABLE: constant args.
	out, err := exec.Command("ls", "-la").Output()
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.String(http.StatusOK, string(out))
}
