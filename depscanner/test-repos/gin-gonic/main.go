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
