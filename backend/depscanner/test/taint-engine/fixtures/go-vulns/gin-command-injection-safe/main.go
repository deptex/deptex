package main

import (
	"os/exec"
	"strconv"

	"github.com/gin-gonic/gin"
)

func handler(c *gin.Context) {
	raw := c.Query("count")
	// Numeric coercion sanitizes the user input — ParseInt is registered
	// as a sanitizer for command_injection in go-stdlib.yaml.
	n, _ := strconv.ParseInt(raw, 10, 64)
	count := strconv.FormatInt(n, 10)
	exec.Command("ping", "-c", count, "1.1.1.1").Run()
}

func main() {
	r := gin.Default()
	r.GET("/p", handler)
	r.Run()
}
