package main

import (
	"github.com/gin-gonic/gin"
	"example.com/gin-cmd-vuln/internal/runner"
)

func handler(c *gin.Context) {
	target := c.Query("target")
	runner.Ping(target)
}

func main() {
	r := gin.Default()
	r.GET("/ping", handler)
	r.Run()
}
