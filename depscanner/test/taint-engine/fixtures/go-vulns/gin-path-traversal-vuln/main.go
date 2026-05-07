package main

import (
	"github.com/gin-gonic/gin"
	"example.com/gin-path-vuln/internal/files"
)

func handler(c *gin.Context) {
	name := c.Query("name")
	files.Read(name)
}

func main() {
	r := gin.Default()
	r.GET("/download", handler)
	r.Run()
}
