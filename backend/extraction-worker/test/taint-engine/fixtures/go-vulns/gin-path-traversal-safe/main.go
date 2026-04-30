package main

import (
	"path/filepath"

	"github.com/gin-gonic/gin"
	"example.com/gin-path-safe/internal/files"
)

func handler(c *gin.Context) {
	raw := c.Query("name")
	// filepath.Base strips directory components, defeating ../ traversal.
	safe := filepath.Base(raw)
	files.Read(safe)
}

func main() {
	r := gin.Default()
	r.GET("/download", handler)
	r.Run()
}
