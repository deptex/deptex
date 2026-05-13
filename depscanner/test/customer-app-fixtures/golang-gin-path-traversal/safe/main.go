package main

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"example.com/customer-app/internal/audit"
	"example.com/customer-app/internal/files"
)

func downloadHandler(c *gin.Context) {
	raw := c.Query("id")
	audit.Record(c)
	// Coerce to a numeric id — strconv.Atoi is a path_traversal sanitizer
	// in go-stdlib.yaml, so the tainted query string is cleared before it
	// reaches the files package.
	id, _ := strconv.Atoi(raw)
	body, _ := files.ReadByID(id)
	c.Data(200, "application/octet-stream", body)
}

func main() {
	r := gin.Default()
	r.GET("/download", downloadHandler)
	r.Run()
}
