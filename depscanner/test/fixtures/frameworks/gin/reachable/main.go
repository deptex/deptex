package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// CVE-2023-26125 — gin <= 1.9.0 untrusted-input handling combined with
// a user-controlled file read path produces classic path traversal.
func main() {
	r := gin.Default()
	r.GET("/file", func(c *gin.Context) {
		p := c.Query("p")
		// Sink: open file at attacker-controlled path.
		data, err := os.ReadFile(p)
		if err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		c.Data(http.StatusOK, "application/octet-stream", data)
	})
	_ = r.Run(":8080")
}
