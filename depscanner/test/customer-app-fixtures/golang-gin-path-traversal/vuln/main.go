package main

import (
	"github.com/gin-gonic/gin"

	"example.com/customer-app/internal/audit"
	"example.com/customer-app/internal/files"
)

func downloadHandler(c *gin.Context) {
	name := c.Query("name")
	audit.Record(c)
	body, _ := files.Read(name)
	c.Data(200, "application/octet-stream", body)
}

func main() {
	r := gin.Default()
	r.GET("/download", downloadHandler)
	r.Run()
}
