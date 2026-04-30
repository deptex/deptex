package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"
)

var db *sql.DB

func handler(c *gin.Context) {
	id := c.Query("id")
	// Parameterized query: user input lives in args slot, not interpolated.
	db.Query("SELECT * FROM users WHERE id = $1", id)
}

func main() {
	r := gin.Default()
	r.GET("/u", handler)
	r.Run()
}
