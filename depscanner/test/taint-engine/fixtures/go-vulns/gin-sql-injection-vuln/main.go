package main

import (
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"
	"example.com/gin-sql-vuln/internal/repo"
)

var db *sql.DB

func handler(c *gin.Context) {
	id := c.Query("id")
	repo.LookupUser(db, id)
}

func directHandler(c *gin.Context) {
	name := c.Query("name")
	q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	db.Query(q)
}

func main() {
	r := gin.Default()
	r.GET("/u", handler)
	r.GET("/u2", directHandler)
	r.Run()
}
