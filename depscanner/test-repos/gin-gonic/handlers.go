package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"
)

// db is a package-level handle the handlers borrow; nil at runtime since this
// is a dogfood fixture, but the call shapes are what the scanner reads.
var db *sql.DB

// lookupUser interpolates a request query param straight into SQL.
func lookupUser(c *gin.Context) {
	// REACHABLE: sql_injection
	id := c.Query("id")
	db.Query("SELECT * FROM users WHERE id = '" + id + "'")
	c.String(http.StatusOK, "ok")
}

// readDoc serves a file named by a route param with no path sanitization.
func readDoc(c *gin.Context) {
	// REACHABLE: path_traversal
	name := c.Param("name")
	data, _ := os.ReadFile("/srv/docs/" + name)
	_ = data
	c.String(http.StatusOK, "ok")
}

// writeNote writes a file to a request-controlled path.
func writeNote(c *gin.Context) {
	// REACHABLE: path_traversal
	dest := c.PostForm("dest")
	os.WriteFile("/srv/notes/"+dest, []byte("note"), 0o644)
	c.String(http.StatusOK, "ok")
}

// fetchURL makes an outbound request to a user-supplied URL.
func fetchURL(c *gin.Context) {
	// REACHABLE: ssrf
	target := c.Query("url")
	resp, _ := http.Get(target)
	_ = resp
	c.String(http.StatusOK, "ok")
}

// proxyRequest builds an outbound request with a user-supplied URL.
func proxyRequest(c *gin.Context) {
	// REACHABLE: ssrf
	dest := c.Query("dest")
	req, _ := http.NewRequest("GET", dest, nil)
	_ = req
	c.String(http.StatusOK, "ok")
}

// redirectNext sends the client to a user-supplied location.
func redirectNext(c *gin.Context) {
	// REACHABLE: open_redirect
	next := c.Query("next")
	c.Redirect(http.StatusFound, next)
}

// renderProfile bypasses auto-escape with a user-supplied bio.
func renderProfile(c *gin.Context) {
	// REACHABLE: xss
	bio := c.Query("bio")
	unsafe := template.HTML(bio)
	_ = unsafe
	c.String(http.StatusOK, "ok")
}

// compileFilter compiles a user-supplied regular expression.
func compileFilter(c *gin.Context) {
	// REACHABLE: redos
	pattern := c.Query("pattern")
	re := regexp.MustCompile(pattern)
	_ = re
	c.String(http.StatusOK, "ok")
}

// auditLog writes an attacker-controlled header into the log unescaped.
func auditLog(c *gin.Context) {
	// REACHABLE: log_injection
	agent := c.GetHeader("X-Forwarded-For")
	log.Printf("request from %s", agent)
	c.String(http.StatusOK, "ok")
}

// loadConfig deserializes the raw request body as YAML.
func loadConfig(c *gin.Context) {
	// REACHABLE: deserialization
	body, _ := c.GetRawData()
	var cfg map[string]interface{}
	yaml.Unmarshal(body, &cfg)
	c.String(http.StatusOK, "ok")
}

// pingHost passes a form value straight into a shell command.
func pingHost(c *gin.Context) {
	// REACHABLE: command_injection
	host := c.PostForm("host")
	exec.CommandContext(c, "/bin/sh", "-c", "ping -c1 "+host).Run()
	c.String(http.StatusOK, "ok")
}

// formatRecord interpolates a query param into a dynamic SQL string.
func formatRecord(c *gin.Context) {
	// REACHABLE: sql_injection
	table := c.Query("table")
	q := fmt.Sprintf("SELECT * FROM %s", table)
	db.Exec(q)
	c.String(http.StatusOK, "ok")
}
