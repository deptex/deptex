package main

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/html"
	"golang.org/x/text/language"
)

// CVE-2022-32149 reachability target.
func parseLanguage(input string) {
	tag, _ := language.Parse(input)
	fmt.Println("Language:", tag)
}

// CVE-2023-3978 reachability target.
func parseHTML(rawHTML string) {
	doc, _ := html.Parse(strings.NewReader(rawHTML))
	fmt.Println("Parsed:", doc.Type)
}

// golang.org/x/crypto InsecureIgnoreHostKey is flagged by linters — keeping to exercise
// static analyzers on an intentional-bad-pattern case.
func createSSHConfig() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func main() {
	r := gin.Default()
	r.GET("/parse/:lang", func(c *gin.Context) {
		parseLanguage(c.Param("lang"))
		c.String(200, "OK")
	})
	r.POST("/html", func(c *gin.Context) {
		body, _ := c.GetRawData()
		parseHTML(string(body))
		c.String(200, "Parsed")
	})
	_ = createSSHConfig()
	r.Run(":8080")
}
