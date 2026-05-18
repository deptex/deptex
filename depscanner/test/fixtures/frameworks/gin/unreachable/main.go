package main

import (
	"github.com/gin-gonic/gin"
)

// gin imported, engine constructed, but no routes are ever registered.
// No HTTP entry point exists, therefore the vulnerable path-handling code
// surface is unreachable.
func main() {
	r := gin.Default()
	_ = r // engine never serves
}
