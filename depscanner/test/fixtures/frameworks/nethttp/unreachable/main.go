package main

import (
	"net/http"
)

// net/http server with no HandleFunc; vulnerable golang.org/x/text never imported.
func main() {
	_ = http.NewServeMux()
}
