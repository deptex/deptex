package main

import (
	"github.com/gorilla/mux"
)

// Router built but no routes registered, no ListenAndServe.
func main() {
	r := mux.NewRouter()
	_ = r
}
