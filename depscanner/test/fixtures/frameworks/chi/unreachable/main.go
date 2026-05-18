package main

import (
	"github.com/go-chi/chi/v5"
)

// chi router constructed but never bound to ListenAndServe; no routes added.
func main() {
	r := chi.NewRouter()
	_ = r
}
