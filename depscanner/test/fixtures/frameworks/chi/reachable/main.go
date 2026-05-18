package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// CVE-2023-44487 (rapid-reset HTTP/2) is the proxy CVE for chi <= 5.0.10.
// We also exhibit a reflected XSS sink to demonstrate framework reachability
// for the dataflow analysis.
func main() {
	r := chi.NewRouter()
	r.Get("/echo", func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query().Get("q")
		// Sink: write user input directly into HTML response — reflected XSS.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<h1>" + q + "</h1>"))
	})
	_ = http.ListenAndServe(":8080", r)
}
