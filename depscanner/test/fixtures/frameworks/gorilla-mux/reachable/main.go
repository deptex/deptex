package main

import (
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

// CVE-2023-39325 — golang.org/x/net <= 0.16.0 HTTP/2 rapid reset DoS
// (transitive). Reachable surface is any Mux router that serves HTTP/2.
// Also includes a path-traversal sink to drive dataflow tooling.
func main() {
	r := mux.NewRouter()
	r.HandleFunc("/file/{name}", func(w http.ResponseWriter, req *http.Request) {
		name := mux.Vars(req)["name"]
		// Sink: open user-controlled file path.
		data, err := os.ReadFile("./uploads/" + name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write(data)
	})
	_ = http.ListenAndServe(":8080", r)
}
