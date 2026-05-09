package main

import (
	"html/template"
	"net/http"

	"golang.org/x/text/language"
)

// CVE-2022-32149 — golang.org/x/text/language ParseAcceptLanguage DoS
// when the Accept-Language header contains specifically crafted values.
func main() {
	http.HandleFunc("/lang", func(w http.ResponseWriter, req *http.Request) {
		// Sink: parse user-controlled header value.
		tags, _, _ := language.ParseAcceptLanguage(req.Header.Get("Accept-Language"))
		t := template.Must(template.New("o").Parse("{{.}}"))
		_ = t.Execute(w, tags)
	})
	_ = http.ListenAndServe(":8080", nil)
}
