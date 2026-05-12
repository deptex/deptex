package main

import (
	"net/http"

	jose "github.com/go-jose/go-jose/v4"
)

// Safe variant: the JWE input is hardcoded, never tainted by the request.
func handler(w http.ResponseWriter, r *http.Request) {
	_ = r // request param unused for parsing
	key := []byte("secret")

	var obj jose.JSONWebEncryption
	_, err := obj.Parse("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..hardcoded")
	if err != nil {
		return
	}

	plaintext, err := obj.Decrypt(key)
	if err != nil {
		return
	}

	w.Write(plaintext)
}

func main() {
	http.HandleFunc("/decrypt", handler)
	http.ListenAndServe(":8080", nil)
}
