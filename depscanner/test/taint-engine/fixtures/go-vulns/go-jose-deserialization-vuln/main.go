package main

import (
	"net/http"

	jose "github.com/go-jose/go-jose/v4"
)

// CVE-2024-28180 shape — attacker-controlled JWE flows into Parse + Decrypt.
func handler(w http.ResponseWriter, r *http.Request) {
	encryptedData := r.FormValue("jwe")
	key := []byte("secret")

	var obj jose.JSONWebEncryption
	_, err := obj.Parse(encryptedData)
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
