package main

import (
	"bytes"
	"crypto/sha1"
	"net/http"
	"strings"
)

// wkdHash returns the Zbase32-encoded SHA-1 hash of the lowercased localpart,
// as required by the Web Key Directory (WKD) spec (RFC-draft).
func wkdHash(localpart string) string {
	h := sha1.Sum([]byte(strings.ToLower(localpart)))
	const alpha = "ybndrfg8ejkmcpqxot1uwisza345h769"
	var sb strings.Builder
	bits, cur := 0, 0
	for _, b := range h {
		cur = (cur << 8) | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(alpha[(cur>>bits)&0x1f])
		}
	}
	if bits > 0 {
		sb.WriteByte(alpha[(cur<<(5-bits))&0x1f])
	}
	return sb.String()
}

// registerWKD adds WKD endpoints to mux.
// Serves /.well-known/openpgpkey/policy and /.well-known/openpgpkey/hu/.
func registerWKD(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/openpgpkey/policy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/.well-known/openpgpkey/hu/", func(w http.ResponseWriter, r *http.Request) {
		if pgpEntity == nil {
			http.NotFound(w, r)
			return
		}
		hash := strings.TrimPrefix(r.URL.Path, "/.well-known/openpgpkey/hu/")
		localpart := r.URL.Query().Get("l")
		if localpart != "" && wkdHash(localpart) != hash {
			http.NotFound(w, r)
			return
		}
		var buf bytes.Buffer
		if err := pgpEntity.Serialize(&buf); err != nil {
			http.Error(w, "key error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write(buf.Bytes()) //nolint:errcheck
	})
}
