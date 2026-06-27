package main

import (
	"bytes"
	"crypto/sha1"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
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

func pubkeyFile(dataDir, domain, localpart string) string {
	return filepath.Join(dataDir, domain, localpart, "pubkey.pgp")
}

func privkeyEncFile(dataDir, domain, localpart string) string {
	return filepath.Join(dataDir, domain, localpart, "privkey.enc")
}

// loadUserPubkeyEntity reads the recipient's armored public key from disk.
// Returns nil if the key is absent or unparseable.
func loadUserPubkeyEntity(dataDir, domain, localpart string) *openpgp.Entity {
	b, err := os.ReadFile(pubkeyFile(dataDir, domain, localpart))
	if err != nil {
		return nil
	}
	block, err := armor.Decode(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	entities, err := openpgp.ReadKeyRing(block.Body)
	if err != nil || len(entities) == 0 {
		return nil
	}
	return entities[0]
}

// serveUserPubkey reads an armored public key from disk, serializes it as binary,
// and writes it to w. Returns false if the key is absent or unparseable.
func serveUserPubkey(w http.ResponseWriter, dataDir, domain, localpart string) bool {
	b, err := os.ReadFile(pubkeyFile(dataDir, domain, localpart))
	if err != nil {
		return false
	}
	block, err := armor.Decode(bytes.NewReader(b))
	if err != nil {
		return false
	}
	entities, err := openpgp.ReadKeyRing(block.Body)
	if err != nil || len(entities) == 0 {
		return false
	}
	var buf bytes.Buffer
	for _, e := range entities {
		e.Serialize(&buf) //nolint:errcheck
	}
	if buf.Len() == 0 {
		return false
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(buf.Bytes()) //nolint:errcheck
	return true
}

// registerWKD adds WKD and PGP key-upload endpoints to mux.
func registerWKD(mux *http.ServeMux, dataDir string) {
	mux.HandleFunc("/.well-known/openpgpkey/policy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/.well-known/openpgpkey/hu/", func(w http.ResponseWriter, r *http.Request) {
		hash := strings.TrimPrefix(r.URL.Path, "/.well-known/openpgpkey/hu/")
		localpart := r.URL.Query().Get("l")

		// Per-user key takes priority over the global key.
		if localpart != "" && wkdHash(localpart) == hash {
			for domain, domCfg := range cfg.Domains {
				if _, ok := domCfg.Accounts[localpart]; ok {
					if serveUserPubkey(w, dataDir, domain, localpart) {
						return
					}
				}
			}
		}

		// Fall back to global key.
		if pgpEntity == nil {
			http.NotFound(w, r)
			return
		}
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

	// PUT /pgp/pubkey — authenticated public key upload (armored PGP).
	mux.HandleFunc("/pgp/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		domain, localpart, ok := authenticate(r, dataDir)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="biset"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}

		// Validate that the payload is a parseable PGP public key.
		block, err := armor.Decode(bytes.NewReader(body))
		if err != nil {
			http.Error(w, "invalid PGP key", http.StatusBadRequest)
			return
		}
		if _, err := openpgp.ReadKeyRing(block.Body); err != nil {
			http.Error(w, "invalid PGP key", http.StatusBadRequest)
			return
		}

		dir := filepath.Join(dataDir, domain, localpart)
		if err := os.MkdirAll(dir, 0700); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(pubkeyFile(dataDir, domain, localpart), body, 0600); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})

	// GET /pgp/privkey  — fetch encrypted private key blob.
	// PUT /pgp/privkey  — store encrypted private key blob (opaque; encrypted client-side).
	mux.HandleFunc("/pgp/privkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		domain, localpart, ok := authenticate(r, dataDir)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="biset"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		fpath := privkeyEncFile(dataDir, domain, localpart)

		switch r.Method {
		case http.MethodGet:
			data, err := os.ReadFile(fpath)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data) //nolint:errcheck

		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read error", http.StatusInternalServerError)
				return
			}
			dir := filepath.Join(dataDir, domain, localpart)
			if err := os.MkdirAll(dir, 0700); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if err := os.WriteFile(fpath, body, 0600); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// GET /pgp/peerkey?addr=<email> — fetch stored Autocrypt peer public key (authenticated).
	mux.HandleFunc("/pgp/peerkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		domain, _, ok := authenticate(r, dataDir)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		addr := r.URL.Query().Get("addr")
		if addr == "" {
			http.Error(w, "addr required", http.StatusBadRequest)
			return
		}

		keyPath := dataDir + "/" + domain + "/peers/" + strings.ToLower(addr) + ".pgp"

		switch r.Method {
		case http.MethodGet:
			b, err := os.ReadFile(keyPath)
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(b) //nolint:errcheck

		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read error", http.StatusInternalServerError)
				return
			}
			if _, err := openpgp.ReadKeyRing(bytes.NewReader(body)); err != nil {
				http.Error(w, "invalid PGP key", http.StatusBadRequest)
				return
			}
			dir := dataDir + "/" + domain + "/peers"
			if err := os.MkdirAll(dir, 0700); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if err := os.WriteFile(keyPath, body, 0600); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	})
}
