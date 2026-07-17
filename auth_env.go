package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/yno9/go-jmap-smtp/cryptenv"
	jmapserver "github.com/yno9/go-jmapserver"
)

// envelope.json layout: cryptenv.Envelope serialized as JSON.
// One per account, stored alongside privkey.enc.

func envelopeFile(dataDir, domain, localpart string) string {
	return filepath.Join(dataDir, domain, localpart, "envelope.json")
}

// Per-account, per-relay auth-token hash (base64(sha256(scoped token))). This is
// what login verifies against now — NOT the envelope's hash — so tokens can be
// relay-scoped (a token stolen by one relay is useless here) and DID-less /
// third-party accounts (no envelope) still authenticate.
func authHashFile(dataDir, domain, localpart string) string {
	return filepath.Join(dataDir, domain, localpart, "auth_token_hash")
}

func readAuthHash(dataDir, domain, localpart string) string {
	if b, err := os.ReadFile(authHashFile(dataDir, domain, localpart)); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

func writeAuthHash(dataDir, domain, localpart, hashB64 string) error {
	dir := filepath.Join(dataDir, domain, localpart)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(authHashFile(dataDir, domain, localpart), []byte(hashB64), 0600)
}

func readEnvelope(dataDir, domain, localpart string) *cryptenv.Envelope {
	b, err := os.ReadFile(envelopeFile(dataDir, domain, localpart))
	if err != nil {
		return nil
	}
	env, err := cryptenv.FromBytes(b)
	if err != nil {
		return nil
	}
	return env
}

func writeEnvelope(dataDir, domain, localpart string, env *cryptenv.Envelope) error {
	dir := filepath.Join(dataDir, domain, localpart)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := env.Bytes()
	if err != nil {
		return err
	}
	return os.WriteFile(envelopeFile(dataDir, domain, localpart), b, 0600)
}

// authenticate parses Basic Auth from r, verifies the presented auth_token
// against the account's envelope, and returns the resolved (domain, localpart).
// The Basic Auth password field MUST carry base64(auth_token).
func authenticate(r *http.Request, dataDir string) (domain, localpart string, ok bool) {
	username, password, hasBA := r.BasicAuth()
	if !hasBA {
		return "", "", false
	}
	parts := strings.SplitN(strings.ToLower(username), "@", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	lp, dm := parts[0], parts[1]
	if _, exists := domainConfig(dm); !exists {
		return "", "", false
	}
	hash := readAuthHash(dataDir, dm, lp)
	if hash == "" {
		return "", "", false // account has no relay-scoped credential
	}
	tok, err := decodeAuthToken(password)
	if err != nil {
		return "", "", false
	}
	if !jmapserver.VerifyAuthToken(tok, hash) {
		return "", "", false
	}
	return dm, lp, true
}

func decodeAuthToken(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("invalid base64")
}

// ── HTTP endpoints ───────────────────────────────────────────────────────────

func registerAuthEnv(mux *http.ServeMux, dataDir string) {
	// GET /auth/envelope?email=user@domain
	// Returns the envelope JSON (opaque without password). Public — the envelope
	// itself is useless to an attacker who doesn't know the password (Argon2id
	// + AES-GCM gate the master_secret).
	mux.HandleFunc("/auth/envelope", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		switch r.Method {
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
			return

		case http.MethodGet:
			email := strings.ToLower(r.URL.Query().Get("email"))
			parts := strings.SplitN(email, "@", 2)
			if len(parts) != 2 {
				http.Error(w, "email required", http.StatusBadRequest)
				return
			}
			lp, dm := parts[0], parts[1]
			if _, ok := domainConfig(dm); !ok {
				http.NotFound(w, r)
				return
			}
			// Serve the envelope for ANY account that has one on disk — dynamic
			// (provisioned) accounts aren't in the static config but still need
			// their envelope for the client's add-account/login flow. The
			// envelope is useless without the password (Argon2id-gated), so
			// exposing it is safe. os.ReadFile below 404s if none exists.
			b, err := os.ReadFile(envelopeFile(dataDir, dm, lp))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b) //nolint:errcheck

		case http.MethodPut:
			// Password change: Basic Auth with current auth_token authorizes
			// replacing the envelope with a re-wrapped one. Server doesn't
			// touch the master_secret; it only enforces "you held the old auth_token".
			dm, lp, ok := authenticate(r, dataDir)
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
			newEnv, err := cryptenv.FromBytes(body)
			if err != nil {
				http.Error(w, "invalid envelope", http.StatusBadRequest)
				return
			}
			if err := writeEnvelope(dataDir, dm, lp, newEnv); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// POST /auth/signup?token=XXX — consume a setup token, install the
	// client-built envelope as the account's initial credential.
	mux.HandleFunc("/auth/signup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}

		// Find which (domain, localpart) the token was issued for.
		var dm, lp string
		for d, domCfg := range cfg.Domains {
			for l := range domCfg.Accounts {
				tf := tokenFile(dataDir, d, l)
				b, err := os.ReadFile(tf)
				if err != nil {
					continue
				}
				if strings.TrimSpace(string(b)) == token {
					dm, lp = d, l
					break
				}
			}
			if dm != "" {
				break
			}
		}
		if dm == "" {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Reject if an envelope already exists (idempotency — caller should
		// rotate via PUT /auth/envelope instead).
		if readEnvelope(dataDir, dm, lp) != nil {
			http.Error(w, "already initialized", http.StatusConflict)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		newEnv, err := cryptenv.FromBytes(body)
		if err != nil {
			http.Error(w, "invalid envelope", http.StatusBadRequest)
			return
		}
		// Register the identity anchor, same as provisioning does — otherwise a
		// setup-token claim leaves the name un-anchored and a sibling relay can't
		// later be added to it (the anchor gate would 409 for lack of a record).
		if cfg.AnchorURL != "" {
			switch jmapserver.AnchorClaim(anchorRef(), lp, dm, envelopeFingerprint(newEnv), "", nil) {
			case "conflict":
				http.Error(w, "identity owned by a different key", http.StatusConflict)
				return
			case "error":
				log.Printf("[anchor] unreachable (%s) — refusing signup of %s@%s", cfg.AnchorURL, lp, dm)
				http.Error(w, "identity anchor unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		if err := writeEnvelope(dataDir, dm, lp, newEnv); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		os.Remove(tokenFile(dataDir, dm, lp)) //nolint:errcheck
		w.WriteHeader(http.StatusNoContent)
	})
}

// authenticatedAccount is a convenience wrapper that callers in wkd.go and
// elsewhere can use in place of the old (username/password) → checkPassword
// dance. Returns (domain, localpart, true) on success.
//
// Kept as a thin alias of authenticate for readability at call sites.
func authenticatedAccount(r *http.Request, dataDir string) (string, string, bool) {
	return authenticate(r, dataDir)
}

// Stable JSON marshalling helper used in tests (and reserved for future use).
//
//nolint:unused
func marshalEnvelope(env *cryptenv.Envelope) []byte {
	b, _ := json.Marshal(env)
	return b
}
