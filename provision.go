package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/yno9/go-jmap-smtp/cryptenv"
)

var validUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,30}$`)

// envelopeFingerprint hashes the cryptenv envelope. biset sends the identical
// envelope to every relay, so this matches the fingerprint the anchor computed
// for the AP relay's copy — the basis for detecting a split identity.
func envelopeFingerprint(env *cryptenv.Envelope) string {
	b, err := env.Bytes()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// backfillAnchorPush registers existing local accounts with the anchor so
// identities that predate it are protected too. A conflict here means the name
// is already held on another relay by a DIFFERENT key — i.e. a pre-existing split
// — which we surface loudly rather than silently.
func backfillAnchorPush(h *handler, dataDir string) {
	if cfg.AnchorURL == "" {
		return
	}
	h.mu.RLock()
	primaries := make([]string, 0, len(h.stores))
	for p := range h.stores {
		primaries = append(primaries, p)
	}
	h.mu.RUnlock()
	for _, primary := range primaries {
		parts := strings.SplitN(primary, "@", 2)
		if len(parts) != 2 {
			continue
		}
		lp, dm := parts[0], parts[1]
		env := readEnvelope(dataDir, dm, lp)
		if env == nil {
			continue
		}
		if anchorClaim(cfg.AnchorURL, lp, envelopeFingerprint(env)) == "conflict" {
			log.Printf("[anchor] SPLIT DETECTED: %s is already claimed with a different key on the anchor", primary)
		}
	}
}

// anchorClaim asks the identity anchor to claim/verify this name for the given
// fingerprint. Returns "ok" (claim recorded or matched), "conflict" (name held
// by a different key — a split attempt), or "error" (anchor unreachable).
func anchorClaim(anchorURL, localpart, fp string) string {
	body, _ := json.Marshal(map[string]string{"fingerprint": fp})
	url := strings.TrimRight(anchorURL, "/") + "/identity/" + localpart
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "error"
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return "ok"
	case http.StatusConflict:
		return "conflict"
	default:
		return "error"
	}
}

// replyOnlyExempt returns true if the sender address or its domain is listed
// in cfg.ReplyOnlyExempt, bypassing the reply_only_outbound restriction.
func replyOnlyExempt(sender string) bool {
	senderLow := strings.ToLower(sender)
	var senderDomain string
	if i := strings.LastIndex(senderLow, "@"); i >= 0 {
		senderDomain = senderLow[i+1:]
	}
	for _, entry := range cfg.ReplyOnlyExempt {
		e := strings.ToLower(strings.TrimSpace(entry))
		if e == senderLow || e == senderDomain {
			return true
		}
	}
	return false
}

func primaryDomain() string {
	for d := range cfg.Domains {
		return d
	}
	return cfg.Hostname
}

func provisionDomain() string {
	for d, dc := range cfg.Domains {
		if dc.AllowProvision {
			return d
		}
	}
	return ""
}

func registerProvision(mux *http.ServeMux, h *handler, dataDir string) {
	mux.HandleFunc("/account/provision", func(w http.ResponseWriter, r *http.Request) {
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

		var body struct {
			Username string          `json:"username"`
			Envelope json.RawMessage `json:"envelope"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		username := strings.ToLower(strings.TrimSpace(body.Username))
		if !validUsername.MatchString(username) {
			http.Error(w, "invalid username", http.StatusBadRequest)
			return
		}

		domain := provisionDomain()
		if domain == "" {
			http.Error(w, "account creation not available", http.StatusForbidden)
			return
		}
		email := username + "@" + domain

		// Check not already taken (static config or dynamic)
		if domCfg, ok := cfg.Domains[domain]; ok {
			if _, ok := domCfg.Accounts[username]; ok {
				http.Error(w, "username taken", http.StatusConflict)
				return
			}
		}
		h.mu.RLock()
		_, dynExists := h.dyn[email]
		h.mu.RUnlock()
		if dynExists || readEnvelope(dataDir, domain, username) != nil {
			http.Error(w, "username taken", http.StatusConflict)
			return
		}

		env, err := cryptenv.FromBytes(body.Envelope)
		if err != nil {
			http.Error(w, "invalid envelope", http.StatusBadRequest)
			return
		}
		// Identity anchor: verify this name isn't already owned by a different
		// key on another relay. Empty AnchorURL = single-relay mode (no anchor),
		// so we skip. A configured-but-unreachable anchor fails closed (503) —
		// better to refuse than to create a possibly-split identity.
		if cfg.AnchorURL != "" {
			switch anchorClaim(cfg.AnchorURL, username, envelopeFingerprint(env)) {
			case "conflict":
				http.Error(w, "identity owned by a different key", http.StatusConflict)
				return
			case "error":
				log.Printf("[anchor] unreachable (%s) — refusing provision of %s", cfg.AnchorURL, email)
				http.Error(w, "identity anchor unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		if err := writeEnvelope(dataDir, domain, username, env); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		h.addDynAccount(username, domain, dataDir)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"email": email}) //nolint:errcheck
	})
}
