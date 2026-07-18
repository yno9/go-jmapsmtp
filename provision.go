package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yno9/go-jmap-smtp/cryptenv"
)

var validUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,30}$`)

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

		// Signature-based provisioning (biset DID.md): DID control is proven by a
		// root-key signature; the login credential is a relay-scoped token hash.
		// The envelope (wrapped master secret) is OPTIONAL — own relays store it
		// for password recovery, third-party relays omit it (no secret leaves).
		var body struct {
			Username        string          `json:"username"`
			Domain          string          `json:"domain,omitempty"` // target domain; default = the open one
			DID             string          `json:"did"`
			BindTS          int64           `json:"bind_ts"`
			DIDSig          string          `json:"did_sig"`
			AuthTokenHash   string          `json:"auth_token_hash"`
			ProvisionSecret string          `json:"provision_secret,omitempty"` // required for gated domains
			Envelope        json.RawMessage `json:"envelope,omitempty"`
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
		if body.AuthTokenHash == "" {
			http.Error(w, "auth_token_hash required", http.StatusBadRequest)
			return
		}
		// DID is optional (biset started as a plain JMAP server; DID is a layered
		// identity feature, not a requirement to have an account at all — see
		// DID.md "coreless" mode). A client that omits it gets a plain account:
		// no binding proof needed, no anchor claim, no DNS record, no
		// discovery/portability — same as any classic JMAP mailbox.
		hasDID := body.DID != ""
		if hasDID {
			// Anchorless first, because it is the more fundamental refusal: this
			// relay cannot take a DID at all, and saying "did_sig required" to
			// someone who then supplies one would be a lie. The proof is verified
			// by the anchor, not here (ANCHOR.md decision 1), so with no anchor
			// there is nobody to verify it — and an unverified DID must never be
			// claimed, or anyone could have a stranger's identity recorded as
			// their own. Anchorless means plain accounts, exactly as ANCHOR.md's
			// non-goals describe it. In a noanchor build anchorAvailable() is
			// false and this refuses every DID unconditionally — the anchor code
			// was never compiled in to prove one.
			if !anchorAvailable() || cfg.AnchorURL == "" {
				http.Error(w, "did not supported on this relay (no identity anchor)", http.StatusBadRequest)
				return
			}
			if body.DIDSig == "" {
				http.Error(w, "did_sig required when did is present", http.StatusBadRequest)
				return
			}
		}

		// Domain routing: honor the client's requested domain if it exists; else
		// fall back to the default open (self-service) domain.
		domain := strings.ToLower(strings.TrimSpace(body.Domain))
		var dc DomainConfig
		if domain != "" {
			c, ok := domainConfig(domain)
			if !ok {
				http.Error(w, "unknown domain", http.StatusBadRequest)
				return
			}
			dc = c
		} else {
			domain = provisionDomain()
			if domain == "" {
				http.Error(w, "account creation not available", http.StatusForbidden)
				return
			}
			dc = cfg.Domains[domain]
		}
		// Provision policy: open (allow_provision) OR gated by a shared secret
		// (privileged domains — not creatable from the UI, no secret = refused).
		if !dc.AllowProvision {
			if dc.ProvisionSecret == "" || body.ProvisionSecret != dc.ProvisionSecret {
				http.Error(w, "domain not open for provisioning", http.StatusForbidden)
				return
			}
		}
		email := username + "@" + domain

		// Accounts are purely dynamic (no config-managed account list) — a name is
		// taken iff it already has a credential.
		h.mu.RLock()
		_, dynExists := h.dyn[email]
		h.mu.RUnlock()
		if dynExists || readAuthHash(dataDir, domain, username) != "" {
			http.Error(w, "username taken", http.StatusConflict)
			return
		}

		// Identity anchor: prove control of the DID and verify this name isn't
		// already owned by a different one — one round trip, both jobs. r.Host is
		// forwarded verbatim: it is what the client signed against, and only this
		// relay saw it first-hand.
		if hasDID {
			switch anchorClaim(username, domain, body.DID, body.DIDSig, body.BindTS, r.Host) {
			case "invalid":
				http.Error(w, "did binding rejected", http.StatusUnauthorized)
				return
			case "conflict":
				http.Error(w, "identity owned by a different key", http.StatusConflict)
				return
			case "error":
				log.Printf("[anchor] unreachable (%s) — refusing provision of %s", cfg.AnchorURL, email)
				http.Error(w, "identity anchor unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		// Store the per-relay login credential.
		if err := writeAuthHash(dataDir, domain, username, body.AuthTokenHash); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Own relays receive the envelope (password recovery); third-party ones don't.
		if len(body.Envelope) > 0 {
			if env, err := cryptenv.FromBytes(body.Envelope); err == nil {
				writeEnvelope(dataDir, domain, username, env) //nolint:errcheck
			}
		}

		h.addDynAccount(username, domain, dataDir)
		// No local DID index to maintain: which addresses trace back to a DID is
		// cross-relay information, so the anchor derives it from the claim this
		// provision just made (ANCHOR.md decision 1). A relay could only ever
		// answer for itself, and keeping a second copy is what let this one drift
		// out of step with the registry.

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"email": email}) //nolint:errcheck
	})
}

// registerAccountDelete exposes POST /account/delete (Basic Auth) — the
// missing counterpart to /account/provision (create) and PUT /account/did
// (update): permanently removes the caller's OWN account data. Same
// no-email-in-the-body property as registerDidUpdate: the target comes only
// from the authenticated credential, so this can never touch anyone else's
// account. Mirrors purgeInactiveAccounts' cleanup (maintenance.go) — same
// map deletions, same os.RemoveAll — just on-demand for one account instead
// of a periodic sweep over all of them.
//
// Deleting your own account is a plain-account operation, so this stays in the
// default JMAP surface; only the anchor release is DID, and it goes through the
// anchorRelease seam — a no-op in the noanchor build (there is no claim to
// withdraw), so account deletion works identically either way. When a claim
// does exist, releasing it tells the anchor the address is gone and the anchor
// takes it from there: it reads the DID off the claim it is about to release,
// withdraws the DNS record, and stops re-announcing the DHT record.
func registerAccountDelete(mux *http.ServeMux, h *handler, dataDir string) {
	mux.HandleFunc("/account/delete", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		domain, localpart, ok := authenticate(r, dataDir)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="biset"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if dc, exists := domainConfig(domain); exists {
			if _, static := dc.Accounts[localpart]; static {
				http.Error(w, "this account is server-managed and can't be self-deleted", http.StatusForbidden)
				return
			}
		}
		email := localpart + "@" + domain
		acctDir := filepath.Join(dataDir, domain, localpart)

		h.mu.Lock()
		delete(h.stores, email)
		delete(h.dyn, email)
		for alias, target := range h.aliases {
			if target == email || strings.EqualFold(alias, email) {
				delete(h.aliases, alias)
			}
		}
		h.mu.Unlock()

		anchorRelease(localpart, domain)
		if err := os.RemoveAll(acctDir); err != nil {
			log.Printf("[delete] failed to remove %s: %v", acctDir, err)
			http.Error(w, "failed to delete account data", http.StatusInternalServerError)
			return
		}
		log.Printf("[delete] account %s deleted (self-service)", email)
		w.WriteHeader(http.StatusNoContent)
	})
}
