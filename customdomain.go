package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Custom domains: an end user brings their own domain (e.g. y.jp) to be
// hosted on this relay, without running any server themselves — the
// biset-verse "Google Workspace" middle ground between a pure DNS signpost
// and full self-hosting (see DID.md). Ownership is proven via a
// deterministic DNS TXT challenge (no pending-state needed: the expected
// token is always recomputable from domain + a server-held secret), then the
// domain is added to a dynamic registry — the same "purely dynamic, no
// restart needed" treatment accounts already got.
//
// Scope: mail (this relay) only. A custom domain used for ActivityPub would
// additionally need real HTTP/TLS routing to jmapap (SNI-level hosting, not
// just a DNS record) — a materially bigger problem, out of scope here.

var (
	dynDomainsMu sync.RWMutex
	dynDomains   = map[string]DomainConfig{}
)

var validCustomDomain = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

func customDomainDir(dataDir, domain string) string {
	return filepath.Join(dataDir, "_domains", domain)
}

// domainConfig resolves a domain against static config first, then the
// dynamic (custom) registry — the single lookup every domain-gated code path
// should use from here on.
func domainConfig(domain string) (DomainConfig, bool) {
	if dc, ok := cfg.Domains[domain]; ok {
		return dc, true
	}
	dynDomainsMu.RLock()
	dc, ok := dynDomains[domain]
	dynDomainsMu.RUnlock()
	return dc, ok
}

// verifyToken is deterministic (HMAC(secret, domain)) — recomputable at
// challenge time with no pending-state to store or expire. Its only job is
// to distinguish "an admin who read biset's instructions and deliberately
// added this" from coincidence; DNS control is the actual ground truth of
// ownership (whoever can write a domain's records already controls it).
func verifyToken(domain string) string {
	mac := hmac.New(sha256.New, []byte(cfg.DomainVerifySecret))
	mac.Write([]byte(domain)) //nolint:errcheck
	return "biset-verify=" + hex.EncodeToString(mac.Sum(nil))[:32]
}

// provisionSecretFor is deterministic (HMAC(secret, "provision:"+domain)) —
// like verifyToken, no persisted/rotated state needed to recompute it later.
// Handed back to whoever currently controls the domain's DNS each time they
// complete /domain/add, including a domain that's already registered — a BYO
// domain's account creation stays gated on *current* DNS control rather than
// becoming permanently open (AllowProvision) the moment it's first set up,
// which would otherwise let anyone create accounts under someone else's
// domain forever, no re-proof required.
func provisionSecretFor(domain string) string {
	mac := hmac.New(sha256.New, []byte(cfg.DomainVerifySecret))
	mac.Write([]byte("provision:" + domain)) //nolint:errcheck
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

func checkVerifyTXT(domain, expected string) bool {
	txts, err := net.LookupTXT("_biset-verify." + domain)
	if err != nil {
		return false
	}
	for _, t := range txts {
		if t == expected {
			return true
		}
	}
	return false
}

// loadDynDomains restores the custom-domain registry (and its DKIM keys) at
// startup, so a restart doesn't require re-verification.
func loadDynDomains(dataDir string) {
	root := filepath.Join(dataDir, "_domains")
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		domain := e.Name()
		b, err := os.ReadFile(filepath.Join(root, domain, "domain.json"))
		if err != nil {
			continue
		}
		var dc DomainConfig
		if json.Unmarshal(b, &dc) != nil {
			continue
		}
		dynDomainsMu.Lock()
		dynDomains[domain] = dc
		dynDomainsMu.Unlock()
		key := loadOrGenerateDKIMKey(filepath.Join(root, domain))
		if key != nil {
			dkimKeys[domain] = key
			writeDKIMRecordFile(filepath.Join(root, domain), dc.DKIMSelector, domain)
		}
	}
}

// registerCustomDomain exposes the two-step verification flow:
//
//	GET  /domain/verify-token?domain=y.jp   → {"txt_name":"...", "token":"..."}
//	POST /domain/add   {"domain":"y.jp"}    → verifies the TXT is live, then
//	    registers the domain (dynamic, AllowProvision) and returns the
//	    remaining DNS records (DKIM, MX target) the owner still needs to add.
func registerCustomDomain(mux *http.ServeMux, dataDir string) {
	mux.HandleFunc("/domain/verify-token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
		if !validCustomDomain.MatchString(domain) {
			http.Error(w, "invalid domain", http.StatusBadRequest)
			return
		}
		// MX target and DKIM key are handed out here too, alongside the
		// ownership TXT, so the client can show all the DNS records the owner
		// needs to add in one screen instead of two sequential ones — nothing
		// here is privileged (a public key record + this relay's own
		// hostname), unlike provision_secret below, which stays gated behind
		// actual ownership proof. The DKIM key is generated (or loaded, if
		// this domain was already verify-token'd before) eagerly; /domain/add
		// below reuses the exact same key via the same idempotent
		// loadOrGenerateDKIMKey rather than rotating it once ownership is
		// confirmed.
		dir := customDomainDir(dataDir, domain)
		var dkimRecord, dkimName string
		if err := os.MkdirAll(dir, 0700); err == nil {
			if key := loadOrGenerateDKIMKey(dir); key != nil {
				dkimKeys[domain] = key
				writeDKIMRecordFile(dir, "default", domain)
				dkimRecord = dkimPublicKeyRecord(key)
				dkimName = "default._domainkey." + domain
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"txt_name":   "_biset-verify." + domain,
			"token":      verifyToken(domain),
			"mx_target":  cfg.Hostname,
			"dkim_name":  dkimName,
			"dkim_value": dkimRecord,
		})
	})

	mux.HandleFunc("/domain/add", func(w http.ResponseWriter, r *http.Request) {
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
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		domain := strings.ToLower(strings.TrimSpace(body.Domain))
		if !validCustomDomain.MatchString(domain) {
			http.Error(w, "invalid domain", http.StatusBadRequest)
			return
		}
		// Re-checked every time, even for an already-registered domain: a
		// past registration doesn't grant standing access to provision more
		// accounts under it forever — see provisionSecretFor.
		if !checkVerifyTXT(domain, verifyToken(domain)) {
			http.Error(w, "verification TXT record not found (DNS propagation can take a few minutes — retry shortly)", http.StatusPreconditionFailed)
			return
		}

		dir := customDomainDir(dataDir, domain)
		if err := os.MkdirAll(dir, 0700); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Gated (never AllowProvision:true) — account creation under this
		// domain requires provision_secret, freshly re-issued above only to
		// whoever currently controls its DNS, not a one-time, forever-open claim.
		dc := DomainConfig{AllowProvision: false, ProvisionSecret: provisionSecretFor(domain), DKIMSelector: "default"}
		b, _ := json.Marshal(dc)
		if err := os.WriteFile(filepath.Join(dir, "domain.json"), b, 0600); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		dynDomainsMu.Lock()
		dynDomains[domain] = dc
		dynDomainsMu.Unlock()

		// loadOrGenerateDKIMKey loads the existing key from disk if this
		// domain was already registered — never rotates an existing key.
		var dkimRecord, dkimName string
		if key := loadOrGenerateDKIMKey(dir); key != nil {
			dkimKeys[domain] = key
			writeDKIMRecordFile(dir, dc.DKIMSelector, domain)
			dkimRecord = dkimPublicKeyRecord(key)
			dkimName = dc.DKIMSelector + "._domainkey." + domain
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"domain":           domain,
			"mx_target":        cfg.Hostname,
			"dkim_name":        dkimName,
			"dkim_value":       dkimRecord,
			"provision_secret": dc.ProvisionSecret,
		})
	})
}
