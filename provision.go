package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yno9/go-jmap-smtp/cryptenv"
	jmapserver "github.com/yno9/go-jmapserver"
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
		// No DID at backfill time — no client interaction to derive one from.
		// Fills in on this account's next lazy-migration login.
		if jmapserver.AnchorClaim(anchorRef(), lp, dm, envelopeFingerprint(env), "", nil) == "conflict" {
			log.Printf("[anchor] SPLIT DETECTED: %s is already claimed with a different key on the anchor", primary)
		}
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
			// non-goals describe it.
			if cfg.AnchorURL == "" {
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
			proof := &jmapserver.BindingProof{Sig: body.DIDSig, TS: body.BindTS, Host: r.Host}
			switch jmapserver.AnchorClaim(anchorRef(), username, domain, "", body.DID, proof) {
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

// registerDidUpdate exposes PUT /account/did (Basic Auth) so an already-
// provisioned account can register its DID after the fact — DID.md's "lazy
// migration on next login" for identities that predate DID support. The
// fingerprint is read from the account's own envelope on disk (never trusted
// from the request), so this can only ever fill in / confirm the DID for the
// caller's own identity, never claim someone else's. Mirrors go-jmapap's
// registerDidUpdate, but forwards to the anchor over HTTP (jmapsmtp doesn't
// host the registry itself — see anchorClaim).
func registerDidUpdate(mux *http.ServeMux, dataDir string) {
	mux.HandleFunc("/account/did", func(w http.ResponseWriter, r *http.Request) {
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
		var body struct {
			DID    string `json:"did"`
			BindTS int64  `json:"bind_ts"`
			DIDSig string `json:"did_sig"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&body); err != nil || body.DID == "" {
			http.Error(w, "did required", http.StatusBadRequest)
			return
		}
		// An anchorless relay cannot take a DID at all — the same answer, in the
		// same words, that /account/provision gives. This used to 204: it
		// reported success for work it had not done and could not do, having no
		// anchor to prove the DID against and, since the local index went away,
		// nowhere to record one either. The caller treating this as best-effort
		// is not a licence to lie to it.
		if cfg.AnchorURL == "" {
			http.Error(w, "did not supported on this relay (no identity anchor)", http.StatusBadRequest)
			return
		}
		// Basic Auth proves the caller owns this ACCOUNT. It says nothing about
		// whether they own the DID they are naming, and those are different
		// claims: without a signature anyone with a self-service account could
		// have the anchor bind a stranger's DID to their address, and publish a
		// DNS record asserting it. Same rule as /account/provision.
		if body.DIDSig == "" {
			http.Error(w, "did_sig required", http.StatusBadRequest)
			return
		}
		env := readEnvelope(dataDir, domain, localpart)
		if env == nil {
			http.Error(w, "no envelope on file", http.StatusInternalServerError)
			return
		}
		proof := &jmapserver.BindingProof{Sig: body.DIDSig, TS: body.BindTS, Host: r.Host}
		switch jmapserver.AnchorClaim(anchorRef(), localpart, domain, envelopeFingerprint(env), body.DID, proof) {
		case "invalid":
			http.Error(w, "did binding rejected", http.StatusUnauthorized)
			return
		case "conflict":
			http.Error(w, "did mismatch for this identity", http.StatusConflict)
			return
		case "error":
			http.Error(w, "identity anchor unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
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
// Nothing about a DID is needed here any more. AnchorRelease tells the anchor
// the address is gone, and the anchor takes it from there: it reads the DID off
// the claim it is about to release, withdraws the DNS record, and stops
// re-announcing the DHT record. Clients still send {"did":"..."} and it is
// simply ignored — it was only ever there because this relay had no way to look
// the DID up, and the anchor has never had that problem.
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

		jmapserver.AnchorRelease(anchorRef(), localpart, domain)
		if err := os.RemoveAll(acctDir); err != nil {
			log.Printf("[delete] failed to remove %s: %v", acctDir, err)
			http.Error(w, "failed to delete account data", http.StatusInternalServerError)
			return
		}
		log.Printf("[delete] account %s deleted (self-service)", email)
		w.WriteHeader(http.StatusNoContent)
	})
}
