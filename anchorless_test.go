//go:build !noanchor

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jmapserver "github.com/yno9/go-jmapserver"
)

// Anchorless is the mode production never runs, which is exactly why it needs a
// test: nothing here can be checked against the live relays, because they all
// set anchor_url. ANCHOR.md decision 2 says anchorless means plain accounts and
// no DIDs at all — and since the local DID index was absorbed into the anchor,
// there is now literally nowhere on an anchorless relay to put one.
//
// This is RUNTIME anchorlessness — an anchor-capable binary with anchor_url
// unset — so it tests registerDidUpdate, which the noanchor build tag compiles
// out entirely. Hence the tag: under -tags noanchor there is no /account/did
// route to refuse a DID, which is a stronger form of the same guarantee.

func anchorlessRelay(t *testing.T) (mux *http.ServeMux, dataDir string) {
	t.Helper()
	origAnchor, origDomains := cfg.AnchorURL, cfg.Domains
	t.Cleanup(func() { cfg.AnchorURL, cfg.Domains = origAnchor, origDomains })

	cfg.AnchorURL = "" // the whole point
	cfg.Domains = map[string]DomainConfig{"plain.example": {AllowProvision: true}}

	dataDir = t.TempDir()
	mux = http.NewServeMux()
	registerDidUpdate(mux, dataDir)
	return mux, dataDir
}

// A DID sent to an anchorless relay is refused, not accepted-and-ignored. It
// used to answer 204: success for work it had not done and could not do.
func TestAnchorlessRefusesDidUpdate(t *testing.T) {
	mux, dataDir := anchorlessRelay(t)

	token := []byte("a-relay-scoped-token")
	if err := writeAuthHash(dataDir, "plain.example", "alice", jmapserver.HashAuthToken(token)); err != nil {
		t.Fatalf("writeAuthHash: %v", err)
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString(
		[]byte("alice@plain.example:"+base64.StdEncoding.EncodeToString(token)))

	body, _ := json.Marshal(map[string]any{
		"did": "did:dht:abc", "bind_ts": 1784000000, "did_sig": "c2ln",
	})
	req := httptest.NewRequest(http.MethodPut, "/account/did", strings.NewReader(string(body)))
	req.Header.Set("Authorization", basic)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("PUT /account/did on an anchorless relay = %d, want 400 (was 204: a success it could not deliver)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no identity anchor") {
		t.Errorf("body = %q, want it to say why", strings.TrimSpace(w.Body.String()))
	}
}

// The refusal must not depend on the caller having supplied a proof: asking for
// a did_sig here would imply that adding one helps, and it never can — there is
// no anchor to check it against. Same reason /account/provision checks
// anchorlessness before it checks the signature.
func TestAnchorlessRefusesDidUpdateBeforeAskingForAProof(t *testing.T) {
	mux, dataDir := anchorlessRelay(t)

	token := []byte("a-relay-scoped-token")
	if err := writeAuthHash(dataDir, "plain.example", "alice", jmapserver.HashAuthToken(token)); err != nil {
		t.Fatalf("writeAuthHash: %v", err)
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString(
		[]byte("alice@plain.example:"+base64.StdEncoding.EncodeToString(token)))

	body, _ := json.Marshal(map[string]any{"did": "did:dht:abc"}) // no did_sig
	req := httptest.NewRequest(http.MethodPut, "/account/did", strings.NewReader(string(body)))
	req.Header.Set("Authorization", basic)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if strings.Contains(w.Body.String(), "did_sig required") {
		t.Errorf("body = %q — telling an anchorless relay's caller to add a signature points at a door that isn't there", strings.TrimSpace(w.Body.String()))
	}
}

// Unauthenticated callers still get 401 first: anchorlessness is not a reason to
// answer questions about accounts to strangers.
func TestAnchorlessDidUpdateStillRequiresAuth(t *testing.T) {
	mux, _ := anchorlessRelay(t)
	req := httptest.NewRequest(http.MethodPut, "/account/did", strings.NewReader(`{"did":"did:dht:abc"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}
