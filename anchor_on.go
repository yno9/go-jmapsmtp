//go:build !noanchor

package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	jmapserver "github.com/yno9/go-jmapserver"
	"github.com/yno9/go-jmapserver/anchor"
)

// This file is jmapsmtp's DID-coordination seam, compiled into the default
// build. `go build -tags noanchor` swaps it for anchor_off.go and the relay
// speaks no DID at all — no claim, no release, no /account/did, no /pkarr. The
// anchor package (and whatever it depends on) is imported ONLY here, so that
// exclusion is a compile-time fact: the noanchor binary links none of it.

func anchorAvailable() bool { return true }

// anchorRef bundles where this relay's anchor is with the secret that proves it
// may write there — the two always travel together and both come from config.
func anchorRef() anchor.Ref {
	return anchor.Ref{URL: cfg.AnchorURL, Token: cfg.AnchorToken}
}

// anchorClaim forwards a DID claim to the anchor. It takes primitives, not
// anchor.BindingProof, so the always-compiled call sites (provision.go) never
// name a type from the anchor package — that is what keeps them linkable in the
// noanchor build, where anchor_off.go supplies the stub.
func anchorClaim(localpart, domain, did, sig string, ts int64, host string) string {
	return anchor.Claim(anchorRef(), localpart, domain, did, anchor.BindingProof{Sig: sig, TS: ts, Host: host})
}

func anchorRelease(localpart, domain string) {
	anchor.Release(anchorRef(), localpart, domain)
}

// registerAnchorRoutes mounts the DID-only HTTP surface. Absent entirely in the
// noanchor build.
func registerAnchorRoutes(mux *http.ServeMux, dataDir string) {
	registerDidUpdate(mux, dataDir)
	// Pkarr/did:dht gateway: this relay no longer runs a DHT node, it forwards
	// to the anchor's (ANCHOR.md decision 1). The route stays because clients
	// derive their gateway URL from their own relay and publish only there.
	anchor.RegisterPkarrProxy(mux, anchorRef())
	registerDrainAnchor(mux, dataDir)
}

// registerDrainAnchor mounts POST /admin/drain-anchor (ADMIN_TOKEN, the same
// credential RegisterAdmin uses): it releases the claim of every address this
// relay hosts, so an operator can turn an anchored relay anchorless without
// stranding its names at the anchor. It must be driven while anchor_url is still
// set — releasing is a call TO the anchor — so the flow is: POST here, confirm
// no failures, then remove anchor_url. There is no drain route in the noanchor
// build: this whole file is compiled out, and a relay with no anchor has nothing
// to drain. The reverse migration needs no endpoint — see anchor.Drain.
func registerDrainAnchor(mux *http.ServeMux, dataDir string) {
	mux.Handle("/admin/drain-anchor", jmapserver.BearerAuth(os.Getenv("ADMIN_TOKEN"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.AnchorURL == "" {
			http.Error(w, "relay is not anchored — nothing to drain", http.StatusBadRequest)
			return
		}
		refs := jmapserver.ListProvisioned(dataDir)
		names := make([]anchor.Name, len(refs))
		for i, ref := range refs {
			names[i] = anchor.Name{Localpart: ref.Localpart, Domain: ref.Domain}
		}
		rep := anchor.Drain(anchorRef(), names)
		log.Printf("[drain] anchor %s: released %d, failed %d", cfg.AnchorURL, len(rep.Released), len(rep.Failed))
		w.Header().Set("Content-Type", "application/json")
		// A partial drain is a failure to report loudly: any Failed name may still
		// hold a claim, so it is NOT yet safe to go anchorless.
		if len(rep.Failed) > 0 {
			w.WriteHeader(http.StatusBadGateway)
		}
		json.NewEncoder(w).Encode(rep) //nolint:errcheck
	})))
}

// checkAnchorConfig refuses to start an anchored relay that cannot authenticate
// itself. There is deliberately no "just warn and carry on": an anchor whose
// writes are unauthenticated lets anyone on the internet claim a name nobody
// holds, or release somebody else's claim and take it, DNS record and all. A
// silent fallback here would be exactly the *quiet* security degradation
// src/did/freshness.ts refuses for the same reason — it also has no default and
// throws instead.
func checkAnchorConfig() {
	if cfg.AnchorURL != "" && cfg.AnchorToken == "" {
		log.Fatalf("config: anchor_url is set but anchor_token is empty — the anchor's writes would be unauthenticated (set it to the anchor's relay_token)")
	}
}

// registerDidUpdate exposes PUT /account/did (Basic Auth) so an already-
// provisioned account can register its DID after the fact — DID.md's "lazy
// migration on next login" for identities that predate DID support. The target
// comes only from the authenticated credential, so this can only ever fill in /
// confirm the DID for the caller's own identity, never claim someone else's.
// Mirrors go-jmapap's registerDidUpdate, but forwards to the anchor over HTTP
// (jmapsmtp doesn't host the registry itself).
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
		switch anchorClaim(localpart, domain, body.DID, body.DIDSig, body.BindTS, r.Host) {
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
