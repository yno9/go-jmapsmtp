//go:build noanchor

package main

import (
	"log"
	"net/http"
)

// This file replaces anchor_on.go under `go build -tags noanchor`: a pure JMAP
// relay that speaks no DID. It imports nothing from the anchor package, so that
// package and everything it pulls in stay out of the binary. Every anchor
// operation degrades to "not supported here" — plain JMAP accounts are wholly
// unaffected, since they never touched the anchor to begin with.

func anchorAvailable() bool { return false }

// anchorClaim can only refuse: this binary has no anchor to prove a DID against.
// Callers gate on anchorAvailable() before reaching a real claim, so in practice
// this returns for defence in depth; "unsupported" is deliberately none of the
// verdicts the real Claim yields.
func anchorClaim(localpart, domain, did, sig string, ts int64, host string) string {
	return "unsupported"
}

func anchorRelease(localpart, domain string) {}

// registerAnchorRoutes mounts nothing: no /account/did, no /pkarr gateway.
func registerAnchorRoutes(mux *http.ServeMux, dataDir string) {}

// checkAnchorConfig warns rather than fatals: a config carrying anchor_url built
// into the noanchor binary is a wrong-binary mistake, but a survivable one — the
// relay simply ignores it and runs plain JMAP. Silence would let the operator
// believe DID coordination was on when nothing was compiled to do it.
func checkAnchorConfig() {
	if cfg.AnchorURL != "" {
		log.Printf("config: anchor_url is set but this binary was built with -tags noanchor — DID coordination is disabled, running as a plain JMAP relay")
	}
}
