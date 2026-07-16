package main

import "testing"

func TestVerifyTokenDeterministic(t *testing.T) {
	cfg.DomainVerifySecret = "test-secret"
	t1 := verifyToken("y.jp")
	t2 := verifyToken("y.jp")
	if t1 != t2 {
		t.Fatalf("verifyToken not deterministic: %q vs %q", t1, t2)
	}
	if verifyToken("other.jp") == t1 {
		t.Fatal("different domains must not share a token")
	}
	if len(t1) < 20 {
		t.Fatalf("token suspiciously short: %q", t1)
	}
}

func TestProvisionSecretDeterministic(t *testing.T) {
	cfg.DomainVerifySecret = "test-secret"
	s1 := provisionSecretFor("y.jp")
	s2 := provisionSecretFor("y.jp")
	if s1 != s2 {
		t.Fatalf("provisionSecretFor not deterministic: %q vs %q", s1, s2)
	}
	if provisionSecretFor("other.jp") == s1 {
		t.Fatal("different domains must not share a provision secret")
	}
	if s1 == verifyToken("y.jp") {
		t.Fatal("provision secret must differ from the verify token for the same domain")
	}
}

func TestDomainConfigFallback(t *testing.T) {
	orig := cfg.Domains
	defer func() { cfg.Domains = orig }()
	cfg.Domains = map[string]DomainConfig{"static.example": {AllowProvision: true}}

	dynDomainsMu.Lock()
	dynDomains = map[string]DomainConfig{"custom.example": {AllowProvision: true, DKIMSelector: "default"}}
	dynDomainsMu.Unlock()

	if _, ok := domainConfig("static.example"); !ok {
		t.Error("static domain should resolve")
	}
	if dc, ok := domainConfig("custom.example"); !ok || dc.DKIMSelector != "default" {
		t.Error("dynamic domain should resolve with its stored config")
	}
	if _, ok := domainConfig("unknown.example"); ok {
		t.Error("unregistered domain should not resolve")
	}
}

func TestValidCustomDomain(t *testing.T) {
	valid := []string{"y.jp", "example.com", "sub.example.co.uk", "a-b.example.com"}
	invalid := []string{"", "no-tld", "-leading.com", "trailing-.com", "has space.com", "a/b.com"}
	for _, d := range valid {
		if !validCustomDomain.MatchString(d) {
			t.Errorf("expected %q to be valid", d)
		}
	}
	for _, d := range invalid {
		if validCustomDomain.MatchString(d) {
			t.Errorf("expected %q to be invalid", d)
		}
	}
}
