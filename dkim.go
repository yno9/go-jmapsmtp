package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

var dkimKeys = map[string]*rsa.PrivateKey{}

func loadOrGenerateDKIMKeys(dir string) {
	for domain, domCfg := range cfg.Domains {
		keyDir := filepath.Join(dir, "data", domain)
		os.MkdirAll(keyDir, 0700) //nolint:errcheck
		key := loadOrGenerateDKIMKey(keyDir)
		if key == nil {
			continue
		}
		dkimKeys[domain] = key
		selector := domCfg.DKIMSelector
		if selector == "" {
			selector = "default"
		}
		writeDKIMRecordFile(keyDir, selector, domain)
	}
}

func loadOrGenerateDKIMKey(dir string) *rsa.PrivateKey {
	keyPath := filepath.Join(dir, "key.pem")
	if b, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(b)
		if block != nil {
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if rk, ok := k.(*rsa.PrivateKey); ok {
					return rk
				}
			}
		}
	}

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil
	}
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil
	}
	pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}) //nolint:errcheck
	f.Close()
	return k
}

func signDKIMForDomain(raw []byte, fromDomain string) []byte {
	key, ok := dkimKeys[fromDomain]
	if !ok {
		return raw
	}
	domCfg, _ := domainConfig(fromDomain)
	selector := domCfg.DKIMSelector
	if selector == "" {
		selector = "default"
	}
	opts := &dkim.SignOptions{
		Domain:                 fromDomain,
		Selector:               selector,
		Signer:                 key,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             []string{"From", "To", "Cc", "Subject", "Date", "Message-Id", "Content-Type"},
	}
	var out bytes.Buffer
	if err := dkim.Sign(&out, strings.NewReader(string(raw)), opts); err != nil {
		return raw
	}
	return out.Bytes()
}

func dkimPublicKeyRecord(key *rsa.PrivateKey) string {
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return ""
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)
}

func writeDKIMRecordFile(dir, selector, domain string) {
	key, ok := dkimKeys[domain]
	if !ok || dir == "" {
		return
	}
	r := dkimPublicKeyRecord(key)
	if r == "" {
		return
	}
	content := fmt.Sprintf("# Add this TXT record to DNS:\n# %s._domainkey.%s\n%s\n", selector, domain, r)
	os.WriteFile(filepath.Join(dir, "dkim-dns.txt"), []byte(content), 0644) //nolint:errcheck
}
