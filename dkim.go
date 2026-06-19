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

var dkimKey *rsa.PrivateKey

// loadOrGenerateDKIMKey loads <dir>/key.pem if it exists, otherwise generates
// a new RSA 2048 key, persists it, and uses it for DKIM signing.
func loadOrGenerateDKIMKey(dir string) {
	keyPath := filepath.Join(dir, "key.pem")
	if b, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(b)
		if block != nil {
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if rk, ok := k.(*rsa.PrivateKey); ok {
					dkimKey = rk
					return
				}
			}
		}
	}

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return
	}
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return
	}
	pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}) //nolint:errcheck
	f.Close()
	dkimKey = k
}

// signDKIM adds a DKIM-Signature header to a raw RFC 5322 message.
// Returns the original message unchanged if signing is not possible.
func signDKIM(raw []byte, domain, selector string) []byte {
	if dkimKey == nil || domain == "" || selector == "" {
		return raw
	}
	opts := &dkim.SignOptions{
		Domain:                 domain,
		Selector:               selector,
		Signer:                 dkimKey,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             []string{"From", "To", "Subject", "Date", "Message-Id", "Content-Type"},
	}
	var out bytes.Buffer
	if err := dkim.Sign(&out, strings.NewReader(string(raw)), opts); err != nil {
		return raw
	}
	return out.Bytes()
}

// DKIMPublicKeyRecord returns the DNS TXT record value for the DKIM public key.
// Publish at: <selector>._domainkey.<domain>  IN TXT  "<value>"
func DKIMPublicKeyRecord() string {
	if dkimKey == nil {
		return ""
	}
	pub, err := x509.MarshalPKIXPublicKey(&dkimKey.PublicKey)
	if err != nil {
		return ""
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)
}

// writeDKIMRecordFile writes the DNS TXT record to <dir>/dkim-dns.txt
func writeDKIMRecordFile(dir, selector, domain string) {
	r := DKIMPublicKeyRecord()
	if r == "" || dir == "" {
		return
	}
	content := fmt.Sprintf("# Add this TXT record to DNS:\n# %s._domainkey.%s\n%s\n", selector, domain, r)
	os.WriteFile(filepath.Join(dir, "dkim-dns.txt"), []byte(content), 0644) //nolint:errcheck
}
