package main

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var pgpEntity *openpgp.Entity

func loadPGPEntity() {
	pgpKey := os.Getenv("BISET_PGP_KEY")
	if pgpKey == "" {
		return
	}
	block, err := armor.Decode(bytes.NewBufferString(pgpKey))
	if err != nil {
		return
	}
	entities, err := openpgp.ReadKeyRing(block.Body)
	if err != nil || len(entities) == 0 {
		return
	}
	pgpEntity = entities[0]
}

// injectChatVersionHeader adds Chat-Version: 1.0 to outer headers so DeltaChat
// (and compatible clients) recognize the message as chat-type and apply Autocrypt.
func injectChatVersionHeader(raw []byte) []byte {
	if bytes.Contains(raw, []byte("\nChat-Version:")) || bytes.HasPrefix(raw, []byte("Chat-Version:")) {
		return raw
	}
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return raw
	}
	var out bytes.Buffer
	out.Write(raw[:idx+2])
	out.WriteString("Chat-Version: 1.0\r\n")
	out.Write(raw[idx+2:])
	return out.Bytes()
}

// injectEntityAutocryptHeader injects an Autocrypt: header using a specific entity.
func injectEntityAutocryptHeader(raw []byte, fromEmail string, entity *openpgp.Entity) []byte {
	var pubBuf bytes.Buffer
	if err := entity.Serialize(&pubBuf); err != nil {
		return raw
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubBuf.Bytes())
	acHeader := "Autocrypt: addr=" + fromEmail + "; prefer-encrypt=mutual; keydata=" + pubB64 + "\r\n"
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return raw
	}
	var out bytes.Buffer
	out.Write(raw[:idx+2])
	out.WriteString(acHeader)
	out.Write(raw[idx+2:])
	return out.Bytes()
}

// injectAutocryptHeader injects an Autocrypt: header into a raw RFC 5322 message.
func injectAutocryptHeader(raw []byte, fromEmail string) []byte {
	if pgpEntity == nil {
		return raw
	}
	var pubBuf bytes.Buffer
	if err := pgpEntity.Serialize(&pubBuf); err != nil {
		return raw
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubBuf.Bytes())
	acHeader := "Autocrypt: addr=" + fromEmail + "; prefer-encrypt=mutual; keydata=" + pubB64 + "\r\n"

	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return raw
	}
	var out bytes.Buffer
	out.Write(raw[:idx+2]) // headers up to last \r\n
	out.WriteString(acHeader)
	out.Write(raw[idx+2:]) // \r\n + body
	return out.Bytes()
}

// loadPeerEntity loads a stored peer OpenPGP public key from vault.
func loadPeerEntity(vaultDir, addr string) *openpgp.Entity {
	path := peerKeyPath(vaultDir, addr)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(b))
	if err != nil || len(entities) == 0 {
		return nil
	}
	return entities[0]
}

func peerKeyPath(vaultDir, addr string) string {
	return vaultDir + "/.autocrypt/" + strings.ToLower(addr) + ".pgp"
}

// parseAutocryptHeader extracts addr and keydata from an Autocrypt header value.
func parseAutocryptHeader(header string) (addr, keydata string) {
	for _, part := range strings.Split(header, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch k {
		case "addr":
			addr = v
		case "keydata":
			keydata = v
		}
	}
	return
}

// storePeerKey saves an Autocrypt public key for addr into dataDir/domain/peers/<addr>.pgp.
func storePeerKey(dataDir, domain, addr, keydata string) {
	// Autocrypt keydata may be folded (whitespace-wrapped) per RFC 5322.
	stripped := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, keydata)
	raw, err := base64.StdEncoding.DecodeString(stripped)
	if err != nil {
		log.Printf("[autocrypt] base64 decode failed for %s: %v", addr, err)
		return
	}
	if _, err := openpgp.ReadKeyRing(bytes.NewReader(raw)); err != nil {
		log.Printf("[autocrypt] invalid PGP key for %s: %v", addr, err)
		return
	}
	dir := dataDir + "/" + domain + "/peers"
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("[autocrypt] mkdir failed: %v", err)
		return
	}
	path := dir + "/" + strings.ToLower(addr) + ".pgp"
	if err := os.WriteFile(path, raw, 0600); err != nil {
		log.Printf("[autocrypt] write failed: %v", err)
		return
	}
	log.Printf("[autocrypt] stored key for %s in %s/peers", addr, domain)
}

// loadPeerKeyForDomain loads a stored peer public key from dataDir/domain/peers/<addr>.pgp.
func loadPeerKeyForDomain(dataDir, domain, addr string) *openpgp.Entity {
	path := dataDir + "/" + domain + "/peers/" + strings.ToLower(addr) + ".pgp"
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(b))
	if err != nil || len(entities) == 0 {
		return nil
	}
	return entities[0]
}

// loadPeerPrefer returns the stored prefer-encrypt value for a peer address.
func loadPeerPrefer(vaultDir, addr string) string {
	path := vaultDir + "/.autocrypt/" + strings.ToLower(addr) + ".prefer"
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// encryptMessage encrypts the body of a raw RFC 5322 message with the
// recipient's stored OpenPGP public key (inline PGP / armored).
// Only encrypts if the peer advertised prefer-encrypt=mutual.
func encryptMessage(raw []byte, vaultDir, toAddr string) []byte {
	if vaultDir == "" {
		return raw
	}
	if loadPeerPrefer(vaultDir, toAddr) != "mutual" {
		return raw
	}
	peer := loadPeerEntity(vaultDir, toAddr)
	if peer == nil {
		return raw
	}
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return raw
	}
	plaintext := raw[idx+4:]
	encrypted, err := pgpEncryptInline(plaintext, peer)
	if err != nil {
		return raw
	}
	var out bytes.Buffer
	out.Write(raw[:idx+4])
	out.Write(encrypted)
	return out.Bytes()
}

// pgpEncryptInline encrypts plaintext bytes for one or more recipients (no signing).
// Used for storage encryption (armored PGP MESSAGE, not MIME-wrapped).
func pgpEncryptInline(plaintext []byte, recipients ...*openpgp.Entity) ([]byte, error) {
	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	cfg := &packet.Config{
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}
	list := openpgp.EntityList{}
	for _, r := range recipients {
		if r != nil {
			list = append(list, r)
		}
	}
	w, err := openpgp.Encrypt(aw, list, nil, nil, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	w.Close()
	aw.Close()
	return buf.Bytes(), nil
}

// pgpMIMEWrapInline takes a raw RFC 5322 message whose body is an inline PGP
// armored block (already encrypted/signed by the client) and rewraps the body
// in RFC 3156 multipart/encrypted format for SMTP transport (DeltaChat compat).
func pgpMIMEWrapInline(rawMsg []byte) ([]byte, error) {
	sep := []byte("\r\n\r\n")
	headerEnd := bytes.Index(rawMsg, sep)
	if headerEnd < 0 {
		return nil, fmt.Errorf("no header/body separator")
	}
	origHeaders := string(rawMsg[:headerEnd])
	body := rawMsg[headerEnd+4:]

	startMarker := []byte("-----BEGIN PGP MESSAGE-----")
	endMarker := []byte("-----END PGP MESSAGE-----")
	start := bytes.Index(body, startMarker)
	end := bytes.Index(body, endMarker)
	if start < 0 || end < 0 {
		return nil, fmt.Errorf("no PGP block in body")
	}
	pgpBlock := body[start : end+len(endMarker)]

	h := sha1.Sum(pgpBlock)
	boundary := fmt.Sprintf("biset-pgp-%x", h[:6])

	var out bytes.Buffer
	for _, line := range strings.Split(origHeaders, "\r\n") {
		k := strings.ToLower(strings.SplitN(line, ":", 2)[0])
		if k == "content-type" || k == "content-transfer-encoding" {
			continue
		}
		out.WriteString(line + "\r\n")
	}
	out.WriteString(`Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="` + boundary + `"` + "\r\n")
	out.WriteString("\r\n")
	out.WriteString("--" + boundary + "\r\n")
	out.WriteString("Content-Type: application/pgp-encrypted\r\n\r\n")
	out.WriteString("Version: 1\r\n")
	out.WriteString("\r\n--" + boundary + "\r\n")
	out.WriteString("Content-Type: application/octet-stream\r\n\r\n")
	out.Write(bytes.ReplaceAll(pgpBlock, []byte("\n"), []byte("\r\n")))
	out.WriteString("\r\n--" + boundary + "--\r\n")
	return out.Bytes(), nil
}

// pgpEncryptMIME encrypts rawMsg as PGP/MIME (RFC 3156 multipart/encrypted).
// signer is the sender's entity (used for signing + self-encrypt); may be nil.
func pgpEncryptMIME(rawMsg []byte, recipient *openpgp.Entity, signer *openpgp.Entity) ([]byte, error) {
	sep := []byte("\r\n\r\n")
	headerEnd := bytes.Index(rawMsg, sep)
	if headerEnd < 0 {
		return nil, fmt.Errorf("no header/body separator")
	}
	origHeaders := string(rawMsg[:headerEnd])
	body := rawMsg[headerEnd+4:]

	// Build inner MIME: Content-Type, Content-Transfer-Encoding, Chat-Version.
	var innerBuf bytes.Buffer
	hasChatVersion := false
	for _, line := range strings.Split(origHeaders, "\r\n") {
		k := strings.ToLower(strings.SplitN(line, ":", 2)[0])
		if k == "content-type" || k == "content-transfer-encoding" || k == "chat-version" || k == "chat-user-avatar" {
			innerBuf.WriteString(line + "\r\n")
			if k == "chat-version" {
				hasChatVersion = true
			}
		}
	}
	if !hasChatVersion {
		innerBuf.WriteString("Chat-Version: 1\r\n")
	}
	innerBuf.WriteString("\r\n")
	innerBuf.Write(body)

	// Encrypt inner MIME as PGP armor.
	// signer must have a private key to sign; pubkey-only entities are added as recipients only.
	var cipherBuf bytes.Buffer
	aw, err := armor.Encode(&cipherBuf, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	cfg := &packet.Config{
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}
	recipients := openpgp.EntityList{recipient}
	var actualSigner *openpgp.Entity
	if signer != nil {
		recipients = append(recipients, signer)
		// Only sign if private key is available.
		if signer.PrivateKey != nil {
			actualSigner = signer
		}
	}
	w, err := openpgp.Encrypt(aw, recipients, actualSigner, nil, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(innerBuf.Bytes()); err != nil {
		return nil, err
	}
	w.Close()
	aw.Close()

	// Build boundary.
	h := sha1.Sum(body)
	boundary := fmt.Sprintf("biset-pgp-%x", h[:6])

	// Rewrite outer headers: replace Content-Type, drop Content-Transfer-Encoding.
	var out bytes.Buffer
	for _, line := range strings.Split(origHeaders, "\r\n") {
		k := strings.ToLower(strings.SplitN(line, ":", 2)[0])
		if k == "content-type" || k == "content-transfer-encoding" {
			continue
		}
		out.WriteString(line + "\r\n")
	}
	out.WriteString(`Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="` + boundary + `"` + "\r\n")
	out.WriteString("\r\n")
	out.WriteString("--" + boundary + "\r\n")
	out.WriteString("Content-Type: application/pgp-encrypted\r\n\r\n")
	out.WriteString("Version: 1\r\n")
	out.WriteString("\r\n--" + boundary + "\r\n")
	out.WriteString("Content-Type: application/octet-stream\r\n\r\n")
	out.WriteString(strings.ReplaceAll(cipherBuf.String(), "\n", "\r\n"))
	out.WriteString("\r\n--" + boundary + "--\r\n")
	return out.Bytes(), nil
}
