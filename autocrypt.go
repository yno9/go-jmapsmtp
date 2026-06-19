package main

import (
	"bytes"
	"crypto"
	"encoding/base64"
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

func pgpEncryptInline(plaintext []byte, recipient *openpgp.Entity) ([]byte, error) {
	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	cfg := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
	}
	recipients := openpgp.EntityList{recipient}
	var signer *openpgp.Entity
	if pgpEntity != nil {
		signer = pgpEntity
	}
	w, err := openpgp.Encrypt(aw, recipients, signer, nil, cfg)
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
