// Package cryptenv implements a password-derived key envelope for jmapsmtp.
//
// Design (KEK wrap):
//
//	password ──Argon2id(salt)──> wrap_key
//	wrap_key ──AES-GCM-decrypt──> master_secret (random 32B, generated once)
//	master_secret ──HKDF("auth")──> auth_token  (presented to server)
//	master_secret ──HKDF("enc") ──> KEK         (encrypts PGP keys etc.)
//
// Password rotation rewraps master_secret only; auth_token and KEK are stable.
package cryptenv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	masterSecretSize = 32
	saltSize         = 16
	wrapKeySize      = 32
	aesNonceSize     = 12
	authTokenSize    = 32
	kekSize          = 32

	currentVersion = 1
)

// HKDF context strings — change → backwards incompatible.
var (
	hkdfInfoAuth = []byte("biset-jmapsmtp/auth/v1")
	hkdfInfoKEK  = []byte("biset-jmapsmtp/enc/v1")
)

// KDFParams configures Argon2id. Time/Memory/Threads follow OWASP guidance.
type KDFParams struct {
	Time    uint32 `json:"t"` // iterations
	Memory  uint32 `json:"m"` // KiB
	Threads uint8  `json:"p"` // lanes
}

// DefaultKDF — OWASP-recommended minimum for interactive logins.
var DefaultKDF = KDFParams{Time: 3, Memory: 64 * 1024, Threads: 4}

// Envelope is the per-account password-derived envelope stored server-side.
// Bytes fields are base64-encoded in JSON via encoding/json default.
type Envelope struct {
	Version       int       `json:"v"`
	Salt          []byte    `json:"salt"`
	KDF           KDFParams `json:"kdf"`
	WrappedSecret []byte    `json:"wrapped_secret"` // nonce(12) || ciphertext || tag
	AuthTokenHash []byte    `json:"auth_token_hash"` // sha256(auth_token)
}

// NewEnvelope generates a fresh master_secret, seals it with password,
// and returns the envelope along with the derived auth_token and KEK.
func NewEnvelope(password string) (*Envelope, []byte, []byte, error) {
	if password == "" {
		return nil, nil, nil, errors.New("cryptenv: empty password")
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, nil, fmt.Errorf("cryptenv: salt: %w", err)
	}
	masterSecret := make([]byte, masterSecretSize)
	if _, err := rand.Read(masterSecret); err != nil {
		return nil, nil, nil, fmt.Errorf("cryptenv: master: %w", err)
	}
	wrapKey := deriveWrapKey(password, salt, DefaultKDF)
	wrapped, err := aesGCMSeal(wrapKey, masterSecret)
	if err != nil {
		return nil, nil, nil, err
	}
	authToken, kek := deriveAuthAndKEK(masterSecret)
	env := &Envelope{
		Version:       currentVersion,
		Salt:          salt,
		KDF:           DefaultKDF,
		WrappedSecret: wrapped,
		AuthTokenHash: hashAuthToken(authToken),
	}
	return env, authToken, kek, nil
}

// Unseal recovers auth_token and KEK from the envelope using password.
// Returns an error on wrong password (AEAD tag mismatch).
func (e *Envelope) Unseal(password string) ([]byte, []byte, error) {
	if e.Version != currentVersion {
		return nil, nil, fmt.Errorf("cryptenv: unsupported version %d", e.Version)
	}
	wrapKey := deriveWrapKey(password, e.Salt, e.KDF)
	masterSecret, err := aesGCMOpen(wrapKey, e.WrappedSecret)
	if err != nil {
		return nil, nil, errors.New("cryptenv: wrong password")
	}
	authToken, kek := deriveAuthAndKEK(masterSecret)
	return authToken, kek, nil
}

// Rewrap changes the password without rotating master_secret. The returned
// envelope is a fresh value; the caller is responsible for persisting it.
// auth_token and KEK derived from the new envelope are identical to those
// derived from the old one.
func (e *Envelope) Rewrap(oldPw, newPw string) (*Envelope, error) {
	if newPw == "" {
		return nil, errors.New("cryptenv: empty new password")
	}
	oldKey := deriveWrapKey(oldPw, e.Salt, e.KDF)
	masterSecret, err := aesGCMOpen(oldKey, e.WrappedSecret)
	if err != nil {
		return nil, errors.New("cryptenv: wrong old password")
	}
	newSalt := make([]byte, saltSize)
	if _, err := rand.Read(newSalt); err != nil {
		return nil, fmt.Errorf("cryptenv: salt: %w", err)
	}
	newKey := deriveWrapKey(newPw, newSalt, DefaultKDF)
	wrapped, err := aesGCMSeal(newKey, masterSecret)
	if err != nil {
		return nil, err
	}
	authToken, _ := deriveAuthAndKEK(masterSecret)
	return &Envelope{
		Version:       currentVersion,
		Salt:          newSalt,
		KDF:           DefaultKDF,
		WrappedSecret: wrapped,
		AuthTokenHash: hashAuthToken(authToken),
	}, nil
}

// VerifyAuth performs a constant-time check of the presented auth_token
// against the stored hash. master_secret is never reconstructed here —
// the server uses this without holding the password.
func (e *Envelope) VerifyAuth(authToken []byte) bool {
	want := hashAuthToken(authToken)
	return subtle.ConstantTimeCompare(want, e.AuthTokenHash) == 1
}

// MarshalJSON / UnmarshalJSON use the default []byte→base64 encoding.

func (e *Envelope) Bytes() ([]byte, error) { return json.Marshal(e) }

func FromBytes(b []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// ── internals ─────────────────────────────────────────────────────────────

func deriveWrapKey(password string, salt []byte, p KDFParams) []byte {
	return argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, wrapKeySize)
}

func deriveAuthAndKEK(masterSecret []byte) (authToken, kek []byte) {
	authToken = hkdfExtract(masterSecret, hkdfInfoAuth, authTokenSize)
	kek = hkdfExtract(masterSecret, hkdfInfoKEK, kekSize)
	return
}

func hkdfExtract(secret, info []byte, n int) []byte {
	r := hkdf.New(sha256.New, secret, nil, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

func hashAuthToken(authToken []byte) []byte {
	h := sha256.Sum256(authToken)
	return h[:]
}

func aesGCMSeal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptenv: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptenv: gcm: %w", err)
	}
	nonce := make([]byte, aesNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cryptenv: nonce: %w", err)
	}
	out := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, out...), nil
}

func aesGCMOpen(key, sealed []byte) ([]byte, error) {
	if len(sealed) < aesNonceSize {
		return nil, errors.New("cryptenv: sealed too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptenv: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptenv: gcm: %w", err)
	}
	nonce, ct := sealed[:aesNonceSize], sealed[aesNonceSize:]
	return aead.Open(nil, nonce, ct, nil)
}
