package cryptenv

import (
	"bytes"
	"testing"
)

// Use fast KDF params throughout tests to keep runtime manageable.
func fastEnv(t *testing.T, pw string) (*Envelope, []byte, []byte) {
	t.Helper()
	prev := DefaultKDF
	DefaultKDF = KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}
	t.Cleanup(func() { DefaultKDF = prev })
	env, auth, kek, err := NewEnvelope(pw)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	return env, auth, kek
}

func TestNewEnvelope_RoundTrip(t *testing.T) {
	env, auth, kek := fastEnv(t, "correct horse battery staple")
	gotAuth, gotKEK, err := env.Unseal("correct horse battery staple")
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(auth, gotAuth) {
		t.Errorf("auth_token mismatch")
	}
	if !bytes.Equal(kek, gotKEK) {
		t.Errorf("kek mismatch")
	}
}

func TestUnseal_WrongPassword(t *testing.T) {
	env, _, _ := fastEnv(t, "correct")
	if _, _, err := env.Unseal("wrong"); err == nil {
		t.Fatal("Unseal: expected error on wrong password")
	}
}

func TestRewrap_PreservesDerivedKeys(t *testing.T) {
	env, auth1, kek1 := fastEnv(t, "old-pw")
	env2, err := env.Rewrap("old-pw", "new-pw")
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	auth2, kek2, err := env2.Unseal("new-pw")
	if err != nil {
		t.Fatalf("Unseal after rewrap: %v", err)
	}
	if !bytes.Equal(auth1, auth2) {
		t.Errorf("auth_token changed after rewrap; expected stable")
	}
	if !bytes.Equal(kek1, kek2) {
		t.Errorf("kek changed after rewrap; expected stable")
	}
}

func TestRewrap_OldPasswordStopsWorking(t *testing.T) {
	env, _, _ := fastEnv(t, "old-pw")
	env2, err := env.Rewrap("old-pw", "new-pw")
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	if _, _, err := env2.Unseal("old-pw"); err == nil {
		t.Fatal("old password should not unseal new envelope")
	}
}

func TestRewrap_WrongOldPassword(t *testing.T) {
	env, _, _ := fastEnv(t, "old-pw")
	if _, err := env.Rewrap("wrong", "new-pw"); err == nil {
		t.Fatal("Rewrap should fail with wrong old password")
	}
}

func TestVerifyAuth(t *testing.T) {
	env, auth, _ := fastEnv(t, "pw")
	if !env.VerifyAuth(auth) {
		t.Error("VerifyAuth should accept the correct token")
	}
	bad := make([]byte, len(auth))
	copy(bad, auth)
	bad[0] ^= 0xff
	if env.VerifyAuth(bad) {
		t.Error("VerifyAuth should reject a tampered token")
	}
}

func TestSerialization(t *testing.T) {
	env, auth, kek := fastEnv(t, "pw")
	b, err := env.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	got, err := FromBytes(b)
	if err != nil {
		t.Fatalf("FromBytes: %v", err)
	}
	gotAuth, gotKEK, err := got.Unseal("pw")
	if err != nil {
		t.Fatalf("Unseal after roundtrip: %v", err)
	}
	if !bytes.Equal(auth, gotAuth) || !bytes.Equal(kek, gotKEK) {
		t.Error("derived keys differ after JSON roundtrip")
	}
}

func TestNewEnvelope_RandomnessAcrossCalls(t *testing.T) {
	e1, a1, k1 := fastEnv(t, "pw")
	e2, a2, k2 := fastEnv(t, "pw")
	if bytes.Equal(e1.Salt, e2.Salt) {
		t.Error("salt should be unique per envelope")
	}
	if bytes.Equal(a1, a2) || bytes.Equal(k1, k2) {
		t.Error("master_secret (and derived keys) should differ across envelopes")
	}
}

func TestEmptyPassword(t *testing.T) {
	if _, _, _, err := NewEnvelope(""); err == nil {
		t.Error("NewEnvelope should reject empty password")
	}
}
