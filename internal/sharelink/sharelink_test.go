package sharelink

import (
	"encoding/base64"
	"testing"
)

func TestDecodeBase64LooseVariants(t *testing.T) {
	payload := []byte(`{"add":"example.com","port":"443"}`)
	variants := map[string]string{
		"std padded":   base64.StdEncoding.EncodeToString(payload),
		"std unpadded": base64.RawStdEncoding.EncodeToString(payload),
		"url padded":   base64.URLEncoding.EncodeToString(payload),
		"url unpadded": base64.RawURLEncoding.EncodeToString(payload),
	}
	for name, enc := range variants {
		got, err := DecodeBase64Loose(enc)
		if err != nil {
			t.Errorf("%s: %v", name, err)
		} else if string(got) != string(payload) {
			t.Errorf("%s: got %q", name, got)
		}
	}
	if _, err := DecodeBase64Loose("!!!not base64!!!"); err == nil {
		t.Error("invalid input: expected error")
	}
}

func TestDecodeSSUserinfo(t *testing.T) {
	classic := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret"))
	classicStd := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:p@ss"))
	cases := []struct {
		name, in, method, password string
		ok                         bool
	}{
		{"plain", "aes-256-gcm:secret", "aes-256-gcm", "secret", true},
		{"plain password with colon", "aes-256-gcm:a:b", "aes-256-gcm", "a:b", true},
		{"classic url-safe unpadded", classic, "aes-256-gcm", "secret", true},
		{"classic std padded", classicStd, "chacha20-ietf-poly1305", "p@ss", true},
		{"empty password plain", "aes-256-gcm:", "", "", false},
		{"no colon not base64 pair", "justapassword", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, c := range cases {
		m, p, ok := DecodeSSUserinfo(c.in)
		if ok != c.ok || m != c.method || p != c.password {
			t.Errorf("%s: got (%q, %q, %v), want (%q, %q, %v)", c.name, m, p, ok, c.method, c.password, c.ok)
		}
	}
}

func TestKnownSSMethod(t *testing.T) {
	for _, m := range []string{"aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-256-gcm", "aes-256-cfb", "xchacha20-ietf-poly1305"} {
		if !KnownSSMethod(m) {
			t.Errorf("%q should be known", m)
		}
	}
	for _, m := range []string{"", "none", "rc4-md5", "plain"} {
		if KnownSSMethod(m) {
			t.Errorf("%q should not be known", m)
		}
	}
}
