package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The vectors below are the cases the parser audit found the three
// parsers disagreeing on. main.go and converter.go now share
// internal/sharelink for them; these tests pin main.go's side.

func TestVMessFingerprintUnpadded(t *testing.T) {
	jsonBody := `{"add":"example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":0,"net":"ws","tls":"tls","host":"cdn.example.com","path":"/ray","sni":"sni.example.com"}`
	unpadded := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(jsonBody))
	fp := getConfigFingerprint(unpadded)
	if fp == "" {
		t.Fatal("unpadded VMess produced empty fingerprint")
	}
	if !strings.HasPrefix(fp, "vmess|example.com|443|") {
		t.Errorf("fingerprint = %q", fp)
	}
	// Same config, padded standard encoding: same fingerprint.
	padded := "vmess://" + base64.StdEncoding.EncodeToString([]byte(jsonBody))
	if got := getConfigFingerprint(padded); got != fp {
		t.Errorf("padded fingerprint %q != unpadded %q", got, fp)
	}
}

func TestIsValidShadowsocksForms(t *testing.T) {
	classic := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret")) + "@1.2.3.4:8388"
	if !isValidShadowsocks(classic) {
		t.Error("classic base64 form rejected")
	}
	if !isValidShadowsocks("ss://aes-256-gcm:secret@1.2.3.4:8388") {
		t.Error("plain form rejected")
	}
	if isValidShadowsocks("ss://justapassword@1.2.3.4:8388") {
		t.Error("method-less userinfo accepted")
	}
	unknown := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("rc4-md5:secret")) + "@1.2.3.4:8388"
	if isValidShadowsocks(unknown) {
		t.Error("rc4-md5 accepted (not a known method)")
	}
}

func TestExtractHostVMessUnpadded(t *testing.T) {
	jsonBody := `{"add":"example.org","port":"443","id":"x"}`
	link := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(jsonBody))
	if got := extractHost(link); got != "example.org" {
		t.Errorf("extractHost = %q, want example.org", got)
	}
}
