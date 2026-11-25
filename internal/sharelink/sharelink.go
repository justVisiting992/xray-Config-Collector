// Package sharelink holds the low-level share-link decoding helpers
// that main.go and converter.go both need, so the two root-module
// programs parse the same link the same way. It was extracted after
// an audit found the copies had drifted: converter.go's VMess decode
// never padded its input (unpadded VMess links were silently
// skipped), and the Shadowsocks userinfo logic existed in two
// near-identical forms. The functions here are the union of what the
// copies accepted, mirroring livetest's b64DecodeLoose semantics;
// livetest itself is a separate Go module and keeps its own copy.
//
// Only decoding primitives live here. What each program builds from
// the decoded values (labels, fingerprints, Clash proxies) is policy
// and stays in its own file.
package sharelink

import (
	"encoding/base64"
	"net/url"
	"strings"
)

// DecodeBase64Loose decodes base64 in any of the standard / URL-safe,
// padded / unpadded variants used by share links.
func DecodeBase64Loose(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	var lastErr error
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		} else {
			lastErr = err
		}
	}
	// Last resort: add padding ourselves and try the URL-safe alphabet.
	if m := len(s) % 4; m != 0 {
		if b, err := base64.URLEncoding.DecodeString(s + strings.Repeat("=", 4-m)); err == nil {
			return b, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}

// DecodeSSUserinfo extracts the method and password from an ss://
// userinfo, which comes in two forms:
//
//	plain:   method:password
//	classic: base64(method:password)
//
// ok is false when neither form yields a non-empty method and
// password. A classic base64 userinfo never contains ':', so the
// plain split cannot misfire on it.
func DecodeSSUserinfo(userinfo string) (method, password string, ok bool) {
	// PathUnescape, not QueryUnescape: '+' is a valid base64
	// character in the userinfo and must not become a space.
	if unescaped, err := url.PathUnescape(userinfo); err == nil {
		userinfo = unescaped
	}
	if parts := strings.SplitN(userinfo, ":", 2); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1], true
	}
	decoded, err := DecodeBase64Loose(userinfo)
	if err != nil {
		return "", "", false
	}
	if parts := strings.SplitN(string(decoded), ":", 2); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1], true
	}
	return "", "", false
}

// KnownSSMethod reports whether method is a real Shadowsocks
// encryption method: a known cipher, or at least one containing a
// known cipher family name. Empty and "none" are not encryption.
func KnownSSMethod(method string) bool {
	if method == "" || method == "none" {
		return false
	}
	validMethods := map[string]bool{
		"aes-128-gcm":                   true,
		"aes-256-gcm":                   true,
		"chacha20-ietf-poly1305":        true,
		"chacha20-poly1305":             true,
		"2022-blake3-aes-128-gcm":       true,
		"2022-blake3-aes-256-gcm":       true,
		"2022-blake3-chacha20-poly1305": true,
	}
	if validMethods[method] {
		return true
	}
	// Also allow any method that contains typical cipher names
	// (like "aes-128", "aes-256", "chacha", "2022").
	return strings.Contains(method, "aes") || strings.Contains(method, "chacha") || strings.Contains(method, "2022")
}
