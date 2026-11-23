package livetest

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// The expected values below were verified against the repository's
// Country.mmdb itself (not assumed): 8.8.8.8 resolves to US /
// "United States" and 193.0.14.129 to NL / "The Netherlands", which the
// label conventions normalize to "USA" and "Netherlands".
func TestCountryLabelAgainstRealDB(t *testing.T) {
	g, err := OpenGeoLabeler("../Country.mmdb")
	if err != nil {
		t.Fatalf("OpenGeoLabeler: %v", err)
	}
	defer g.Close()

	cases := map[string]string{
		"8.8.8.8":      "🇺🇸 USA",
		"193.0.14.129": "🇳🇱 Netherlands",
	}
	for ip, want := range cases {
		got, ok := g.CountryLabel(ip)
		if !ok {
			t.Errorf("CountryLabel(%q): ok = false, want %q", ip, want)
			continue
		}
		if got != want {
			t.Errorf("CountryLabel(%q) = %q, want %q", ip, got, want)
		}
	}

	for _, ip := range []string{"", "not-an-ip", "192.168.1.1", "127.0.0.1", "203.0.113.7"} {
		if label, ok := g.CountryLabel(ip); ok {
			t.Errorf("CountryLabel(%q) = %q, true; want ok = false", ip, label)
		}
	}
}

func TestRewriteRemarkFragment(t *testing.T) {
	link := sampleLinks["vless"]
	label := "🇩🇪 Germany | VLESS"
	got := RewriteRemark(link, label)

	before, _, _ := strings.Cut(link, "#")
	want := before + "#" + label
	if got != want {
		t.Errorf("RewriteRemark(vless) =\n%q\nwant\n%q", got, want)
	}
}

func TestRewriteRemarkVMessPS(t *testing.T) {
	link := sampleLinks["vmess"]
	label := "🇨🇦 Canada | VMESS"
	got := RewriteRemark(link, label)

	if !strings.HasPrefix(got, "vmess://") {
		t.Fatalf("rewritten vmess link lost its scheme: %q", got)
	}
	payload := strings.TrimPrefix(got, "vmess://")
	if i := len(payload) % 4; i != 0 {
		payload += strings.Repeat("=", 4-i)
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(payload)
		if err != nil {
			t.Fatalf("decode rewritten vmess payload: %v", err)
		}
	}
	var v map[string]any
	if err := json.Unmarshal(decoded, &v); err != nil {
		t.Fatalf("unmarshal rewritten vmess payload: %v", err)
	}
	if v["ps"] != label {
		t.Errorf("ps = %q, want %q", v["ps"], label)
	}
	// The rest of the config must survive the rewrite.
	if v["add"] != "23.227.38.20" {
		t.Errorf("add = %v, want 23.227.38.20 (payload corrupted)", v["add"])
	}
}

func TestLabelWithExitIP(t *testing.T) {
	g, err := OpenGeoLabeler("../Country.mmdb")
	if err != nil {
		t.Fatalf("OpenGeoLabeler: %v", err)
	}
	defer g.Close()

	link := sampleLinks["vless"]
	got := LabelWithExitIP(link, "8.8.8.8", g)
	before, _, _ := strings.Cut(link, "#")
	want := before + "#🇺🇸 USA | VLESS"
	if got != want {
		t.Errorf("LabelWithExitIP(vless, 8.8.8.8) =\n%q\nwant\n%q", got, want)
	}

	// Unknown or private exit IPs must leave the original remark
	// untouched — never guess a country.
	for _, ip := range []string{"", "192.168.1.1", "garbage"} {
		if got := LabelWithExitIP(link, ip, g); got != link {
			t.Errorf("LabelWithExitIP(vless, %q) changed the link:\n%q", ip, got)
		}
	}
	// A nil labeler must also leave the link unchanged.
	if got := LabelWithExitIP(link, "8.8.8.8", nil); got != link {
		t.Errorf("LabelWithExitIP with nil labeler changed the link:\n%q", got)
	}
}
