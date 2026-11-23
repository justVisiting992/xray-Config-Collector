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
	want := before + "#🇺🇸 USA | VLESS | WS • TLS"
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

func TestTraitTag(t *testing.T) {
	cases := map[string]string{
		// Sample links (real-world shapes).
		"vless":  "WS • TLS",
		"vmess":  "WS • TLS",
		"trojan": "WS • TLS",
		"ss":     "TCP • AES256",
		"hy2":    "QUIC • TLS • Salamander",
	}
	for proto, want := range cases {
		if got := TraitTag(sampleLinks[proto]); got != want {
			t.Errorf("TraitTag(%s sample) = %q, want %q", proto, got, want)
		}
	}

	crafted := map[string]string{
		"vless://u@h:443?security=reality&flow=xtls-rprx-vision&type=tcp#x": "TCP • Reality • Vision",
		"vless://u@h:443?security=tls&type=grpc#x":                          "gRPC • TLS",
		"vless://u@h:443#x":  "TCP",
		"trojan://p@h:443#x": "TCP • TLS",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@h:8388#x": "TCP • ChaCha",
		"ss://aes-128-gcm:pass@h:8388#x":                     "TCP • AES128",
		"hysteria2://p@h:443#x":                              "QUIC • TLS",
		"http://not-a-proxy":                                 "",
	}
	for link, want := range crafted {
		if got := TraitTag(link); got != want {
			t.Errorf("TraitTag(%q) = %q, want %q", link, got, want)
		}
	}
}

func TestNumberDuplicateRemarks(t *testing.T) {
	mkVless := func(host, remark string) string {
		return "vless://u@" + host + ":443?security=reality#" + remark
	}
	links := []string{
		mkVless("a.example", "🇩🇪 Germany | VLESS | TCP • Reality"),
		mkVless("b.example", "🇩🇪 Germany | VLESS | TCP • Reality"),
		mkVless("c.example", "🇫🇷 France | VLESS | WS • TLS"),
		mkVless("d.example", "🇩🇪 Germany | VLESS | TCP • Reality"),
		sampleLinks["vmess"],
		sampleLinks["vmess"],
		"ss://YWVzLTI1Ni1nY206cGFzcw@h:8388",
	}
	out := NumberDuplicateRemarks(links)
	if len(out) != len(links) {
		t.Fatalf("length changed: %d -> %d", len(links), len(out))
	}
	wantRemarks := []string{
		"🇩🇪 Germany | VLESS | TCP • Reality 01",
		"🇩🇪 Germany | VLESS | TCP • Reality 02",
		"🇫🇷 France | VLESS | WS • TLS",
		"🇩🇪 Germany | VLESS | TCP • Reality 03",
		"", // vmess checked via ps below
		"",
		"",
	}
	for i, want := range wantRemarks {
		if want == "" {
			continue
		}
		if got := remarkOf(out[i]); got != want {
			t.Errorf("link %d remark = %q, want %q", i, got, want)
		}
	}
	// VMess duplicates: ps fields numbered 01 and 02, payloads intact.
	ps1, ps2 := remarkOf(out[4]), remarkOf(out[5])
	if !strings.HasSuffix(ps1, " 01") || !strings.HasSuffix(ps2, " 02") {
		t.Errorf("vmess ps not numbered: %q / %q", ps1, ps2)
	}
	if ps1[:len(ps1)-3] != ps2[:len(ps2)-3] {
		t.Errorf("vmess ps bases differ: %q vs %q", ps1, ps2)
	}
	// The remark-less SS link must be untouched.
	if out[6] != links[6] {
		t.Errorf("remark-less link changed: %q", out[6])
	}
	// All remarks in the output must now be unique.
	seen := map[string]bool{}
	for _, l := range out {
		r := remarkOf(l)
		if r == "" {
			continue
		}
		if seen[r] {
			t.Errorf("duplicate remark survived: %q", r)
		}
		seen[r] = true
	}
}
