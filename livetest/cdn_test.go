package livetest

import "testing"

func TestCDNName(t *testing.T) {
	matches := map[string]string{
		"104.16.5.4":           "Cloudflare", // 104.16.0.0/13
		"172.64.10.1":          "Cloudflare", // 172.64.0.0/13
		"2606:4700:4700::1111": "Cloudflare", // 2606:4700::/32
		"13.32.0.5":            "CloudFront", // 13.32.0.0/15
		"151.101.1.1":          "Fastly",     // 151.101.0.0/16
		"2.16.0.3":             "Akamai",     // 2.16.0.0/13
		"::ffff:104.16.5.4":    "Cloudflare", // 4-in-6 form unmaps
	}
	for ip, want := range matches {
		if got, ok := CDNName(ip); !ok || got != want {
			t.Errorf("CDNName(%q) = %q, %v; want %q, true", ip, got, ok, want)
		}
	}
	// None of these may ever match: public DNS resolvers, a GCP
	// address (cloud hosting is a real exit location, not a CDN),
	// and malformed input.
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "35.184.5.5", "", "not-an-ip", "104.16.5.4/32"} {
		if got, ok := CDNName(ip); ok {
			t.Errorf("CDNName(%q) = %q, true; want no match", ip, got)
		}
	}
}

func TestLabelWithExitIPCDN(t *testing.T) {
	link := "vless://d3adb33f-0000-4000-8000-000000000000@example.com:443?security=tls&type=ws#old remark"
	got := LabelWithExitIP(link, "104.16.5.4", nil)
	if r := remarkOf(got); r != "☁️ Cloudflare | VLESS | WS • TLS" {
		t.Errorf("remark = %q; want %q", r, "☁️ Cloudflare | VLESS | WS • TLS")
	}
	// A non-CDN exit with no labeler keeps the original link,
	// exactly as before CDN labelling existed.
	if got := LabelWithExitIP(link, "8.8.8.8", nil); got != link {
		t.Errorf("non-CDN exit without labeler changed the link: %q", got)
	}
}
