package livetest

import (
	"testing"
)

// Real sample links: the first line of each per-protocol list in the
// repository root, copied verbatim.
var sampleLinks = map[string]string{
	"vless":  "vless://dc7d45c9-c942-41e3-b880-9a7fd5b64e2f@199.232.78.159:443?encryption=none&host=copy_az_channel_NUFiLTER_5i.global.ssl.fastly.net.&path=%2F%3FTELEGRAM--BYA--CHANEL---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN--%40JKVPN---%40JKVPN---%40JKVPN---%40JKVPN&security=tls&sni=firefox.com&type=ws#\U0001f1fa\U0001f1f8 USA | TLS \u2022 WS",
	"vmess":  "vmess://eyJhZGQiOiIyMy4yMjcuMzguMjAiLCJhaWQiOjAsImhvc3QiOiJvcGxnMS5jZmNkbjIueHl6IiwiaWQiOiJjNWEyZDdiOC1iZjg0LTRmOTctODU3Ny1iOWI4N2YyYmFhZjciLCJuZXQiOiJ3cyIsInBhdGgiOiIvQVVJS044QVUiLCJwb3J0Ijo0NDMsInBzIjoi8J+HqPCfh6YgQ2FuYWRhIHwgV1MiLCJzZWN1cml0eSI6ImF1dG8iLCJza2lwLWNlcnQtdmVyaWZ5Ijp0cnVlLCJzbmkiOiIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiYXV0byJ9",
	"trojan": "trojan://humanity@188.42.145.180:443?path=%2Fassignment&security=tls&insecure=0&fp=chrome&type=ws&allowInsecure=0&sni=www.volumeroot.com#\U0001f1f1\U0001f1fa Luxembourg | TLS \u2022 chrome",
	"ss":     "ss://YWVzLTI1Ni1nY20677+977+9Ww@162.159.38.119:443#\U0001f3f4 Dynamic | Basic",
	"hy2":    "hy2://Yet-Another-Public-Config-1@[2a14:3f87:f001:13::a]:35200/?insecure=1&sni=YAPC-1.afshin.ir&obfs=salamander&obfs-password=Yet-Another-Public-Config-1#\U0001f1f3\U0001f1f1 Netherlands | TLS \u2022 Salamander",
}

// For every supported protocol, a real-world link must convert without
// error, and the resulting outbound must build and start an xray-core
// instance (no traffic is sent).
func TestConvertSamplesAndStartInstance(t *testing.T) {
	for proto, link := range sampleLinks {
		t.Run(proto, func(t *testing.T) {
			outbound, err := Convert(link)
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			if outbound["protocol"] == "" || outbound["protocol"] == nil {
				t.Fatalf("outbound has no protocol: %v", outbound)
			}
			inst, err := startInstance(outbound)
			if err != nil {
				t.Fatalf("startInstance: %v", err)
			}
			if err := inst.Close(); err != nil {
				t.Fatalf("instance Close: %v", err)
			}
		})
	}
}

func TestConvertErrors(t *testing.T) {
	for _, link := range []string{
		"",
		"not a link at all",
		"://missing-scheme",
		"ssr://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTI3LjAuMC4xOjgzODg",
		"tuic://uuid:password@127.0.0.1:443",
		"vless://@127.0.0.1:443",
		"vless://dc7d45c9-c942-41e3-b880-9a7fd5b64e2f@127.0.0.1:notaport",
		"ss://",
		"ss://bm9jb2xvbg",
		"vmess://!!!not-base64!!!",
	} {
		if _, err := Convert(link); err == nil {
			t.Errorf("Convert(%q): expected error, got nil", link)
		}
	}
}

// The ss sample uses the classic form ss://base64(method:password)@host:port.
// Decoding its userinfo must yield the real method and password:
// base64 "YWVzLTI1Ni1nY20677+977+9Ww" decodes to
// "aes-256-gcm:" followed by two U+FFFD replacement characters and '['.
func TestSSClassicUserinfoDecoding(t *testing.T) {
	outbound, err := Convert(sampleLinks["ss"])
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	settings, ok := outbound["settings"].(map[string]any)
	if !ok {
		t.Fatalf("no settings in %v", outbound)
	}
	servers, ok := settings["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("bad servers in %v", settings)
	}
	server := servers[0].(map[string]any)
	if got := server["method"]; got != "aes-256-gcm" {
		t.Errorf("method = %v, want aes-256-gcm", got)
	}
	if got, want := server["password"], "\ufffd\ufffd["; got != want {
		t.Errorf("password = %q, want %q", got, want)
	}
	if got := server["address"]; got != "162.159.38.119" {
		t.Errorf("address = %v, want 162.159.38.119", got)
	}
	if got := server["port"]; got != 443 {
		t.Errorf("port = %v, want 443", got)
	}
}

// SIP002 plain userinfo and IPv6 hosts.
func TestSSPlainUserinfoAndIPv6(t *testing.T) {
	outbound, err := Convert("ss://aes-128-gcm:plainpass@[2001:db8::1]:8388#x")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	server := outbound["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if server["method"] != "aes-128-gcm" || server["password"] != "plainpass" {
		t.Errorf("method/password = %v/%v", server["method"], server["password"])
	}
	if server["address"] != "2001:db8::1" || server["port"] != 8388 {
		t.Errorf("address/port = %v/%v", server["address"], server["port"])
	}
}

// A Hysteria2 link must produce a real hysteria outbound (not trojan),
// with the auth carried in hysteriaSettings.
func TestHysteria2OutboundShape(t *testing.T) {
	outbound, err := Convert(sampleLinks["hy2"])
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if outbound["protocol"] != "hysteria" {
		t.Fatalf("protocol = %v, want hysteria", outbound["protocol"])
	}
	stream := outbound["streamSettings"].(map[string]any)
	if stream["network"] != "hysteria" {
		t.Errorf("network = %v, want hysteria", stream["network"])
	}
	hs := stream["hysteriaSettings"].(map[string]any)
	if hs["auth"] != "Yet-Another-Public-Config-1" {
		t.Errorf("auth = %v", hs["auth"])
	}
	// The sample carries salamander obfs, which belongs in udpmasks.
	masks, ok := stream["udpmasks"].([]any)
	if !ok || len(masks) != 1 {
		t.Fatalf("no udpmasks for obfs sample: %v", stream)
	}
	if masks[0].(map[string]any)["type"] != "salamander" {
		t.Errorf("udpmasks = %v", masks)
	}
}

// Regression test for the 2026-11-24 production panic: a VLESS XHTTP
// link whose host= parameter decodes to a string that cannot be a URL
// host made xray-core's SplitHTTP dialer re-parse a broken URL, get a
// nil *url.URL and panic — killing the live test of a 53k-config list.
// Conversion must reject such links with an error instead.
func TestConvertXHTTPPoisonHostRejected(t *testing.T) {
	poison := []string{
		// host decodes to "bad host" (space)
		"vless://dc7d45c9-c942-41e3-b880-9a7fd5b64e2f@203.0.113.10:443?security=tls&type=xhttp&host=bad%20host&path=%2F#x",
		// host decodes to a URL with slashes
		"vless://dc7d45c9-c942-41e3-b880-9a7fd5b64e2f@203.0.113.10:443?security=tls&type=splithttp&host=https%3A%2F%2Fevil.example%2Fp&path=%2F#x",
		// host decodes to an unbalanced IPv6 bracket
		"vless://dc7d45c9-c942-41e3-b880-9a7fd5b64e2f@203.0.113.10:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&type=xhttp&host=%5B%3A%3A1&path=%2F#x",
		// sni fallback: no host=, but an sni that cannot be a URL host
		"vless://dc7d45c9-c942-41e3-b880-9a7fd5b64e2f@203.0.113.10:443?security=tls&sni=bad%20sni&type=xhttp&path=%2F#x",
	}
	for _, link := range poison {
		if _, err := Convert(link); err == nil {
			t.Errorf("Convert(poison xhttp) succeeded, want error:\n%s", link)
		}
	}

	// A well-formed XHTTP link must still convert.
	good := "vless://dc7d45c9-c942-41e3-b880-9a7fd5b64e2f@203.0.113.10:443?security=tls&type=xhttp&host=cdn.example.com&path=%2Fapi#x"
	if _, err := Convert(good); err != nil {
		t.Errorf("Convert(valid xhttp) failed: %v", err)
	}
}
