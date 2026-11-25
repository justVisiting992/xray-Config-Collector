package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestClashYAMLBlockStyle(t *testing.T) {
	body := []byte(`
mixed-port: 7890
dns:
  enable: true
  nameserver: ['https://1.1.1.1/dns-query']
proxies:
- name: 'NL Reality'
  type: vless
  server: 195.63.143.129
  port: 8446
  uuid: 5d98ff1a-d576-46d3-9504-b158d94bcce9
  udp: true
  tls: true
  reality-opts:
    public-key: UzS81axpyoGU0UUzsWPMBi1cdAxo5hyfLkqB9wy9HkI
    short-id: ec685991deb623f7
  client-fingerprint: safari
  servername: www.kpn.com
  flow: xtls-rprx-vision
- name: 'WS VMess'
  type: vmess
  server: vm.example.com
  port: 443
  uuid: 11111111-2222-3333-4444-555555555555
  alterId: 0
  cipher: auto
  network: ws
  tls: true
  servername: vm.example.com
  ws-opts:
    path: /ray
    headers:
      Host: cdn.example.com
- name: 'SSR skip'
  type: ssr
  server: 1.2.3.4
  port: 33336
  password: x
  cipher: chacha20-ietf
  protocol: auth_chain_a
  obfs: tls1.2_ticket_auth
`)
	uris := structuredSubscriptionURIs(body)
	if len(uris) != 2 {
		t.Fatalf("got %d URIs, want 2 (ssr skipped): %v", len(uris), uris)
	}
	vless := uris[0]
	for _, want := range []string{"vless://5d98ff1a-d576-46d3-9504-b158d94bcce9@195.63.143.129:8446", "security=reality", "pbk=UzS81axpyoGU0UUzsWPMBi1cdAxo5hyfLkqB9wy9HkI", "sid=ec685991deb623f7", "sni=www.kpn.com", "fp=safari", "flow=xtls-rprx-vision"} {
		if !strings.Contains(vless, want) {
			t.Errorf("vless URI missing %q: %s", want, vless)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uris[1], "vmess://"))
	if err != nil {
		t.Fatalf("vmess URI does not decode: %v", err)
	}
	var v map[string]interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("vmess JSON: %v", err)
	}
	if v["add"] != "vm.example.com" || v["net"] != "ws" || v["path"] != "/ray" || v["host"] != "cdn.example.com" || v["tls"] != "tls" {
		t.Errorf("vmess fields wrong: %v", v)
	}
}

func TestClashYAMLFlowStyle(t *testing.T) {
	body := []byte(`proxies:
- {"name":"AL_01","server":"109.104.153.43","type":"ss","country":"AL","port":33336,"password":"dongtaiwang.com","cipher":"chacha20-ietf"}
- {"name":"TJ","server":"43.156.36.253","type":"trojan","port":443,"password":"pw","sni":"s.example.com","skip-cert-verify":true}
`)
	uris := structuredSubscriptionURIs(body)
	if len(uris) != 2 {
		t.Fatalf("got %d URIs, want 2: %v", len(uris), uris)
	}
	if !strings.HasPrefix(uris[0], "ss://") || !strings.Contains(uris[0], "@109.104.153.43:33336") {
		t.Errorf("ss URI wrong: %s", uris[0])
	}
	method, password, ok := func() (string, string, bool) {
		ui := strings.Split(strings.TrimPrefix(uris[0], "ss://"), "@")[0]
		dec, err := base64.RawURLEncoding.DecodeString(ui)
		if err != nil {
			return "", "", false
		}
		m, p, found := strings.Cut(string(dec), ":")
		return m, p, found
	}()
	if !ok || method != "chacha20-ietf" || password != "dongtaiwang.com" {
		t.Errorf("ss userinfo = %q/%q/%v", method, password, ok)
	}
	if !strings.Contains(uris[1], "sni=s.example.com") || !strings.Contains(uris[1], "allowInsecure=1") {
		t.Errorf("trojan URI wrong: %s", uris[1])
	}
}

func TestSingboxHysteria2PortHopping(t *testing.T) {
	body := []byte(`{"outbounds":[
		{"type":"selector","tag":"Internet","outbounds":["Best Latency"]},
		{"type":"hysteria2","tag":"DE JNIR-1\n@JavidnamanIran","server":"jnir-1.example.com","server_port":0,"server_ports":"35000:45000","password":"pw123","obfs":{"type":"salamander","password":"obfs456"},"tls":{"enabled":true,"server_name":"sni.example.com"}}
	]}`)
	uris := structuredSubscriptionURIs(body)
	if len(uris) != 1 {
		t.Fatalf("got %d URIs, want 1 (selector skipped): %v", len(uris), uris)
	}
	u := uris[0]
	for _, want := range []string{"hysteria2://pw123@jnir-1.example.com:35000", "mport=35000-45000", "obfs=salamander", "obfs-password=obfs456", "sni=sni.example.com"} {
		if !strings.Contains(u, want) {
			t.Errorf("hy2 URI missing %q: %s", want, u)
		}
	}
	if strings.ContainsAny(u, "\n\r") {
		t.Errorf("tag newline leaked into URI: %q", u)
	}
}

func TestStructuredLeavesPlainListsAlone(t *testing.T) {
	plain := "vless://5d98ff1a-d576-46d3-9504-b158d94bcce9@1.2.3.4:443?security=tls#x"
	if got := structuredSubscriptionURIs([]byte(plain)); got != nil {
		t.Errorf("plain list: got %v, want nil", got)
	}
	if decodeSubscriptionBody([]byte(plain)) != plain {
		t.Error("plain list altered by decodeSubscriptionBody")
	}
}
