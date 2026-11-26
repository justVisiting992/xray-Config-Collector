//go:build ignore

// This file is a standalone program: the workflow runs it as
// `go run converter.go`, and go run with an explicitly named file
// ignores build constraints, so that invocation is unaffected. The
// constraint exists so package-level commands (go build ./...,
// go vet ./..., go test ./...) see only main.go's main() instead of
// failing on two mains in one package.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/justVisiting992/xray-Config-Collector/internal/sharelink"
)

type Proxy map[string]interface{}

func main() {
	inputFile := "mixed_iran.txt"
	providerFile := "clash-proxies.yaml"
	configFile := "clash.yaml"

	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("❌ Error opening input file: %v\n", err)
		os.Exit(0)
	}
	defer file.Close()

	var proxies []Proxy
	skipped := 0
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var p Proxy
		var parseErr error

		// Scheme matching is case-insensitive: the harvest regexes
		// accept any case, so an upper-case scheme is a valid config,
		// not a line to drop.
		lowerLine := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lowerLine, "vless://"):
			p, parseErr = parseVless(line)
		case strings.HasPrefix(lowerLine, "vmess://"):
			p, parseErr = parseVmess(line)
		case strings.HasPrefix(lowerLine, "trojan://"):
			p, parseErr = parseTrojan(line)
		case strings.HasPrefix(lowerLine, "ss://"):
			p, parseErr = parseSS(line)
		case strings.HasPrefix(lowerLine, "hysteria2://") || strings.HasPrefix(lowerLine, "hy2://"):
			p, parseErr = parseHy2(line)
		}

		if parseErr == nil && p != nil {
			p["udp"] = true
			p["skip-cert-verify"] = true

			if p["tls"] == true {
				p["alpn"] = []string{"h2", "http/1.1"}
			}

			delete(p, "plugin")
			delete(p, "plugin-opts")
			// obfs is a first-class field for hysteria2 (salamander
			// servers cannot be reached without it); for every
			// other protocol it is an unsupported leftover.
			if p["type"] != "hysteria2" {
				delete(p, "obfs")
				delete(p, "obfs-password")
			}

			if name, ok := p["name"].(string); ok {
				p["name"] = sanitizeString(name)
			}

			proxies = append(proxies, p)
		} else {
			// Never drop a config silently: count it and report
			// the total after the loop.
			skipped++
		}
	}

	proxies = dedupeProxies(proxies)
	proxies = selectClashProxies(proxies)
	writeProxiesYaml(providerFile, proxies)
	writeClashConfig(configFile)
	if skipped > 0 {
		fmt.Printf("⚠️ Skipped %d unparseable line(s) from %s\n", skipped, inputFile)
	}
}

func sanitizeString(s string) string {
	if !utf8.ValidString(s) {
		v := make([]rune, 0, len(s))
		for i, r := range s {
			if r == utf8.RuneError {
				_, size := utf8.DecodeRuneInString(s[i:])
				if size == 1 {
					continue
				}
			}
			v = append(v, r)
		}
		s = string(v)
	}
	return strings.Map(func(r rune) rune {
		if r >= 32 && r != 127 {
			return r
		}
		return -1
	}, s)
}

func parseVless(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	p := make(Proxy)
	p["type"] = "vless"
	p["name"] = u.Fragment
	p["server"] = u.Hostname()
	p["port"] = u.Port()
	p["uuid"] = u.User.Username()

	security := q.Get("security")
	if security == "tls" || security == "reality" {
		p["tls"] = true
		if sni := q.Get("sni"); sni != "" {
			p["servername"] = sni
		}
	}

	if security == "reality" {
		pbk := q.Get("pbk")
		sid := q.Get("sid")
		if pbk != "" {
			p["reality-opts"] = map[string]string{
				"public-key": pbk,
				"short-id":   sid,
			}
		}
	}

	// The link's own flow is authoritative: hard-coding Vision for
	// every reality link invented a flow some servers never had and
	// dropped the flow of plain-TLS Vision links.
	if flow := q.Get("flow"); flow != "" {
		p["flow"] = flow
	}

	fp := q.Get("fp")
	if fp != "" {
		p["client-fingerprint"] = fp
	} else if p["tls"] == true {
		p["client-fingerprint"] = "chrome"
	}

	network := q.Get("type")
	if network != "" {
		p["network"] = network
		// TLS comes from the security parameter alone (set above).
		// Forcing it on for ws/httpupgrade/grpc published a
		// different config from the one the live test passed: a
		// plaintext-WS link was tested without TLS and published
		// with TLS + ALPN.
		if network == "ws" || network == "httpupgrade" {
			headers := map[string]string{}
			if host := q.Get("host"); host != "" {
				headers["Host"] = host
			}
			p[network+"-opts"] = map[string]interface{}{
				"path":    q.Get("path"),
				"headers": headers,
			}
		} else if network == "grpc" {
			p["grpc-opts"] = map[string]interface{}{
				"service-name": q.Get("serviceName"),
			}
		} else if network == "xhttp" {
			opts := map[string]interface{}{}
			if path := q.Get("path"); path != "" {
				opts["path"] = path
			}
			if host := q.Get("host"); host != "" {
				opts["host"] = host
			}
			if mode := q.Get("mode"); mode != "" {
				opts["mode"] = mode
			}
			if len(opts) > 0 {
				p["xhttp-opts"] = opts
			}
		}
	} else {
		p["network"] = "tcp"
	}

	return p, nil
}

func parseVmess(raw string) (Proxy, error) {
	data := strings.TrimPrefix(raw, "vmess://")
	// The shared loose decoder: this function's own two attempts
	// never padded the input, so an unpadded VMess payload — common
	// in the wild, and decoded fine by main.go and livetest — was
	// silently skipped here.
	decoded, err := sharelink.DecodeBase64Loose(data)
	if err != nil {
		return nil, err
	}

	var v map[string]interface{}
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, err
	}
	if v["add"] == nil || v["id"] == nil || v["port"] == nil {
		// Without server or UUID there is no proxy to publish;
		// %v-rendering the missing values used to write literal
		// "<nil>" entries into clash-proxies.yaml.
		return nil, fmt.Errorf("vmess: missing add or id")
	}

	p := make(Proxy)
	p["type"] = "vmess"
	p["name"] = fmt.Sprintf("%v", v["ps"])
	p["server"] = v["add"]
	p["port"] = v["port"]
	p["uuid"] = v["id"]
	// The link's own alterId and cipher are authoritative; both
	// used to be hard-coded (0 / "auto"), which broke legacy
	// servers that require alterId > 0 and hid the real cipher.
	// aid arrives as a JSON number or string depending on the
	// generator; Mihomo wants an int, and the old hard-coded 0 was
	// at least always an int.
	switch aid := v["aid"].(type) {
	case float64:
		p["alterId"] = int(aid)
	case string:
		n, _ := strconv.Atoi(aid)
		p["alterId"] = n
	default:
		p["alterId"] = 0
	}
	if scy := fmt.Sprintf("%v", v["scy"]); v["scy"] != nil && scy != "" && scy != "<nil>" {
		p["cipher"] = scy
	} else {
		p["cipher"] = "auto"
	}
	if sni := fmt.Sprintf("%v", v["sni"]); v["sni"] != nil && sni != "" && sni != "<nil>" {
		p["servername"] = sni
	}

	net := fmt.Sprintf("%v", v["net"])
	if net == "ws" {
		p["network"] = "ws"
		p["ws-opts"] = map[string]interface{}{
			"path":    v["path"],
			"headers": map[string]string{"Host": fmt.Sprintf("%v", v["host"])},
		}
		p["tls"] = true
	} else if net == "grpc" {
		p["network"] = "grpc"
		p["grpc-opts"] = map[string]interface{}{
			"service-name": v["path"],
		}
		p["tls"] = true
	} else if net == "httpupgrade" {
		p["network"] = "httpupgrade"
		p["ws-opts"] = map[string]interface{}{
			"path":    v["path"],
			"headers": map[string]string{"Host": fmt.Sprintf("%v", v["host"])},
		}
	} else if net == "xhttp" || net == "http" {
		// livetest maps the legacy VMess "http" transport to
		// xhttp; publish what was tested.
		p["network"] = "xhttp"
		opts := map[string]interface{}{}
		if path := fmt.Sprintf("%v", v["path"]); v["path"] != nil && path != "" && path != "<nil>" {
			opts["path"] = path
		}
		if host := fmt.Sprintf("%v", v["host"]); v["host"] != nil && host != "" && host != "<nil>" {
			opts["host"] = host
		}
		if len(opts) > 0 {
			p["xhttp-opts"] = opts
		}
	} else if net == "h2" {
		p["network"] = "h2"
		p["h2-opts"] = map[string]interface{}{
			"path": v["path"],
			"host": []string{fmt.Sprintf("%v", v["host"])},
		}
	} else {
		p["network"] = "tcp"
	}

	if fmt.Sprintf("%v", v["tls"]) == "tls" {
		p["tls"] = true
		if tlsSettings, ok := v["tlsSettings"].(map[string]interface{}); ok {
			if fp, ok := tlsSettings["fingerprint"].(string); ok && fp != "" {
				p["client-fingerprint"] = fp
			} else {
				p["client-fingerprint"] = "chrome"
			}
		}
	}

	return p, nil
}

func parseTrojan(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	p := make(Proxy)
	p["type"] = "trojan"
	p["name"] = u.Fragment
	p["server"] = u.Hostname()
	p["port"] = u.Port()
	p["password"] = u.User.Username()
	p["tls"] = true

	// This parser used to read nothing but fp from the query: the
	// SNI and every transport were dropped, so a Trojan-over-WS
	// link that passed the live test was published as plain
	// TCP/TLS to the server host — the largest mangling gap the
	// parser audit found. Mirror parseVless's transport handling.
	q := u.Query()
	if sni := q.Get("sni"); sni != "" {
		p["servername"] = sni
	} else if peer := q.Get("peer"); peer != "" {
		p["servername"] = peer
	}
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	p["network"] = network
	switch network {
	case "ws", "httpupgrade":
		headers := map[string]string{}
		if host := q.Get("host"); host != "" {
			headers["Host"] = host
		}
		p[network+"-opts"] = map[string]interface{}{
			"path":    q.Get("path"),
			"headers": headers,
		}
	case "grpc":
		p["grpc-opts"] = map[string]interface{}{
			"service-name": q.Get("serviceName"),
		}
	case "xhttp":
		opts := map[string]interface{}{}
		if path := q.Get("path"); path != "" {
			opts["path"] = path
		}
		if host := q.Get("host"); host != "" {
			opts["host"] = host
		}
		if mode := q.Get("mode"); mode != "" {
			opts["mode"] = mode
		}
		if len(opts) > 0 {
			p["xhttp-opts"] = opts
		}
	}

	fp := q.Get("fp")
	if fp != "" {
		p["client-fingerprint"] = fp
	} else {
		p["client-fingerprint"] = "chrome"
	}

	return p, nil
}

func parseSS(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	p := make(Proxy)
	p["type"] = "ss"
	p["name"] = u.Fragment
	p["server"] = u.Hostname()
	p["port"] = u.Port()

	// Shadowsocks URIs come in two userinfo forms:
	//   plain:   ss://cipher:password@host:port
	//   classic: ss://base64(cipher:password)@host:port
	// main.go's isValidShadowsocks() *requires* the classic form, and
	// every entry in ss_iran.txt (198/198 at HEAD 16fe905) uses it, so
	// treating the base64 blob as the password and hard-coding
	// aes-256-gcm broke every SS proxy in clash.yaml. Decode the
	// classic form; fall back to the old behaviour only if decoding
	// fails, so unparseable lines degrade instead of erroring.
	cipher, password := decodeSSUserinfo(raw)
	if cipher == "" {
		user := ""
		if u.User != nil {
			user = u.User.Username()
		}
		pass, hasPass := "", false
		if u.User != nil {
			pass, hasPass = u.User.Password()
		}
		if hasPass {
			cipher, password = user, pass
		} else {
			// No decodable method:password anywhere in the link.
			// This used to fabricate cipher aes-256-gcm with the
			// raw userinfo blob as the password, publishing a
			// wrong proxy instead of counting the line as
			// skipped like every other parse failure.
			return nil, fmt.Errorf("ss: no decodable method:password in userinfo")
		}
	}
	p["cipher"] = cipher
	p["password"] = password

	if security := u.Query().Get("security"); security == "tls" {
		p["tls"] = true
		fp := u.Query().Get("fp")
		if fp != "" {
			p["client-fingerprint"] = fp
		} else {
			p["client-fingerprint"] = "chrome"
		}
	}

	return p, nil
}

// decodeSSUserinfo returns the cipher and password from an ss:// URI.
// Returns "", "" when the userinfo is not a decodable method:password
// pair. The userinfo logic itself lives in internal/sharelink, shared
// with main.go's isValidShadowsocks, so the two programs can no
// longer drift apart on what a valid SS userinfo is.
func decodeSSUserinfo(raw string) (string, string) {
	base := strings.Split(raw, "#")[0]
	base = strings.TrimPrefix(base, "ss://")
	atIdx := strings.LastIndex(base, "@")
	if atIdx == -1 {
		return "", ""
	}
	method, password, ok := sharelink.DecodeSSUserinfo(base[:atIdx])
	if !ok {
		return "", ""
	}
	return method, password
}

func parseHy2(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	p := make(Proxy)
	p["type"] = "hysteria2"
	p["name"] = u.Fragment
	p["server"] = u.Hostname()
	p["port"] = u.Port()
	p["password"] = u.User.Username()

	q := u.Query()
	if p["password"] == "" {
		// Some links carry the auth only in the query; livetest
		// accepts those, so publish them with the same password.
		p["password"] = q.Get("auth")
	}
	if sni := q.Get("sni"); sni != "" {
		p["sni"] = sni
	}
	if obfs := q.Get("obfs"); obfs != "" {
		p["obfs"] = obfs
	}
	if obfsPassword := q.Get("obfs-password"); obfsPassword != "" {
		p["obfs-password"] = obfsPassword
	}
	// The non-standard "brutal" key this parser used to emit is
	// gone: Mihomo does not read it (bandwidth belongs in up/down)
	// and no other parser in the pipeline produces it.

	return p, nil
}

// dedupeProxies drops proxies that are identical in everything but
// name, keeping the first occurrence. The input list is normally
// fingerprint-deduped upstream, but two distinct links can still
// collapse into the same Clash proxy here (two Trojans differing
// only in a field this converter does not carry, a hand-edited
// mixed file, ...), and before this pass both landed in
// clash-proxies.yaml, spending two of the 500 selection slots on
// one endpoint. The key is a canonical serialisation of the proxy
// map without its name: keys sorted, values via %v — the same
// rendering writeProxiesYaml produces.
func dedupeProxies(proxies []Proxy) []Proxy {
	seen := make(map[string]bool, len(proxies))
	out := proxies[:0]
	for _, p := range proxies {
		keys := make([]string, 0, len(p))
		for k := range p {
			if k != "name" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s=%v;", k, p[k])
		}
		key := b.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

// clashCountryFlags are the exit countries that get their own group
// in clash.yaml, in the config's group order, plus the ☁️ marker of
// CDN exits (see livetest's CDN labelling), which the Dynamic group
// covers. Only proxies whose remark starts with one of these are
// eligible for clash-proxies.yaml. Keep in sync with the groups in
// the clashConfig template below.
var clashCountryFlags = []string{"🇺🇸", "🇳🇱", "🇩🇪", "🇯🇵", "🇫🇷", "🇨🇦", "🇷🇺", "🇸🇬", "🇪🇸", "🇬🇧", "🇨🇭", "🇭🇰", "🇫🇮", "🇸🇪", "🇵🇱", "🇰🇷", "☁️"}

// clashProtocols is the quota order for the clash selection.
var clashProtocols = []string{"vless", "vmess", "trojan", "ss", "hysteria2"}

const (
	clashMaxProxies = 500 // total cap for clash-proxies.yaml
	clashProtoQuota = 100 // per-protocol share before backfilling
)

// selectClashProxies picks the proxies published in
// clash-proxies.yaml: only the clashConfig countries, at most
// clashProtoQuota per protocol, spread across that protocol's
// countries round-robin so every country present in the pool is
// represented. A protocol that cannot fill its quota (hysteria2,
// usually) hands its unused slots to the other protocols,
// round-robin, up to clashMaxProxies in total. The result keeps
// the input order.
func selectClashProxies(proxies []Proxy) []Proxy {
	// spread[proto] holds the protocol's candidate indexes ordered
	// country-round-robin.
	spread := map[string][]int{}
	byProtoFlag := map[string]map[string][]int{}
	for i, p := range proxies {
		name, _ := p["name"].(string)
		proto, _ := p["type"].(string)
		flag := ""
		for _, f := range clashCountryFlags {
			if strings.HasPrefix(name, f) {
				flag = f
				break
			}
		}
		if flag == "" {
			continue
		}
		if byProtoFlag[proto] == nil {
			byProtoFlag[proto] = map[string][]int{}
		}
		byProtoFlag[proto][flag] = append(byProtoFlag[proto][flag], i)
	}
	for proto, byFlag := range byProtoFlag {
		for {
			took := false
			for _, f := range clashCountryFlags {
				if q := byFlag[f]; len(q) > 0 {
					spread[proto] = append(spread[proto], q[0])
					byFlag[f] = q[1:]
					took = true
				}
			}
			if !took {
				break
			}
		}
	}

	chosen := map[int]bool{}
	pos := map[string]int{} // next spread index per protocol
	take := func(proto string, n int) int {
		got := 0
		for got < n && pos[proto] < len(spread[proto]) {
			chosen[spread[proto][pos[proto]]] = true
			pos[proto]++
			got++
		}
		return got
	}
	total := 0
	for _, proto := range clashProtocols {
		total += take(proto, clashProtoQuota)
	}
	for total < clashMaxProxies {
		progressed := false
		for _, proto := range clashProtocols {
			if total >= clashMaxProxies {
				break
			}
			if take(proto, 1) > 0 {
				total++
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}

	out := make([]Proxy, 0, total)
	counts := map[string]int{}
	for i, p := range proxies {
		if chosen[i] {
			out = append(out, p)
			if t, ok := p["type"].(string); ok {
				counts[t]++
			}
		}
	}
	fmt.Printf("🎯 Selected %d of %d proxies for clash (vless %d, vmess %d, trojan %d, ss %d, hysteria2 %d)\n",
		len(out), len(proxies), counts["vless"], counts["vmess"], counts["trojan"], counts["ss"], counts["hysteria2"])
	return out
}

func writeProxiesYaml(filename string, proxies []Proxy) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("❌ Error creating output file: %v\n", err)
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	w.WriteString("proxies:\n")

	for _, p := range proxies {
		var parts []string
		keys := make([]string, 0, len(p))
		for k := range p {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s: %v", k, formatValue(p[k])))
		}
		w.WriteString(fmt.Sprintf("  - {%s}\n", strings.Join(parts, ", ")))
	}

	w.Flush()
	fmt.Printf("✅ Wrote %d proxies to %s\n", len(proxies), filename)
}

// clashConfig is the static Mihomo subscription config written to
// clash.yaml on every run. The proxies themselves live in
// clash-proxies.yaml, referenced through the proxy-provider below, so
// between runs only that file changes and this config stays identical.
//
// Rule providers: Chocolate4U (Iran domains/IPs and Iranian cloud
// ranges, Persian ads, malware, phishing, cryptominers), MetaCubeX
// meta-rules-dat (global ads, game domains, public trackers, Google
// Play / Google / Microsoft / Apple / Xiaomi), coldwater-10/clash_rules
// (censor — Iranian movie download sites, game processes, Xiaomi
// block/white lists; 10ium's copies are byte-identical mirrors),
// ACL4SSR (BanAD / BanProgramAD; 10ium's are YAML conversions), and
// 10ium/mihomo_rule (Ponzi — 10ium's own list, no upstream found).
// Country groups filter the provider by the flag emoji that starts
// every proxy name (the exit-IP label); the Dynamic group does the
// same for CDN exits, whose names start with ☁️ instead of a flag.
const clashConfig = `# xray-Config-Collector — Mihomo (Clash.Meta) subscription
# Proxies live in clash-proxies.yaml (see proxy-providers below); only
# that file changes between runs. This config is static.
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: false
unified-delay: true
tcp-concurrent: true
global-client-fingerprint: chrome
find-process-mode: strict
geodata-mode: true
geo-auto-update: true
geo-update-interval: 24
geox-url:
  geoip: "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geoip.dat"
  geosite: "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geosite.dat"
  mmdb: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/geoip.metadb"
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  ipv6: false
  prefer-h3: false
  cache-algorithm: arc
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.localdomain"
    - "*.invalid"
    - "*.localhost"
    - "*.test"
    - "*.local"
    - "*.home.arpa"
    - "time.*.com"
    - "ntp.*.com"
    - "*.ir"
  default-nameserver:
    - 78.157.42.100
    - 185.51.200.2
  nameserver:
    - "https://dns.google/dns-query"
    - "https://cloudflare-dns.com/dns-query"
  nameserver-policy:
    "rule-set:iran-domains":
      - 78.157.42.100
      - 185.51.200.2
  direct-nameserver:
    - 78.157.42.100
    - 185.51.200.2
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: false
  sniff:
    HTTP:
      ports: [80, 8080-8880]
    TLS:
      ports: [443, 8443]
proxy-providers:
  collector:
    type: http
    url: "https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/clash-proxies.yaml"
    path: ./clash-proxies.yaml
    interval: 7200
    health-check:
      enable: true
      url: "https://www.gstatic.com/generate_204"
      interval: 300
proxy-groups:
  - name: "🚀 PROXY"
    type: select
    proxies:
      - "♻️ AUTO"
      - "🇺🇸 USA"
      - "🇳🇱 Netherlands"
      - "🇩🇪 Germany"
      - "🇯🇵 Japan"
      - "🇫🇷 France"
      - "🇨🇦 Canada"
      - "🇷🇺 Russia"
      - "🇸🇬 Singapore"
      - "🇪🇸 Spain"
      - "🇬🇧 UK"
      - "🇨🇭 Switzerland"
      - "🇭🇰 Hong Kong"
      - "🇫🇮 Finland"
      - "🇸🇪 Sweden"
      - "🇵🇱 Poland"
      - "🇰🇷 South Korea"
      - "☁️ Dynamic"
      - DIRECT
  - name: "♻️ AUTO"
    type: url-test
    use:
      - collector
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇺🇸 USA"
    type: url-test
    use:
      - collector
    filter: "^🇺🇸"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇳🇱 Netherlands"
    type: url-test
    use:
      - collector
    filter: "^🇳🇱"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇩🇪 Germany"
    type: url-test
    use:
      - collector
    filter: "^🇩🇪"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇯🇵 Japan"
    type: url-test
    use:
      - collector
    filter: "^🇯🇵"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇫🇷 France"
    type: url-test
    use:
      - collector
    filter: "^🇫🇷"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇨🇦 Canada"
    type: url-test
    use:
      - collector
    filter: "^🇨🇦"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇷🇺 Russia"
    type: url-test
    use:
      - collector
    filter: "^🇷🇺"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇸🇬 Singapore"
    type: url-test
    use:
      - collector
    filter: "^🇸🇬"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇪🇸 Spain"
    type: url-test
    use:
      - collector
    filter: "^🇪🇸"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇬🇧 UK"
    type: url-test
    use:
      - collector
    filter: "^🇬🇧"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇨🇭 Switzerland"
    type: url-test
    use:
      - collector
    filter: "^🇨🇭"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇭🇰 Hong Kong"
    type: url-test
    use:
      - collector
    filter: "^🇭🇰"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇫🇮 Finland"
    type: url-test
    use:
      - collector
    filter: "^🇫🇮"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇸🇪 Sweden"
    type: url-test
    use:
      - collector
    filter: "^🇸🇪"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇵🇱 Poland"
    type: url-test
    use:
      - collector
    filter: "^🇵🇱"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "🇰🇷 South Korea"
    type: url-test
    use:
      - collector
    filter: "^🇰🇷"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
  - name: "☁️ Dynamic"
    type: url-test
    use:
      - collector
    filter: "^☁️"
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50
rule-providers:
  iran-domains:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.mrs"
    path: ./ruleset/iran-domains.mrs
    interval: 86400
  iran-ips:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.mrs"
    path: ./ruleset/iran-ips.mrs
    interval: 86400
  arvancloud:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/arvancloud.mrs"
    path: ./ruleset/arvancloud.mrs
    interval: 86400
  derakcloud:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/derakcloud.mrs"
    path: ./ruleset/derakcloud.mrs
    interval: 86400
  iranserver:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/iranserver.mrs"
    path: ./ruleset/iranserver.mrs
    interval: 86400
  parspack:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/parspack.mrs"
    path: ./ruleset/parspack.mrs
    interval: 86400
  ads-ir:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ads.mrs"
    path: ./ruleset/ads-ir.mrs
    interval: 86400
  ads-global:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs"
    path: ./ruleset/ads-global.mrs
    interval: 86400
  malware:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware.mrs"
    path: ./ruleset/malware.mrs
    interval: 86400
  phishing:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.mrs"
    path: ./ruleset/phishing.mrs
    interval: 86400
  cryptominers:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/cryptominers.mrs"
    path: ./ruleset/cryptominers.mrs
    interval: 86400
  censor:
    type: http
    behavior: classical
    format: yaml
    url: "https://raw.githubusercontent.com/coldwater-10/clash_rules/main/censor.yaml"
    path: ./ruleset/censor.yaml
    interval: 86400
  ban-ad:
    type: http
    behavior: classical
    format: text
    url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list"
    path: ./ruleset/ban-ad.list
    interval: 86400
  ban-program-ad:
    type: http
    behavior: classical
    format: text
    url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list"
    path: ./ruleset/ban-program-ad.list
    interval: 86400
  public-tracker:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-public-tracker.mrs"
    path: ./ruleset/public-tracker.mrs
    interval: 86400
  ponzi:
    type: http
    behavior: classical
    format: yaml
    url: "https://raw.githubusercontent.com/10ium/mihomo_rule/main/Ponzi.yaml"
    path: ./ruleset/ponzi.yaml
    interval: 86400
  xiaomi-block-list:
    type: http
    behavior: domain
    format: yaml
    url: "https://raw.githubusercontent.com/coldwater-10/clash_rules/main/xiaomi_block_list.yaml"
    path: ./ruleset/xiaomi-block-list.yaml
    interval: 86400
  xiaomi-white-list:
    type: http
    behavior: classical
    format: yaml
    url: "https://raw.githubusercontent.com/coldwater-10/clash_rules/main/xiaomi_white_list.yaml"
    path: ./ruleset/xiaomi-white-list.yaml
    interval: 86400
  game:
    type: http
    behavior: classical
    format: yaml
    url: "https://raw.githubusercontent.com/coldwater-10/clash_rules/main/game.yaml"
    path: ./ruleset/game.yaml
    interval: 86400
  category-games:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-games.mrs"
    path: ./ruleset/category-games.mrs
    interval: 86400
  google-play:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google-play.mrs"
    path: ./ruleset/google-play.mrs
    interval: 86400
  google:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google.mrs"
    path: ./ruleset/google.mrs
    interval: 86400
  microsoft:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.mrs"
    path: ./ruleset/microsoft.mrs
    interval: 86400
  apple:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple.mrs"
    path: ./ruleset/apple.mrs
    interval: 86400
  xiaomi:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/xiaomi.mrs"
    path: ./ruleset/xiaomi.mrs
    interval: 86400
rules:
  - RULE-SET,ads-ir,REJECT
  - RULE-SET,ads-global,REJECT
  - RULE-SET,malware,REJECT
  - RULE-SET,phishing,REJECT
  - RULE-SET,cryptominers,REJECT
  - RULE-SET,censor,REJECT
  - RULE-SET,ban-ad,REJECT
  - RULE-SET,ban-program-ad,REJECT
  - RULE-SET,public-tracker,REJECT
  - RULE-SET,ponzi,REJECT
  - RULE-SET,xiaomi-block-list,REJECT
  - RULE-SET,game,🚀 PROXY
  - RULE-SET,category-games,🚀 PROXY
  - RULE-SET,xiaomi-white-list,🚀 PROXY
  - RULE-SET,google-play,DIRECT
  - RULE-SET,google,DIRECT
  - RULE-SET,microsoft,DIRECT
  - RULE-SET,apple,DIRECT
  - RULE-SET,xiaomi,DIRECT
  - RULE-SET,iran-domains,DIRECT
  - RULE-SET,iran-ips,DIRECT,no-resolve
  - RULE-SET,arvancloud,DIRECT,no-resolve
  - RULE-SET,derakcloud,DIRECT,no-resolve
  - RULE-SET,iranserver,DIRECT,no-resolve
  - RULE-SET,parspack,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - MATCH,🚀 PROXY
`

// writeClashConfig writes the static subscription config (clashConfig)
// to filename, byte-identical on every run.
func writeClashConfig(filename string) {
	if err := os.WriteFile(filename, []byte(clashConfig), 0644); err != nil {
		fmt.Printf("❌ Error writing config file: %v\n", err)
		return
	}
	fmt.Printf("✅ Wrote static config to %s\n", filename)
}

func formatValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return fmt.Sprintf("%q", val)
	case []string:
		var quoted []string
		for _, s := range val {
			quoted = append(quoted, fmt.Sprintf("%q", s))
		}
		return fmt.Sprintf("[%s]", strings.Join(quoted, ", "))
	case map[string]string:
		var res []string
		for k, v := range val {
			res = append(res, fmt.Sprintf("%s: %q", k, v))
		}
		return fmt.Sprintf("{%s}", strings.Join(res, ", "))
	case map[string]interface{}:
		var res []string
		for k, v := range val {
			res = append(res, fmt.Sprintf("%s: %v", k, formatValue(v)))
		}
		return fmt.Sprintf("{%s}", strings.Join(res, ", "))
	default:
		return fmt.Sprintf("%v", val)
	}
}
