package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

type Proxy map[string]interface{}

func main() {
	inputFile := "mixed_iran.txt"
	outputFile := "clash.yaml"

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
			delete(p, "obfs")
			delete(p, "obfs-password")

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

	writeClashYaml(outputFile, proxies)
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
			p["flow"] = "xtls-rprx-vision"
		}
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
		if network == "ws" || network == "httpupgrade" || network == "grpc" {
			p["tls"] = true
		}
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
		}
	} else {
		p["network"] = "tcp"
	}

	return p, nil
}

func parseVmess(raw string) (Proxy, error) {
	data := strings.TrimPrefix(raw, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(data)
		if err != nil {
			return nil, err
		}
	}

	var v map[string]interface{}
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, err
	}

	p := make(Proxy)
	p["type"] = "vmess"
	p["name"] = fmt.Sprintf("%v", v["ps"])
	p["server"] = v["add"]
	p["port"] = v["port"]
	p["uuid"] = v["id"]
	p["alterId"] = 0
	p["cipher"] = "auto"

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
	p["network"] = "tcp"

	fp := u.Query().Get("fp")
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
			cipher, password = "aes-256-gcm", user
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
// Returns "", "" when the userinfo is not a decodable method:password pair.
func decodeSSUserinfo(raw string) (string, string) {
	base := strings.Split(raw, "#")[0]
	base = strings.TrimPrefix(base, "ss://")
	atIdx := strings.LastIndex(base, "@")
	if atIdx == -1 {
		return "", ""
	}
	userinfo := base[:atIdx]
	// PathUnescape, not QueryUnescape: '+' is a valid base64 character
	// in the userinfo and must not become a space.
	if unescaped, err := url.PathUnescape(userinfo); err == nil {
		userinfo = unescaped
	}
	// Plain form: ss://cipher:password@host:port
	if parts := strings.SplitN(userinfo, ":", 2); len(parts) == 2 && parts[0] != "" {
		return parts[0], parts[1]
	}
	// Classic form: ss://base64(cipher:password)@host:port.
	// Try URL-safe and standard base64, with and without padding,
	// mirroring main.go's isValidShadowsocks().
	padded := userinfo + strings.Repeat("=", (4-len(userinfo)%4)%4)
	for _, decode := range []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
	} {
		decoded, err := decode(padded)
		if err != nil {
			decoded, err = decode(userinfo)
			if err != nil {
				continue
			}
		}
		if parts := strings.SplitN(string(decoded), ":", 2); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return parts[0], parts[1]
		}
	}
	return "", ""
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
	if obfs := q.Get("obfs"); obfs != "" {
		p["obfs"] = obfs
	}
	if brutal := q.Get("brutal"); brutal != "" {
		p["brutal"] = brutal
	}

	return p, nil
}

func writeClashYaml(filename string, proxies []Proxy) {
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
