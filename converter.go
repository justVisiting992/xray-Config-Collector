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
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var p Proxy
		var parseErr error

		switch {
		case strings.HasPrefix(line, "vless://"):
			p, parseErr = parseVless(line)
		case strings.HasPrefix(line, "vmess://"):
			p, parseErr = parseVmess(line)
		case strings.HasPrefix(line, "trojan://"):
			p, parseErr = parseTrojan(line)
		case strings.HasPrefix(line, "ss://"):
			p, parseErr = parseSS(line)
		case strings.HasPrefix(line, "hysteria2://") || strings.HasPrefix(line, "hy2://"):
			p, parseErr = parseHy2(line)
		}

		if parseErr == nil && p != nil {
			p["skip-cert-verify"] = true
			p["udp"] = true
			// Modern Mihomo fingerprint requirement
			p["client-fingerprint"] = "chrome"

			if name, ok := p["name"].(string); ok {
				p["name"] = sanitizeString(name)
			}

			proxies = append(proxies, p)
		}
	}

	writeClashYaml(outputFile, proxies)
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

		// Validate public-key: must exist, be base64-like, typical length 43-44 chars
		if pbk == "" || len(pbk) < 32 || len(pbk) > 64 {
			// Invalid or missing public-key → skip Reality opts, fallback to regular TLS
			// (or return nil, err to drop proxy entirely - safer but loses some nodes)
			// Here we fallback to TLS
			security = "tls" // prevent adding broken reality-opts
		} else {
			// Optional: stricter base64 check
			if _, err := base64.URLEncoding.DecodeString(pbk); err != nil {
				// Not valid base64 → drop Reality
				security = "tls"
			} else {
				// Valid → add opts
				p["reality-opts"] = map[string]string{
					"public-key": pbk,
					"short-id":   sid,
				}
			}
		}
	}

	if q.Get("type") == "ws" {
		p["network"] = "ws"
		p["ws-opts"] = map[string]interface{}{
			"path":    q.Get("path"),
			"headers": map[string]string{"Host": q.Get("host")},
		}
	}

	// Final check: if reality was intended but we dropped opts, ensure tls is still true
	if security == "reality" && p["reality-opts"] == nil {
		p["tls"] = true
	}

	return p, nil
}

func parseVmess(raw string) (Proxy, error) {
	data := strings.TrimPrefix(raw, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
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

	if v["net"] == "ws" {
		p["network"] = "ws"
		p["ws-opts"] = map[string]interface{}{
			"path":    v["path"],
			"headers": map[string]string{"Host": fmt.Sprintf("%v", v["host"])},
		}
	}

	if v["tls"] == "tls" {
		p["tls"] = true
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
	p["cipher"] = "aes-256-gcm"
	p["password"] = u.User.Username()
	return p, nil
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