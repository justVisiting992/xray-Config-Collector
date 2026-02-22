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
			// Common settings
			p["udp"] = true
			p["skip-cert-verify"] = true

			// ALPN for TLS
			if p["tls"] == true {
				p["alpn"] = []string{"h2", "http/1.1"}
			}

			// Explicitly disable any obfs/plugin to prevent "missing obfs password"
			p["plugin"] = nil
			p["plugin-opts"] = nil

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
		if pbk != "" {
			p["reality-opts"] = map[string]string{
				"public-key": pbk,
				"short-id":   sid,
			}
			p["flow"] = "xtls-rprx-vision"
		}
	}

	// Fingerprint: use from config if present, else chrome if TLS
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
			// Force tls: true for these transports if not already set (prevents obfs misparse)
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

	// Explicitly remove any obfs/plugin to avoid "missing obfs password"
	delete(p, "plugin")
	delete(p, "plugin-opts")

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
		// Force tls if implied
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

	// No obfs/plugin
	delete(p, "plugin")
	delete(p, "plugin-opts")

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

	delete(p, "plugin")
	delete(p, "plugin-opts")

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

	user := u.User.Username()
	pass, hasPass := u.User.Password()
	if hasPass {
		p["cipher"] = user
		p["password"] = pass
	} else {
		p["cipher"] = "aes-256-gcm"
		p["password"] = user
	}

	if security := u.Query().Get("security"); security == "tls" {
		p["tls"] = true
		fp := u.Query().Get("fp")
		if fp != "" {
			p["client-fingerprint"] = fp
		} else {
			p["client-fingerprint"] = "chrome"
		}
	}

	delete(p, "plugin")
	delete(p, "plugin-opts")

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

	q := u.Query()
	if obfs := q.Get("obfs"); obfs != "" {
		p["obfs"] = obfs
	}
	if brutal := q.Get("brutal"); brutal != "" {
		p["brutal"] = brutal
	}

	// Hy2 doesn't use obfs-password, so no error risk
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