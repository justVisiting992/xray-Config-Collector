package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
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
	skipped := 0

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
		default:
			fmt.Printf("Skipped unsupported: %s\n", line[:50]+"...")
			skipped++
			continue
		}

		if parseErr != nil {
			fmt.Printf("Parse error skipped: %s | %v\n", line[:50]+"...", parseErr)
			skipped++
			continue
		}

		if p == nil {
			fmt.Printf("Nil proxy skipped: %s\n", line[:50]+"...")
			skipped++
			continue
		}

		// Common fixes
		p["udp"] = true
		p["skip-cert-verify"] = true

		if p["tls"] == true {
			p["alpn"] = []string{"h2", "http/1.1"}
		}

		// Ensure port is string/int
		if port, ok := p["port"].(string); ok {
			if _, err := strconv.Atoi(port); err != nil {
				fmt.Printf("Invalid port skipped: %s\n", p["name"])
				skipped++
				continue
			}
		}

		// Wipe legacy obfs/plugin
		delete(p, "plugin")
		delete(p, "plugin-opts")
		delete(p, "obfs")
		delete(p, "obfs-password")

		if name, ok := p["name"].(string); ok {
			p["name"] = sanitizeString(name)
		}

		proxies = append(proxies, p)
	}

	writeClashYaml(outputFile, proxies)
	fmt.Printf("\nWrote %d proxies | Skipped %d\n", len(proxies), skipped)
}

func sanitizeString(s string) string {
	// Your original sanitize
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

	// UUID validation
	if uuid := p["uuid"].(string); !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(uuid) {
		return nil, fmt.Errorf("invalid UUID")
	}

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
			} else {
				headers["Host"] = p["server"].(string)
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

// ... (parseVmess, parseTrojan, parseSS, parseHy2 remain as in previous full code)

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
			val := p[k]
			// Skip nil values
			if val == nil {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s: %v", k, formatValue(val)))
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