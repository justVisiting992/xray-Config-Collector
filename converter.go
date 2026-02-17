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
			// Sanitize name to prevent UTF-8 errors in Clash
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
		p["reality-opts"] = map[string]string{
			"public-key": q.Get("pbk"),
			"short-id":   q.Get("sid"),
		}
	}
	net := q.Get("type")
	if net == "ws" {
		p["network"] = "ws"
		p["ws-opts"] = map[string]interface{}{
			"path":    q.Get("path"),
			"headers": map[string]string{"Host": q.Get("host")},
		}
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
	json.Unmarshal(decoded, &v)
	p := make(Proxy)
	p["type"] = "vmess"
	p["name"] = fmt.Sprintf("%v", v["ps"])
	p["server"] = v["add"]
	p["port"] = v["port"]
	p["uuid"] = v["id"]
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
	// Hardcoded fix for the "unknown method" error
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
	f, _ := os.Create(filename)
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
	fmt.Printf("✅ Success: Wrote %d proxies to %s\n", len(proxies), filename)
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
