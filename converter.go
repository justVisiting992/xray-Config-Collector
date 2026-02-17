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
)

// Proxy represents a generic proxy config map
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

	fmt.Println("⏳ Parsing proxies...")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
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
			proxies = append(proxies, p)
		}
	}

	writeClashYaml(outputFile, proxies)
}

// --- PARSERS ---

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
	p["tfo"] = false 

	if flow := q.Get("flow"); flow != "" {
		p["flow"] = flow
	}
	if fp := q.Get("fp"); fp != "" {
		p["client-fingerprint"] = fp
	}

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
	if net == "" {
		net = q.Get("net")
	}
	if net == "" {
		net = "tcp"
	}

	if net == "ws" {
		p["network"] = "ws"
		headers := make(map[string]string)
		if host := q.Get("host"); host != "" {
			headers["Host"] = host
		}
		path := q.Get("path")
		if path == "" {
			path = "/"
		}
		p["ws-opts"] = map[string]interface{}{
			"path":    path,
			"headers": headers,
		}
	} else if net == "grpc" {
		p["network"] = "grpc"
		p["grpc-opts"] = map[string]string{
			"grpc-service-name": q.Get("serviceName"),
			"grpc-mode":         q.Get("mode"), 
		}
	}

	return p, nil
}

func parseTrojan(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()

	p := make(Proxy)
	p["type"] = "trojan"
	p["name"] = u.Fragment
	p["server"] = u.Hostname()
	p["port"] = u.Port()
	p["password"] = u.User.Username()
	p["tls"] = true 
	
	if sni := q.Get("sni"); sni != "" {
		p["servername"] = sni
	} else {
		p["servername"] = u.Hostname()
	}

	net := q.Get("type")
	if net == "ws" {
		p["network"] = "ws"
		headers := make(map[string]string)
		if host := q.Get("host"); host != "" {
			headers["Host"] = host
		}
		p["ws-opts"] = map[string]interface{}{
			"path":    q.Get("path"),
			"headers": headers,
		}
	}

	return p, nil
}

func parseVmess(raw string) (Proxy, error) {
	b64 := strings.TrimPrefix(raw, "vmess://")
	if i := len(b64) % 4; i != 0 {
		b64 += strings.Repeat("=", 4-i)
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	var v map[string]interface{}
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, err
	}

	p := make(Proxy)
	p["type"] = "vmess"
	p["name"] = v["ps"]
	p["server"] = v["add"]
	p["uuid"] = v["id"]
	p["cipher"] = "auto"
	
	switch port := v["port"].(type) {
	case string:
		p["port"] = port
	case float64:
		p["port"] = int(port)
	}

	p["alterId"] = 0
	if aid, ok := v["aid"]; ok {
		p["alterId"] = aid
	}

	net := fmt.Sprintf("%v", v["net"])
	if net == "ws" {
		p["network"] = "ws"
		headers := make(map[string]string)
		if host, ok := v["host"].(string); ok && host != "" {
			headers["Host"] = host
		}
		p["ws-opts"] = map[string]interface{}{
			"path":    v["path"],
			"headers": headers,
		}
	} else if net == "grpc" {
		p["network"] = "grpc"
		p["grpc-opts"] = map[string]string{
			"grpc-service-name": fmt.Sprintf("%v", v["path"]),
		}
	}

	if tls, ok := v["tls"].(string); ok && tls == "tls" {
		p["tls"] = true
		if sni, ok := v["sni"].(string); ok && sni != "" {
			p["servername"] = sni
		} else if host, ok := v["host"].(string); ok && host != "" {
			p["servername"] = host
		}
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

	user := u.User.String()
	decoded, err := base64.StdEncoding.DecodeString(user)
	if err == nil {
		parts := strings.Split(string(decoded), ":")
		if len(parts) == 2 {
			p["cipher"] = parts[0]
			p["password"] = parts[1]
		}
	} else {
		p["cipher"] = u.User.Username()
		p["password"], _ = u.User.Password()
	}
	
	return p, nil
}

func parseHy2(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()

	p := make(Proxy)
	p["type"] = "hysteria2"
	p["name"] = u.Fragment
	p["server"] = u.Hostname()
	p["port"] = u.Port()
	p["password"] = u.User.Username()
	
	if sni := q.Get("sni"); sni != "" {
		p["sni"] = sni
	} else {
		p["sni"] = u.Hostname()
	}
	
	if obfs := q.Get("obfs"); obfs != "" {
		p["obfs"] = obfs
		p["obfs-password"] = q.Get("obfs-password")
	}

	return p, nil
}

// --- WRITER ---

func writeClashYaml(filename string, proxies []Proxy) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	w.WriteString("proxies:\n")

	for _, p := range proxies {
		line := formatProxyLine(p)
		w.WriteString(line + "\n")
	}
	w.Flush()
	fmt.Printf("✅ Generated %s with %d proxies.\n", filename, len(proxies))
}

func formatProxyLine(p Proxy) string {
	var parts []string
	
	priority := []string{"name", "server", "port", "type", "uuid", "password", "cipher"}
	
	for _, key := range priority {
		if val, ok := p[key]; ok {
			parts = append(parts, fmt.Sprintf("%s: %v", key, formatValue(val)))
			delete(p, key) 
		}
	}

	var keys []string
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %v", k, formatValue(p[k])))
	}

	return fmt.Sprintf("  - {%s}", strings.Join(parts, ", "))
}

func formatValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		// Wrap in quotes if it contains YAML-breaking characters or is potentially interpreted as a non-string
		if val == "" || strings.ContainsAny(val, ":{}[],&*#?|-<>=!%@ ") || strings.Contains(val, ".") || strings.Contains(val, "/") {
			return fmt.Sprintf("%q", val)
		}
		return val
	case int, float64, bool:
		return fmt.Sprintf("%v", val)
	case map[string]string:
		var subParts []string
		var keys []string
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			subParts = append(subParts, fmt.Sprintf("%s: %v", k, formatValue(val[k])))
		}
		return fmt.Sprintf("{%s}", strings.Join(subParts, ", "))
	case map[string]interface{}:
		var subParts []string
		var keys []string
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			subParts = append(subParts, fmt.Sprintf("%s: %v", k, formatValue(val[k])))
		}
		return fmt.Sprintf("{%s}", strings.Join(subParts, ", "))
	default:
		return fmt.Sprintf("%v", val)
	}
}
