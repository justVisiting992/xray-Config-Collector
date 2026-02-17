package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
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
		os.Exit(0) // Don't fail the workflow, just exit
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
			// Global defaults for all proxies based on your sample
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
	p["tfo"] = false // Default in your sample

	// Map Query Params
	if flow := q.Get("flow"); flow != "" {
		p["flow"] = flow
	}
	if fp := q.Get("fp"); fp != "" {
		p["client-fingerprint"] = fp
	}

	// Security & TLS
	security := q.Get("security")
	if security == "tls" || security == "reality" {
		p["tls"] = true
		if sni := q.Get("sni"); sni != "" {
			p["servername"] = sni
		}
	}

	// Reality specific
	if security == "reality" {
		p["reality-opts"] = map[string]string{
			"public-key": q.Get("pbk"),
			"short-id":   q.Get("sid"),
		}
	}

	// Network types
	net := q.Get("type") // sometimes 'net' or 'type' in links
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
			"grpc-mode":         q.Get("mode"), // usually 'gun' or 'multi'
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
	p["tls"] = true // Trojan is always TLS
	
	if sni := q.Get("sni"); sni != "" {
		p["servername"] = sni
	} else {
		p["servername"] = u.Hostname()
	}

	// Trojan usually supports similar transports to Vless
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
	// Fix standard padding if missing
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
	
	// Handle Port (can be string or float in JSON)
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

	// Transport
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

	// TLS
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

	// Decode userinfo: method:password (Base64'd)
	user := u.User.String()
	decoded, err := base64.StdEncoding.DecodeString(user)
	if err == nil {
		parts := strings.Split(string(decoded), ":")
		if len(parts) == 2 {
			p["cipher"] = parts[0]
			p["password"] = parts[1]
		}
	} else {
		// Sometimes it's plain text in link
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
		// We manually format to match the "Flow Style" requested:
		// - { key: val, key2: val2 }
		line := formatProxyLine(p)
		w.WriteString(line + "\n")
	}
	w.Flush()
	fmt.Printf("✅ Generated %s with %d proxies.\n", filename, len(proxies))
}

func formatProxyLine(p Proxy) string {
	var parts []string
	
	// Order matters for aesthetics? User sample had name, server, port first.
	// We force specific order for common fields, map sort the rest.
	priority := []string{"name", "server", "port", "type", "uuid", "password", "cipher"}
	
	// Process priority keys first
	for _, key := range priority {
		if val, ok := p[key]; ok {
			parts = append(parts, fmt.Sprintf("%s: %v", key, formatValue(val)))
			delete(p, key) // Remove so we don't add it again
		}
	}

	// Sort remaining keys alphabetically
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
		// Only quote if necessary (simplified check)
		if strings.ContainsAny(val, ": {}[],") || val == "" {
			return fmt.Sprintf("%q", val)
		}
		return val
	case int, float64, bool:
		return fmt.Sprintf("%v", val)
	case map[string]string:
		// Handle nested simple maps like reality-opts
		var subParts []string
		for k, v := range val {
			subParts = append(subParts, fmt.Sprintf("%s: %v", k, formatValue(v)))
		}
		return fmt.Sprintf("{%s}", strings.Join(subParts, ", "))
	case map[string]interface{}:
		// Handle deeper nested maps like ws-opts
		var subParts []string
		for k, v := range val {
			subParts = append(subParts, fmt.Sprintf("%s: %v", k, formatValue(v)))
		}
		return fmt.Sprintf("{%s}", strings.Join(subParts, ", "))
	default:
		return fmt.Sprintf("%v", val)
	}
}