package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Proxy represents the internal structure for a Clash proxy
type Proxy struct {
	Name           string
	Type           string
	Server         string
	Port           int
	UUID           string
	Password       string
	Cipher         string // For SS
	UDP            bool
	TLS            bool
	SkipCertVerify bool
	ServerName     string // SNI
	Network        string // "ws", "grpc", "tcp"
	Flow           string // xtls-rprx-vision
	// Reality / Fingerprint
	RealityShortId string
	RealityPubKey  string
	Fingerprint    string
	// Transport
	WSPath         string
	WSHeaders      map[string]string
	GRPCServiceName string
}

// VMessJSON represents the standard VMess share link JSON format
type VMessJSON struct {
	Add  string      `json:"add"`
	Port interface{} `json:"port"` // Can be string or int
	Id   string      `json:"id"`
	Aid  interface{} `json:"aid"`
	Net  string      `json:"net"`
	Type string      `json:"type"`
	Host string      `json:"host"`
	Path string      `json:"path"`
	Tls  string      `json:"tls"`
	Sni  string      `json:"sni"`
	Alpn string      `json:"alpn"`
	Fp   string      `json:"fp"`
}

func main() {
	// 1. Read the harvested configs
	file, err := os.Open("mixed_iran.txt")
	if err != nil {
		fmt.Println("❌ Error: Could not find mixed_iran.txt. Run main.go first.")
		return
	}
	defer file.Close()

	var proxies []Proxy
	seenNames := make(map[string]int)
	scanner := bufio.NewScanner(file)

	fmt.Println("⏳ Parsing proxies...")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		p, ok := parseLink(line)
		if ok {
			// Deduplicate Names
			if count, exists := seenNames[p.Name]; exists {
				seenNames[p.Name]++
				p.Name = fmt.Sprintf("%s %d", p.Name, count+1)
			} else {
				seenNames[p.Name] = 1
			}
			proxies = append(proxies, p)
		}
	}

	if len(proxies) == 0 {
		fmt.Println("⚠️ No valid proxies found.")
		return
	}

	fmt.Printf("✅ Parsed %d proxies.\n", len(proxies))

	// 2. Generate the full YAML
	fmt.Println("📝 Generating clash_meta_iran.yaml...")
	finalConfig := generateConfig(proxies)

	// 3. Write to file
	err = os.WriteFile("clash_meta_iran.yaml", []byte(finalConfig), 0644)
	if err != nil {
		fmt.Printf("❌ Error writing file: %v\n", err)
	} else {
		fmt.Println("🎉 Success! 'clash_meta_iran.yaml' is ready.")
	}
}

// parseLink handles vless, vmess, trojan, ss
func parseLink(link string) (Proxy, bool) {
	link = strings.TrimSpace(link)
	if strings.HasPrefix(link, "vmess://") {
		return parseVMess(link)
	} else if strings.HasPrefix(link, "vless://") {
		return parseVLESS(link)
	} else if strings.HasPrefix(link, "trojan://") {
		return parseTrojan(link)
	} else if strings.HasPrefix(link, "ss://") {
		return parseSS(link)
	}
	return Proxy{}, false
}

func parseVMess(link string) (Proxy, bool) {
	b64 := strings.TrimPrefix(link, "vmess://")
	// padding fix
	if r := len(b64) % 4; r > 0 {
		b64 += strings.Repeat("=", 4-r)
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return Proxy{}, false
	}

	var v VMessJSON
	if err := json.Unmarshal(decoded, &v); err != nil {
		return Proxy{}, false
	}

	p := Proxy{
		Type:           "vmess",
		Server:         v.Add,
		UUID:           v.Id,
		Name:           "VMess Node",
		UDP:            true,
		SkipCertVerify: true,
		Network:        v.Net,
		WSPath:         v.Path,
		ServerName:     v.Sni,
		Fingerprint:    v.Fp,
	}
	
	// Handle Port (can be string or float/int in JSON)
	switch portVal := v.Port.(type) {
	case string:
		p.Port, _ = strconv.Atoi(portVal)
	case float64:
		p.Port = int(portVal)
	}

	if v.Tls == "tls" {
		p.TLS = true
	}
	// Fallback name if standard name is missing
	if v.Add != "" {
		p.Name = "VMess-" + v.Add
	}
	// WS Host mapping
	if v.Net == "ws" && v.Host != "" {
		p.WSHeaders = map[string]string{"Host": v.Host}
		if p.ServerName == "" { p.ServerName = v.Host }
	}

	return p, true
}

func parseVLESS(link string) (Proxy, bool) {
	u, err := url.Parse(link)
	if err != nil {
		return Proxy{}, false
	}
	
	q := u.Query()
	p := Proxy{
		Type:           "vless",
		Server:         u.Hostname(),
		UUID:           u.User.String(),
		Name:           u.Fragment,
		UDP:            true,
		SkipCertVerify: true,
		Network:        q.Get("type"),
		ServerName:     q.Get("sni"),
		Flow:           q.Get("flow"),
		Fingerprint:    q.Get("fp"),
		// Reality fields
		RealityPubKey:  q.Get("pbk"),
		RealityShortId: q.Get("sid"),
		// Transport
		WSPath:          q.Get("path"),
		GRPCServiceName: q.Get("serviceName"),
	}

	if p.Name == "" { p.Name = "VLESS-" + p.Server }
	p.Port, _ = strconv.Atoi(u.Port())

	// Security
	security := q.Get("security")
	if security == "tls" || security == "reality" {
		p.TLS = true
	}
	
	if p.Network == "" { p.Network = "tcp" } // default

	return p, true
}

func parseTrojan(link string) (Proxy, bool) {
	u, err := url.Parse(link)
	if err != nil {
		return Proxy{}, false
	}

	q := u.Query()
	p := Proxy{
		Type:           "trojan",
		Server:         u.Hostname(),
		Password:       u.User.String(),
		Name:           u.Fragment,
		UDP:            true,
		SkipCertVerify: true,
		Network:        q.Get("type"),
		ServerName:     q.Get("sni"),
		WSPath:         q.Get("path"),
		GRPCServiceName: q.Get("serviceName"),
		TLS:            true, // Trojan is always TLS
	}

	if p.Name == "" { p.Name = "Trojan-" + p.Server }
	p.Port, _ = strconv.Atoi(u.Port())
	if p.Network == "" { p.Network = "tcp" }

	return p, true
}

func parseSS(link string) (Proxy, bool) {
	// Simple SS parsing (SIP002 usually)
	u, err := url.Parse(link)
	if err != nil {
		return Proxy{}, false
	}
	
	p := Proxy{
		Type:   "ss",
		Server: u.Hostname(),
		Name:   u.Fragment,
		UDP:    true,
	}
	p.Port, _ = strconv.Atoi(u.Port())
	if p.Name == "" { p.Name = "SS-" + p.Server }

	userInfo := u.User.String()
	// Usually base64 encoded method:password
	// But go url.Parse handles standard user:pass if not encoded.
	// If it looks like a base64 string (no colon), decode it
	if !strings.Contains(userInfo, ":") {
		decoded, err := base64.StdEncoding.DecodeString(userInfo)
		if err == nil {
			userInfo = string(decoded)
		}
	}
	
	parts := strings.SplitN(userInfo, ":", 2)
	if len(parts) == 2 {
		p.Cipher = parts[0]
		p.Password = parts[1]
		return p, true
	}
	return Proxy{}, false
}

// generateConfig builds the massive YAML string
func generateConfig(proxies []Proxy) string {
	var sb strings.Builder

	// 1. Static Header (Your provided Config)
	sb.WriteString(headerTemplate)

	// 2. Proxies List
	sb.WriteString("\nproxies:\n")
	var proxyNames []string
	
	for _, p := range proxies {
		proxyYAML := proxyToYAML(p)
		if proxyYAML != "" {
			sb.WriteString(proxyYAML)
			proxyNames = append(proxyNames, p.Name)
		}
	}

	// 3. Proxy Groups
	// We must redefine the proxy groups to use our generated proxy names
	// instead of the "use: - proxy" provider method, or create a group that holds them.
	sb.WriteString("\nproxy-groups:\n")
	
	// Group 1: The Scraped List (Auto Test)
	sb.WriteString("  - name: 🚀 Auto-Scraped\n")
	sb.WriteString("    type: url-test\n")
	sb.WriteString("    url: https://cp.cloudflare.com/generate_204\n")
	sb.WriteString("    interval: 300\n")
	sb.WriteString("    tolerance: 50\n")
	sb.WriteString("    proxies:\n")
	for _, n := range proxyNames {
		sb.WriteString("      - " + n + "\n")
	}

	// Group 2: Manual Selection (Select)
	sb.WriteString("  - name: 🤏🏻 Manual-Scraped\n")
	sb.WriteString("    type: select\n")
	sb.WriteString("    proxies:\n")
	for _, n := range proxyNames {
		sb.WriteString("      - " + n + "\n")
	}

	// Injecting the rest of your groups, but modifying them to point to our new groups
	sb.WriteString(groupsTemplate)

	// 4. Rule Providers and Rules (Static)
	sb.WriteString(rulesTemplate)

	return sb.String()
}

func proxyToYAML(p Proxy) string {
	var sb strings.Builder
	// Basic indent
	sb.WriteString(fmt.Sprintf("  - name: %s\n", p.Name))
	sb.WriteString(fmt.Sprintf("    type: %s\n", p.Type))
	sb.WriteString(fmt.Sprintf("    server: %s\n", p.Server))
	sb.WriteString(fmt.Sprintf("    port: %d\n", p.Port))
	sb.WriteString("    udp: true\n")
	
	if p.UUID != "" { sb.WriteString(fmt.Sprintf("    uuid: %s\n", p.UUID)) }
	if p.Password != "" { sb.WriteString(fmt.Sprintf("    password: %s\n", p.Password)) }
	if p.Cipher != "" { sb.WriteString(fmt.Sprintf("    cipher: %s\n", p.Cipher)) }
	
	if p.TLS {
		sb.WriteString("    tls: true\n")
		sb.WriteString("    skip-cert-verify: true\n")
		if p.ServerName != "" {
			sb.WriteString(fmt.Sprintf("    servername: %s\n", p.ServerName))
		}
		if p.RealityPubKey != "" {
			sb.WriteString("    reality-opts:\n")
			sb.WriteString(fmt.Sprintf("      public-key: %s\n", p.RealityPubKey))
			if p.RealityShortId != "" {
				sb.WriteString(fmt.Sprintf("      short-id: %s\n", p.RealityShortId))
			}
		}
		// Fingerprint (Client Hello)
		if p.Fingerprint != "" {
			sb.WriteString(fmt.Sprintf("    client-fingerprint: %s\n", p.Fingerprint))
		} else {
			sb.WriteString("    client-fingerprint: chrome\n") // default to chrome
		}
	}

	if p.Flow != "" {
		sb.WriteString(fmt.Sprintf("    flow: %s\n", p.Flow))
	}

	if p.Network != "" && p.Network != "tcp" {
		sb.WriteString(fmt.Sprintf("    network: %s\n", p.Network))
		
		if p.Network == "ws" {
			sb.WriteString("    ws-opts:\n")
			sb.WriteString(fmt.Sprintf("      path: %s\n", p.WSPath))
			if len(p.WSHeaders) > 0 {
				sb.WriteString("      headers:\n")
				for k, v := range p.WSHeaders {
					sb.WriteString(fmt.Sprintf("        %s: %s\n", k, v))
				}
			}
		} else if p.Network == "grpc" {
			sb.WriteString("    grpc-opts:\n")
			sb.WriteString(fmt.Sprintf("      grpc-service-name: %s\n", p.GRPCServiceName))
		}
	}
	return sb.String()
}

// ---------------------------------------------------------
// TEMPLATES (Matches your provided high-end config)
// ---------------------------------------------------------

const headerTemplate = `global-client-fingerprint: chrome 
port: 7890 
socks-port: 7891 
redir-port: 7892 
mixed-port: 7893 
tproxy-port: 7894 
allow-lan: true 
tcp-concurrent: true 
enable-process: true 
find-process-mode: strict 
ipv6: true 
log-level: info 
geo-auto-update: true 
geo-update-interval: 168 
secret: '' 
bind-address: '*' 
unified-delay: false 
profile: 
  store-selected: true 
  store-fake-ip: true 
dns: 
  enable: true 
  ipv6: true 
  respect-rules: false 
  prefer-h3: true 
  cache-algorithm: arc    
  use-system-hosts: true 
  use-host: true 
  listen: 0.0.0.0:53 
  enhanced-mode: fake-ip 
  fake-ip-filter-mode: blacklist 
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: 
    - '*.lan'              
    - '*.localdomain'      
    - '*.invalid'          
    - '*.localhost'        
    - '*.test'             
    - '*.local'            
    - '*.home.arpa' 
    - 'time.*.com' 
    - 'ntp.*.com' 
    - '*.ir' 
  default-nameserver: 
    - 8.8.8.8 
    - 1.1.1.1 
    - 223.5.5.5 
  nameserver:
    - 'https://sky.rethinkdns.com/1:-J8AGH8C7_2-___f3_vZ3f_z-f9KagBI'
    - 'tls://1-7cpqagd7alx73px777p5766z3x77h6p7jjvaasa.max.rethinkdns.com'
    - 'https://dns.google/dns-query'
  direct-nameserver:
    - '78.157.42.100'
    - 'system'

sniffer: 
  enable: true 
  force-dns-mapping: true 
  parse-pure-ip: true 
  override-destination: false 
  sniff: 
    HTTP: 
      ports: [80, 8080, 8880] 
    TLS: 
      ports: [443, 8443] 

tun: 
  enable: true 
  stack: mixed 
  auto-route: true 
  auto-detect-interface: true 
  dns-hijack: 
    - "any:53" 
`

const groupsTemplate = `  - name: نوع انتخاب پروکسی 🔀 
    icon: https://www.svgrepo.com/show/412721/choose.svg 
    type: select 
    proxies: 
      - 🚀 Auto-Scraped
      - 🤏🏻 Manual-Scraped
      - اتصال پایدار 🔗 
      - قطع اینترنت ⛔ 
      - بدون فیلترشکن 🛡️ 

  - name: اتصال پایدار 🔗 
    type: url-test 
    icon: https://www.svgrepo.com/show/428774/connection-internet-communication.svg 
    url: https://cp.cloudflare.com/generate_204 
    interval: 60
    tolerance: 400
    lazy: true 
    proxies: 
      - 🚀 Auto-Scraped
      - 🤏🏻 Manual-Scraped

  - name: تلگرام 💬
    type: select
    icon: https://www.svgrepo.com/show/354443/telegram.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - 🚀 Auto-Scraped
      - 🤏🏻 Manual-Scraped
      - بدون فیلترشکن 🛡️

  - name: یوتیوب ▶️
    type: select
    icon: https://www.svgrepo.com/show/475700/youtube-color.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - 🚀 Auto-Scraped
      - 🤏🏻 Manual-Scraped

  - name: گوگل 🌍
    type: select
    icon: https://www.svgrepo.com/show/475656/google-color.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - 🚀 Auto-Scraped
      - 🤏🏻 Manual-Scraped
      - بدون فیلترشکن 🛡️

  - name: اینستاگرام 📸
    type: select
    icon: https://www.svgrepo.com/show/452229/instagram-1.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - 🚀 Auto-Scraped
      - 🤏🏻 Manual-Scraped

  - name: هوش مصنوعی 🤖
    type: select
    icon: https://www.svgrepo.com/show/306500/openai.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - 🚀 Auto-Scraped

  - name: سایتای ایرانی 🇮🇷
    type: select
    icon: https://upload.wikimedia.org/wikipedia/commons/3/36/Flag_of_Iran_%28civil%29.svg
    proxies:
      - بدون فیلترشکن 🛡️
      - نوع انتخاب پروکسی 🔀

  - name: تبلیغات 🆎
    type: select
    proxies:
      - اجازه ندادن 🚫
      - بدون فیلترشکن 🛡️

  - name: بدون فیلترشکن 🛡️
    type: select
    icon: https://www.svgrepo.com/show/6318/connection.svg
    proxies:
      - DIRECT
    hidden: true
  - name: قطع اینترنت ⛔
    type: select
    icon: https://www.svgrepo.com/show/305372/wifi-off.svg
    proxies:
      - REJECT
    hidden: true
  - name: اجازه ندادن 🚫
    type: select
    icon: https://www.svgrepo.com/show/444307/gui-ban.svg
    proxies:
      - REJECT
    hidden: true
`

const rulesTemplate = `
rule-providers: 
  iran_ads: 
    type: http 
    behavior: domain 
    url: https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/clash_rules_ads.yaml 
    interval: 86400 
    path: ./ruleset/iran_ads.yaml 
  youtube: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/youtube.yaml 
    interval: 86400 
    path: ./ruleset/youtube.yaml 
  telegram: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/telegram.yaml 
    interval: 86400 
    path: ./ruleset/telegram.yaml 
  censor: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/clash_rules/main/censor.yaml 
    interval: 86400 
    path: ./ruleset/tahrim.yaml 
  iran: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/clash_rules/main/iran.yaml 
    interval: 86400 
    path: ./ruleset/iran.yaml 
  google: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/google.yaml 
    interval: 86400 
    path: ./ruleset/google.yaml 
  instagram: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/instagram.yaml 
    interval: 86400 
    path: ./ruleset/instagram.yaml 
  category-ai: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/category-ai-!cn.yaml 
    interval: 86400 
    path: ./ruleset/category-ai.yaml 

rules: 
  - RULE-SET,iran_ads,تبلیغات 🆎 
  - PROCESS-NAME,Telegram.exe,تلگرام 💬 
  - RULE-SET,telegram,تلگرام 💬 
  - RULE-SET,youtube,یوتیوب ▶️ 
  - DOMAIN-SUFFIX,instagram.com,اینستاگرام 📸 
  - RULE-SET,instagram,اینستاگرام 📸 
  - RULE-SET,category-ai,هوش مصنوعی 🤖 
  - RULE-SET,censor,نوع انتخاب پروکسی 🔀 
  - RULE-SET,iran,سایتای ایرانی 🇮🇷 
  - RULE-SET,google,گوگل 🌍
  - GEOIP,IR,سایتای ایرانی 🇮🇷 
  - MATCH,نوع انتخاب پروکسی 🔀 
`