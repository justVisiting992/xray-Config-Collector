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
	Name            string
	Type            string
	Server          string
	Port            int
	UUID            string
	Password        string
	Cipher          string
	UDP             bool
	TLS             bool
	SkipCertVerify  bool
	ServerName      string
	Network         string
	Flow            string
	RealityShortId  string
	RealityPubKey   string
	Fingerprint     string
	WSPath          string
	WSHeaders       map[string]string
	GRPCServiceName string
}

type VMessJSON struct {
	Add  string      `json:"add"`
	Port interface{} `json:"port"`
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
	file, err := os.Open("mixed_iran.txt")
	if err != nil {
		fmt.Println("❌ Error: Could not find mixed_iran.txt.")
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

	finalConfig := generateConfig(proxies)
	err = os.WriteFile("clash_meta_iran.yaml", []byte(finalConfig), 0644)
	if err != nil {
		fmt.Printf("❌ Error writing file: %v\n", err)
	} else {
		fmt.Printf("🎉 Success! Generated %d proxies into 'clash_meta_iran.yaml'\n", len(proxies))
	}
}

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
	} else if strings.HasPrefix(link, "hysteria2://") || strings.HasPrefix(link, "hy2://") {
		return parseHy2(link)
	}
	return Proxy{}, false
}

func parseHy2(link string) (Proxy, bool) {
	u, err := url.Parse(link)
	if err != nil {
		return Proxy{}, false
	}
	p := Proxy{
		Type:           "hysteria2",
		Server:         u.Hostname(),
		Password:       u.User.String(),
		Name:           u.Fragment,
		UDP:            true,
		TLS:            true,
		SkipCertVerify: true,
		ServerName:     u.Query().Get("sni"),
	}
	p.Port, _ = strconv.Atoi(u.Port())
	if p.Name == "" { p.Name = "Hy2-" + p.Server }
	if dn, err := url.QueryUnescape(p.Name); err == nil { p.Name = dn }
	return p, true
}

func parseVMess(link string) (Proxy, bool) {
	b64 := strings.TrimPrefix(link, "vmess://")
	if r := len(b64)%4; r > 0 { b64 += strings.Repeat("=", 4-r) }
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil { return Proxy{}, false }
	var v VMessJSON
	if err := json.Unmarshal(decoded, &v); err != nil { return Proxy{}, false }
	p := Proxy{
		Type: "vmess", Server: v.Add, UUID: v.Id, Name: "VMess-" + v.Add,
		UDP: true, SkipCertVerify: true, Network: v.Net, WSPath: v.Path, ServerName: v.Sni, Fingerprint: v.Fp,
	}
	switch portVal := v.Port.(type) {
	case string: p.Port, _ = strconv.Atoi(portVal)
	case float64: p.Port = int(portVal)
	}
	if v.Tls == "tls" { p.TLS = true }
	if v.Net == "ws" && v.Host != "" {
		p.WSHeaders = map[string]string{"Host": v.Host}
		if p.ServerName == "" { p.ServerName = v.Host }
	}
	return p, true
}

func parseVLESS(link string) (Proxy, bool) {
	u, err := url.Parse(link)
	if err != nil { return Proxy{}, false }
	q := u.Query()
	p := Proxy{
		Type: "vless", Server: u.Hostname(), UUID: u.User.String(), Name: u.Fragment,
		UDP: true, SkipCertVerify: true, Network: q.Get("type"), ServerName: q.Get("sni"),
		Flow: q.Get("flow"), Fingerprint: q.Get("fp"), RealityPubKey: q.Get("pbk"), RealityShortId: q.Get("sid"),
		WSPath: q.Get("path"), GRPCServiceName: q.Get("serviceName"),
	}
	if p.Name == "" { p.Name = "VLESS-" + p.Server }
	if dn, err := url.QueryUnescape(p.Name); err == nil { p.Name = dn }
	p.Port, _ = strconv.Atoi(u.Port())
	if q.Get("security") == "tls" || q.Get("security") == "reality" { p.TLS = true }
	return p, true
}

func parseTrojan(link string) (Proxy, bool) {
	u, err := url.Parse(link)
	if err != nil { return Proxy{}, false }
	q := u.Query()
	p := Proxy{
		Type: "trojan", Server: u.Hostname(), Password: u.User.String(), Name: u.Fragment,
		UDP: true, SkipCertVerify: true, Network: q.Get("type"), ServerName: q.Get("sni"),
		WSPath: q.Get("path"), GRPCServiceName: q.Get("serviceName"), TLS: true,
	}
	if p.Name == "" { p.Name = "Trojan-" + p.Server }
	if dn, err := url.QueryUnescape(p.Name); err == nil { p.Name = dn }
	p.Port, _ = strconv.Atoi(u.Port())
	return p, true
}

func parseSS(link string) (Proxy, bool) {
	u, err := url.Parse(link)
	if err != nil { return Proxy{}, false }
	p := Proxy{Type: "ss", Server: u.Hostname(), Name: u.Fragment, UDP: true}
	p.Port, _ = strconv.Atoi(u.Port())
	if p.Name == "" { p.Name = "SS-" + p.Server }
	userInfo := u.User.String()
	if !strings.Contains(userInfo, ":") {
		if decoded, err := base64.StdEncoding.DecodeString(userInfo); err == nil { userInfo = string(decoded) }
	}
	parts := strings.SplitN(userInfo, ":", 2)
	if len(parts) == 2 { p.Cipher = parts[0]; p.Password = parts[1]; return p, true }
	return Proxy{}, false
}

func generateConfig(proxies []Proxy) string {
	var sb strings.Builder
	sb.WriteString(headerTemplate)
	sb.WriteString("\nproxies:\n")
	
	var proxyNames []string
	for _, p := range proxies {
		proxyNames = append(proxyNames, p.Name)
		sb.WriteString(proxyToYAML(p))
	}

	// We create a special section for rule providers and then groups
	// To maintain your complex group structure, we'll inject the parsed proxies into the groups
	
	sb.WriteString("\nproxy-groups:\n")
	
	// Inject the proxies into the "نوع انتخاب پروکسی 🔀" group as requested
	sb.WriteString(generateProxyGroups(proxyNames))
	
	sb.WriteString(providerTemplate)
	sb.WriteString(rulesTemplate)
	return sb.String()
}

func proxyToYAML(p Proxy) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n", p.Name))
	sb.WriteString(fmt.Sprintf("    type: %s\n", p.Type))
	sb.WriteString(fmt.Sprintf("    server: %s\n", p.Server))
	sb.WriteString(fmt.Sprintf("    port: %d\n", p.Port))
	sb.WriteString("    udp: true\n")
	if p.UUID != "" { sb.WriteString(fmt.Sprintf("    uuid: %s\n", p.UUID)) }
	if p.Password != "" { sb.WriteString(fmt.Sprintf("    password: %s\n", p.Password)) }
	if p.Cipher != "" { sb.WriteString(fmt.Sprintf("    cipher: %s\n", p.Cipher)) }
	if p.TLS || p.Type == "hysteria2" {
		sb.WriteString("    tls: true\n    skip-cert-verify: true\n")
		if p.ServerName != "" { sb.WriteString(fmt.Sprintf("    servername: %s\n", p.ServerName)) }
		if p.RealityPubKey != "" {
			sb.WriteString(fmt.Sprintf("    reality-opts:\n      public-key: %s\n", p.RealityPubKey))
			if p.RealityShortId != "" { sb.WriteString(fmt.Sprintf("      short-id: %s\n", p.RealityShortId)) }
		}
		sb.WriteString(fmt.Sprintf("    client-fingerprint: %s\n", "chrome"))
	}
	if p.Network != "" && p.Network != "tcp" {
		sb.WriteString(fmt.Sprintf("    network: %s\n", p.Network))
		if p.Network == "ws" {
			sb.WriteString(fmt.Sprintf("    ws-opts:\n      path: \"%s\"\n", p.WSPath))
			if len(p.WSHeaders) > 0 {
				sb.WriteString("      headers:\n")
				for k, v := range p.WSHeaders { sb.WriteString(fmt.Sprintf("        %s: %s\n", k, v)) }
			}
		} else if p.Network == "grpc" {
			sb.WriteString(fmt.Sprintf("    grpc-opts:\n      grpc-service-name: \"%s\"\n", p.GRPCServiceName))
		}
	}
	return sb.String()
}

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
log-level: debug 
geo-auto-update: true 
geo-update-interval: 168 
secret: '' 
bind-address: '*' 
unified-delay: false 
disable-keep-alive: false 
keep-alive-idle: 30 
keep-alive-interval: 30 
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
    - 8.8.4.4 
    - 1.0.0.1 
    - 1.1.1.1 
    - 9.9.9.9 
    - 9.9.9.11 
    - 9.9.9.10 
    - 94.140.14.15 
    - 94.140.15.15 
    - 223.5.5.5 
    - 77.88.8.8
  nameserver:
    - 'https://sky.rethinkdns.com/1:-J8AGH8C7_2-___f3_vZ3f_z-f9KagBI'
    - 'tls://1-7cpqagd7alx73px777p5766z3x77h6p7jjvaasa.max.rethinkdns.com'
  direct-nameserver:
    - '78.157.42.100'
    - '78.157.42.101' 
  proxy-server-nameserver: 
    - '2606:4700:4700::1111' 
    - '2606:4700:4700::1001' 
    - '2001:4860:4860::8888' 
    - '2001:4860:4860::8844' 
    - '1.1.1.1' 
    - '8.8.8.8' 
    - '8.8.4.4' 
    - '9.9.9.9' 
    - '223.5.5.5' 
    - '77.88.8.8' 
    - '2400:3200::1' 
    - '2a02:6b8::feed:0ff' 
    - '2620:fe::fe' 

sniffer: 
  enable: true 
  force-dns-mapping: true 
  parse-pure-ip: true 
  override-destination: false 
  sniff: 
    HTTP: 
      ports: [80, 8080, 8880, 2052, 2082, 2086, 2095] 
    TLS: 
      ports: [443, 8443, 2053, 2083, 2087, 2096] 

tun: 
  enable: true 
  stack: mixed 
  auto-route: true 
  auto-detect-interface: true 
  auto-redir: true 
  dns-hijack: 
    - "any:53" 
    - "tcp://any:53" 
`

const providerTemplate = `
proxy-providers:
  proxy:
    type: http
    url: "https://raw.githubusercontent.com/vpnclashfa-backup/subconverter/refs/heads/main/output_configs/clash/rayan_proxy.yaml"
    interval: 3600
    path: "./rayan_proxy.yaml"
    health-check:
      enable: true
      interval: 3600
      url: "https://www.gstatic.com/generate_204"
`

func generateProxyGroups(names []string) string {
	var sb strings.Builder
	// Injected proxies for manual/auto selection
	proxyList := ""
	for _, n := range names {
		proxyList += "      - \"" + n + "\"\n"
	}

	sb.WriteString(`  - name: نوع انتخاب پروکسی 🔀 
    icon: https://www.svgrepo.com/show/412721/choose.svg 
    type: select 
    proxies: 
      - خودکار (بهترین پینگ) 🤖 
      - دستی 🤏🏻 
      - اتصال پایدار 🔗 
      - پشتیبان (در صورت قطعی) 🧯 
      - توزیع بار (پایدار) 🧲 
      - توزیع بار (موقت) ⏳ 
      - توزیع بار (گردشی) 🔁 
      - قطع اینترنت ⛔ 
      - بدون فیلترشکن 🛡️ 
  - name: دستی 🤏🏻 
    type: select 
    icon: https://www.svgrepo.com/show/372331/cursor-hand-click.svg 
    proxies:
` + proxyList + `    use: 
      - proxy 
  - name: خودکار (بهترین پینگ) 🤖 
    type: url-test 
    icon: https://www.svgrepo.com/show/7876/speedometer.svg 
    url: https://api.v2fly.org/checkConnection.svgz 
    interval: 600 
    timeout: 120000 
    tolerance: 500 
    max-failed-times: 6
    lazy: true 
    proxies:
` + proxyList + `    use: 
      - proxy 
  - name: پشتیبان (در صورت قطعی) 🧯 
    type: fallback 
    icon: https://www.svgrepo.com/show/415208/backup-cloud-document.svg 
    url: https://www.gstatic.com/generate_204 
    interval: 600 
    timeout: 120000 
    max-failed-times: 3 
    lazy: true 
    proxies:
` + proxyList + `    use: 
      - proxy 
  - name: اتصال پایدار 🔗 
    type: url-test 
    icon: https://www.svgrepo.com/show/428774/connection-internet-communication.svg 
    url: https://cp.cloudflare.com/generate_204 
    interval: 60
    timeout: 30000
    tolerance: 400
    lazy: true 
    proxies: 
      - خودکار (بهترین پینگ) 🤖 
      - پشتیبان (در صورت قطعی) 🧯 
      - دستی 🤏🏻 
  - name: توزیع بار (پایدار) 🧲 
    type: load-balance 
    icon: https://www.svgrepo.com/show/331731/load-balancer-generic.svg 
    url: https://api.v2fly.org/checkConnection.svgz 
    strategy: consistent-hashing 
    interval: 600 
    timeout: 120000 
    max-failed-times: 5 
    lazy: true 
    proxies:
` + proxyList + `    use: 
      - proxy 
  - name: توزیع بار (گردشی) 🔁 
    type: load-balance 
    icon: https://www.svgrepo.com/show/388466/rotating-forward.svg 
    url: https://api.v2fly.org/checkConnection.svgz 
    strategy: round-robin 
    interval: 600 
    tolerance: 200 
    timeout: 120000 
    max-failed-times: 3 
    lazy: true 
    proxies:
` + proxyList + `    use: 
      - proxy 
  - name: توزیع بار (موقت) ⏳ 
    type: load-balance 
    icon: https://www.svgrepo.com/show/323449/temporary-shield.svg 
    url: https://api.v2fly.org/checkConnection.svgz 
    strategy: sticky-sessions 
    interval: 600 
    timeout: 120000 
    max-failed-times: 5 
    lazy: true 
    proxies:
` + proxyList + `    use: 
      - proxy 
  - name: دانلود منیجر 📥
    type: select
    icon: https://www.sadeemrdp.com/fonts/apps/IDM-Logo.svg
    proxies:
      - بدون فیلترشکن 🛡️
      - نوع انتخاب پروکسی 🔀
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
      - اجازه ندادن 🚫
  - name: تلگرام 💬
    type: select
    icon: https://www.svgrepo.com/show/354443/telegram.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
      - اجازه ندادن 🚫
  - name: یوتیوب ▶️
    type: select
    icon: https://www.svgrepo.com/show/475700/youtube-color.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
      - اجازه ندادن 🚫
  - name: گوگل 🌍
    type: select
    icon: https://www.svgrepo.com/show/475656/google-color.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: واتس آپ 🟢
    type: select
    icon: https://upload.wikimedia.org/wikipedia/commons/4/4c/WhatsApp_Logo_green.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: هوش مصنوعی 🤖
    type: select
    icon: https://www.svgrepo.com/show/306500/openai.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: توییتر 🐦
    type: select
    icon: https://www.svgrepo.com/show/475689/twitter-color.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: اسپاتیفای 🎵
    type: select
    icon: https://www.svgrepo.com/show/475684/spotify-color.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: اینستاگرام 📸
    type: select
    icon: https://www.svgrepo.com/show/452229/instagram-1.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: تبلیغات 🆎
    type: select
    icon: https://www.svgrepo.com/show/336358/ad.svg
    proxies:
      - اجازه ندادن 🚫
      - بدون فیلترشکن 🛡️
      - نوع انتخاب پروکسی 🔀
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: تبلیغات اپ ها 🍃
    type: select
    icon: https://www.svgrepo.com/show/12172/smartphone-ad.svg
    proxies:
      - اجازه ندادن 🚫
      - بدون فیلترشکن 🛡️
      - نوع انتخاب پروکسی 🔀
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: رهگیری جهانی 🛑
    type: select
    icon: https://www.svgrepo.com/show/298725/tracking-track.svg
    proxies:
      - اجازه ندادن 🚫
      - بدون فیلترشکن 🛡️
      - نوع انتخاب پروکسی 🔀
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: سایتای مخرب ⚠️
    type: select
    icon: https://www.svgrepo.com/show/381135/cyber-crime-cyber-phishing-fraud-hack-money.svg
    proxies:
      - اجازه ندادن 🚫
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: استیم 🖥️
    type: select
    icon: https://www.svgrepo.com/show/452107/steam.svg
    proxies:
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - نوع انتخاب پروکسی 🔀
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: گیم 🎮
    type: select
    icon: https://www.svgrepo.com/show/167729/game-controller.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: توییچ 📡
    type: select
    icon: https://www.svgrepo.com/show/343527/twitch-network-communication-interaction-connection.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: سایتای ایرانی 🇮🇷
    type: select
    icon: https://upload.wikimedia.org/wikipedia/commons/3/36/Flag_of_Iran_%28civil%29.svg
    proxies:
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - نوع انتخاب پروکسی 🔀
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: ویندوز 🧊
    type: select
    icon: https://icon.icepanel.io/Technology/svg/Windows-11.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: کلودفلر ☁️
    type: select
    icon: https://icon.icepanel.io/Technology/svg/Cloudflare.svg
    proxies:
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - نوع انتخاب پروکسی 🔀
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: گیتهاب 🐙
    type: select
    icon: https://www.svgrepo.com/show/355033/github.svg
    proxies:
      - نوع انتخاب پروکسی 🔀 
      - بدون فیلترشکن 🛡️ 
      - اجازه ندادن 🚫 
      - اتصال پایدار 🔗 
      - خودکار (بهترین پینگ) 🤖 
      - دستی 🤏🏻 
      - پشتیبان (در صورت قطعی) 🧯 
  - name: دیسکورد 🗣️
    type: select
    icon: https://automatorplugin.com/wp-content/uploads/2024/10/discord-icon.svg
    proxies:
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: استریمیو 🎬
    type: select
    icon: https://stremio.github.io/stremio-addon-guide/img/stremio.svg
    proxies:
      - بدون فیلترشکن 🛡️
      - نوع انتخاب پروکسی 🔀
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: انی‌دسک 🔴
    type: select 
    icon: https://www.svgrepo.com/show/331289/anydesk.svg 
    proxies: 
      - بدون فیلترشکن 🛡️
      - نوع انتخاب پروکسی 🔀
      - اجازه ندادن 🚫
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
  - name: سایتای سانسوری 🤬
    type: select
    icon: https://upload.wikimedia.org/wikipedia/commons/thumb/6/67/Censorship.svg/300px-Censorship.svg.png
    proxies:
      - اجازه ندادن 🚫
      - نوع انتخاب پروکسی 🔀
      - بدون فیلترشکن 🛡️
      - اتصال پایدار 🔗
      - خودکار (بهترین پینگ) 🤖
      - دستی 🤏🏻
      - پشتیبان (در صورت قطعی) 🧯
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
`)
	return sb.String()
}

const rulesTemplate = `
rule-providers: 
  category_public_tracker: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/category-public-tracker.yaml 
    interval: 86400 
    path: ./ruleset/category_public_tracker.yaml 
  iran_ads: 
    type: http 
    behavior: domain 
    url: https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/clash_rules_ads.yaml 
    interval: 86400 
    path: ./ruleset/iran_ads.yaml 
  PersianBlocker: 
    type: http 
    behavior: domain 
    url: "https://github.com/MasterKia/iran-hosted-domains/releases/latest/download/clash_rules_ads.yaml" 
    path: ./ruleset/PersianBlocker.yaml 
    interval: 86400 
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
  twitch: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/twitch.yaml 
    interval: 86400 
    path: ./ruleset/twitch.yaml 
  censor: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/clash_rules/main/censor.yaml 
    interval: 86400 
    path: ./ruleset/tahrim.yaml 
  local_ips: 
    type: http 
    behavior: ipcidr 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/local-ips.yaml 
    interval: 86400 
    path: ./ruleset/local_ips.yaml 
  private: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/private.yaml 
    interval: 86400 
    path: ./ruleset/private.yaml 
  category_ir: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/category-ir.yaml 
    interval: 86400 
    path: ./ruleset/category_ir.yaml 
  iran: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/clash_rules/main/iran.yaml 
    interval: 86400 
    path: ./ruleset/iran.yaml 
  steam: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/clash_rules/main/steam.yaml 
    interval: 86400 
    path: ./ruleset/steam.yaml 
  game: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/clash_rules/refs/heads/main/game.yaml 
    interval: 86400 
    path: ./ruleset/game.yaml 
  category-games: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/category-games.yaml 
    interval: 86400 
    path: ./ruleset/category-games.yaml 
  ir: 
    type: http 
    format: yaml 
    behavior: domain 
    url: "https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ir.yaml" 
    path: ./ruleset/ir.yaml 
    interval: 86400 
  apps: 
    type: http 
    format: yaml 
    behavior: classical 
    url: "https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/apps.yaml" 
    path: ./ruleset/apps.yaml 
    interval: 86400 
  ircidr: 
    type: http 
    format: yaml 
    behavior: ipcidr 
    url: "https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ircidr.yaml" 
    path: ./ruleset/ircidr.yaml 
    interval: 86400 
  irasn: 
    type: http 
    format: yaml 
    behavior: classical 
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/irasn.yaml" 
    path: ./ruleset/irasn.yaml 
    interval: 86400 
  arvancloud: 
    type: http 
    format: yaml 
    behavior: ipcidr 
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/arvancloud.yaml" 
    path: ./ruleset/arvancloud.yaml 
    interval: 86400 
  derakcloud: 
    type: http 
    format: yaml 
    behavior: ipcidr 
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/derakcloud.yaml" 
    path: ./ruleset/derakcloud.yaml 
    interval: 86400 
  iranserver: 
    type: http 
    format: yaml 
    behavior: ipcidr 
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/iranserver.yaml" 
    path: ./ruleset/iranserver.yaml 
    interval: 86400 
  parspack: 
    type: http 
    format: yaml 
    behavior: ipcidr 
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/parspack.yaml" 
    path: ./ruleset/parspack.yaml 
    interval: 86400 
  malware: 
    type: http 
    format: yaml 
    behavior: domain 
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware.yaml" 
    path: ./ruleset/malware.yaml 
    interval: 86400 
  phishing: 
    type: http 
    format: yaml 
    behavior: domain 
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.yaml" 
    path: ./ruleset/phishing.yaml 
    interval: 86400 
  cryptominers: 
    type: http 
    format: yaml 
    behavior: domain 
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/cryptominers.yaml" 
    path: ./ruleset/cryptominers.yaml 
    interval: 86400 
  ads: 
    type: http 
    format: yaml 
    behavior: domain 
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/category-ads-all.yaml" 
    path: ./ruleset/ads.yaml 
    interval: 86400 
  DownloadManagers: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/clash_rules/refs/heads/main/DownloadManagers.yaml 
    interval: 86400 
    path: ./ruleset/DownloadManagers.yaml 
  BanProgramAD: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/BanProgramAD.yaml 
    interval: 86400 
    path: ./ruleset/BanProgramAD.yaml 
  BanAD: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/BanAD.yaml 
    interval: 86400 
    path: ./ruleset/BanAD.yaml 
  PrivateTracker: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/PrivateTracker.yaml 
    interval: 86400 
    path: ./ruleset/PrivateTracker.yaml 
  BanEasyList: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/BanEasyList.yaml 
    interval: 86400 
    path: ./ruleset/BanEasyList.yaml 
  Download: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/Download.yaml 
    interval: 86400 
    path: ./ruleset/Download.yaml 
  GameDownload: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/GameDownload.yaml 
    interval: 86400 
    path: ./ruleset/GameDownload.yaml 
  SteamRegionCheck: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/SteamRegionCheck.yaml 
    interval: 86400 
    path: ./ruleset/SteamRegionCheck.yaml 
  Xbox: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/Xbox.yaml 
    interval: 86400 
    path: ./ruleset/Xbox.yaml 
  YouTubeMusic: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/YouTubeMusic.yaml 
    interval: 86400 
    path: ./ruleset/YouTubeMusic.yaml 
  YouTube: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/YouTube.yaml 
    interval: 86400 
    path: ./ruleset/YouTube.yaml 
  Ponzi: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/Ponzi.yaml 
    interval: 86400 
    path: ./ruleset/Ponzi.yaml 
  warninglist: 
    type: http 
    behavior: classical 
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/warning-list.yaml 
    interval: 86400 
    path: ./ruleset/warninglist.yaml 
  google: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/google.yaml 
    interval: 86400 
    path: ./ruleset/google.yaml 
  google-play: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/google-play.yaml 
    interval: 86400 
    path: ./ruleset/google-play.yaml 
  xiaomi-ads: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/xiaomi-ads.yaml 
    interval: 86400 
    path: ./ruleset/xiaomi-ads.yaml 
  xiaomi_block_list: 
    type: http 
    format: yaml 
    behavior: domain 
    url: "https://raw.githubusercontent.com/10ium/clash_rules/refs/heads/main/xiaomi_block_list.yaml" 
    path: ./ruleset/xiaomi_block_list.yaml 
    interval: 86400 
  xiaomi_white_list: 
    type: http 
    behavior: classical 
    url: "https://raw.githubusercontent.com/10ium/clash_rules/refs/heads/main/xiaomi_white_list.yaml" 
    path: ./ruleset/xiaomi_white_list.yaml 
    interval: 86400 
  cloudflare: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/cloudflare.yaml 
    interval: 86400 
    path: ./ruleset/cloudflare.yaml 
  github: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/github.yaml 
    interval: 86400 
    path: ./ruleset/xgithub.yaml 
  whatsapp: 
    type: http 
    behavior: domain 
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/whatsapp.yaml 
    interval: 86400 
    path: ./ruleset/whatsapp.yaml 
  LiteAds: 
    type: http 
    behavior: classical 
    url: "https://raw.githubusercontent.com/10ium/clash_rules/refs/heads/main/LiteAds.yaml" 
    path: ./ruleset/LiteAds.yaml 
    interval: 86400 
  discord: 
    type: http 
    behavior: classical 
    url: "https://raw.githubusercontent.com/10ium/clash_rules/refs/heads/main/discord.yaml" 
    path: ./ruleset/discord.yaml 
    interval: 86400 
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
  stremio: 
    type: http 
    behavior: classical 
    url: "https://raw.githubusercontent.com/10ium/clash_rules/refs/heads/main/stremio.yaml" 
    path: ./ruleset/stremio.yaml 
    interval: 86400 
  windows: 
    type: http 
    behavior: classical 
    url: "https://raw.githubusercontent.com/10ium/clash_rules/refs/heads/main/windows.yaml" 
    path: ./ruleset/windows.yaml 
    interval: 86400
  Chotwitter:
    type: http
    format: yaml
    behavior: ipcidr
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/twitter.yaml"
    path: ./ruleset/Chotwitter.yaml
    interval: 86400
  mihTwitter:
    type: http
    behavior: classical
    url: "https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/Twitter.yaml"
    path: ./ruleset/mihTwitter.yaml
    interval: 86400
  Domtwitter:
    type: http
    behavior: domain
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/twitter.yaml
    interval: 86400
    path: ./ruleset/Domtwitter.yaml
  spotifyads:
    type: http
    behavior: domain
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/spotify-ads.yaml
    interval: 86400
    path: ./ruleset/spotifyads.yaml
  DomainSpotify:
    type: http
    behavior: domain
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/refs/heads/generated/spotify.yaml
    interval: 86400
    path: ./ruleset/DomainSpotify.yaml
  mihspotify:
    type: http
    behavior: domain
    url: https://raw.githubusercontent.com/10ium/mihomo_rule/refs/heads/main/list/Spotify.yaml
    interval: 86400
    path: ./ruleset/mihSpotify.yaml

rules: 
  - RULE-SET,DownloadManagers,دانلود منیجر 📥 
  - RULE-SET,Download,دانلود منیجر 📥 
  - RULE-SET,stremio,استریمیو 🎬 
  - RULE-SET,BanProgramAD,تبلیغات اپ ها 🍃 
  - RULE-SET,BanAD,رهگیری جهانی 🛑 
  - RULE-SET,PrivateTracker,رهگیری جهانی 🛑 
  - RULE-SET,category_public_tracker,رهگیری جهانی 🛑 
  - RULE-SET,malware,سایتای مخرب ⚠️ 
  - RULE-SET,phishing,سایتای مخرب ⚠️ 
  - RULE-SET,cryptominers,سایتای مخرب ⚠️ 
  - RULE-SET,warninglist,سایتای مخرب ⚠️ 
  - RULE-SET,Ponzi,سایتای مخرب ⚠️ 
  - RULE-SET,LiteAds,تبلیغات 🆎 
  - RULE-SET,iran_ads,تبلیغات 🆎 
  - RULE-SET,PersianBlocker,تبلیغات 🆎 
  - RULE-SET,ads,تبلیغات 🆎 
  - RULE-SET,BanEasyList,تبلیغات 🆎 
  - RULE-SET,twitch,توییچ 📡 
  - PROCESS-NAME,Telegram.exe,تلگرام 💬 
  - PROCESS-NAME,org.telegram.messenger,تلگرام 💬 
  - PROCESS-NAME,org.telegram.messenger.web,تلگرام 💬 
  - RULE-SET,telegram,تلگرام 💬 
  - RULE-SET,YouTube,یوتیوب ▶️ 
  - RULE-SET,youtube,یوتیوب ▶️ 
  - RULE-SET,YouTubeMusic,یوتیوب ▶️
  - PROCESS-NAME,com.anydesk.anydeskandroid,انی‌دسک 🔴
  - PROCESS-NAME,AnyDesk.exe,انی‌دسک 🔴
  - DOMAIN-SUFFIX,anydesk.com,انی‌دسک 🔴
  - PROCESS-NAME,Twitter.exe,توییتر 🐦
  - PROCESS-NAME,com.twitter.android,توییتر 🐦
  - RULE-SET,Chotwitter,توییتر 🐦
  - RULE-SET,mihTwitter,توییتر 🐦
  - RULE-SET,Domtwitter,توییتر 🐦
  - PROCESS-NAME,com.spotify.music,اسپاتیفای 🎵
  - PROCESS-NAME,Spotify.exe,اسپاتیفای 🎵
  - RULE-SET,DomainSpotify,اسپاتیفای 🎵
  - RULE-SET,mihspotify,اسپاتیفای 🎵
  - PROCESS-NAME,com.instagram.android,اینستاگرام 📸 
  - RULE-SET,instagram,اینستاگرام 📸 
  - DOMAIN-SUFFIX,deepseek.com,هوش مصنوعی 🤖 
  - DOMAIN-SUFFIX,qwen.ai,هوش مصنوعی 🤖 
  - RULE-SET,category-ai,هوش مصنوعی 🤖 
  - RULE-SET,censor,سایتای سانسوری 🤬 
  - RULE-SET,apps,سایتای ایرانی 🇮🇷 
  - RULE-SET,iran,سایتای ایرانی 🇮🇷 
  - RULE-SET,arvancloud,سایتای ایرانی 🇮🇷 
  - RULE-SET,derakcloud,سایتای ایرانی 🇮🇷 
  - RULE-SET,iranserver,سایتای ایرانی 🇮🇷 
  - RULE-SET,parspack,سایتای ایرانی 🇮🇷 
  - RULE-SET,irasn,سایتای ایرانی 🇮🇷 
  - RULE-SET,ircidr,سایتای ایرانی 🇮🇷 
  - RULE-SET,ir,سایتای ایرانی 🇮🇷 
  - RULE-SET,category_ir,سایتای ایرانی 🇮🇷 
  - RULE-SET,whatsapp,واتس آپ 🟢 
  - RULE-SET,steam,استیم 🖥️ 
  - RULE-SET,SteamRegionCheck,استیم 🖥️ 
  - RULE-SET,game,گیم 🎮 
  - RULE-SET,GameDownload,گیم 🎮 
  - RULE-SET,category-games,گیم 🎮 
  - RULE-SET,Xbox,گیم 🎮 
  - RULE-SET,discord,دیسکورد 🗣️ 
  - RULE-SET,xiaomi_white_list,نوع انتخاب پروکسی 🔀 
  - RULE-SET,xiaomi-ads,تبلیغات اپ ها 🍃 
  - RULE-SET,xiaomi_block_list,تبلیغات اپ ها 🍃 
  - RULE-SET,windows,ویندوز 🧊 
  - RULE-SET,cloudflare,کلودفلر ☁️ 
  - RULE-SET,github,گیتهاب 🐙 
  - PROCESS-NAME,com.android.vending,نوع انتخاب پروکسی 🔀 
  - PROCESS-NAME,com.google.android.gms,نوع انتخاب پروکسی 🔀 
  - RULE-SET,google-play,نوع انتخاب پروکسی 🔀 
  - RULE-SET,google,گوگل 🌍
  - IP-CIDR,10.10.34.0/24,نوع انتخاب پروکسی 🔀 
  - RULE-SET,local_ips,بدون فیلترشکن 🛡️ 
  - RULE-SET,private,بدون فیلترشکن 🛡️ 
  - MATCH,نوع انتخاب پروکسی 🔀 

ntp: 
  enable: true 
  server: "time.apple.com" 
  port: 123 
  interval: 30
`