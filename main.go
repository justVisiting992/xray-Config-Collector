package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/oschwald/geoip2-golang"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

type VMessConfig struct {
	Add  string      `json:"add"`
	Port interface{} `json:"port"`
	Id   interface{} `json:"id"`
}

type ChannelReport struct {
	Name      string
	Protocols []string
	Count     int
	Message   string
}

type GistRequest struct {
	Files map[string]GistFile `json:"files"`
}
type GistResponse struct {
	Files map[string]GistFile `json:"files"`
}
type GistFile struct {
	Content string `json:"content"`
}

var (
	client   = &http.Client{Timeout: 15 * time.Second}
	maxLimit = 200
	db       *geoip2.Reader

	gistID    = os.Getenv("GIST_ID")
	gistToken = os.Getenv("GIST_TOKEN")

	checkpoints   = make(map[string]int)
	checkpointsMu sync.Mutex

	geoCache   = make(map[string]string)
	geoCacheMu sync.Mutex

	allProtocols   = make(map[string]bool)
	protocolsMu    sync.Mutex

	myregex = map[string]string{
		"SS":        `(?i)ss://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"VMess":     `(?i)vmess://[A-Za-z0-9+/=]+`,
		"Trojan":    `(?i)trojan://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"VLess":     `(?i)vless://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"Hy2":       `(?i)(?:hysteria2|hy2)://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"MTProto":   `(?i)(?:mtproto|proxy)://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"NPV":       `(?i)(?:npv|npvt)://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"SingBox":   `(?i)(?:sing-box://|type["\s]*:.*["\s]*shadowsocks|type["\s]*:.*["\s]*vless)`,
		"ClashMeta": `(?i)(proxies:|proxy-groups:|rules:|\- name:.*server:.*port:)`,
		"WireGuard": `(?i)(wg://|\[Interface\].*PrivateKey|\[Peer\].*PublicKey)`,
		"Naive":     `(?i)naive(?:proxy)?://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"TrojanGo":  `(?i)trojango://[A-Za-z0-9./:=?#-_@!%&+=]+`,
	}
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()
	printBanner()

	var err error
	db, err = geoip2.Open("Country.mmdb")
	if err != nil {
		gologger.Warning().Msg("⚠️ GeoIP database missing! Flags will be 🏴")
	} else {
		gologger.Info().Msg("🌍 GeoIP Database Loaded.")
		defer db.Close()
	}

	loadCheckpoints()
	loadPersistentProtocols()

	rawChannels, _ := loadChannelsFromCSV("channels.csv")
	channels := removeDuplicates(rawChannels)
	gologger.Info().Msgf("📺 Loaded %d Source Channels", len(channels))

	newConfigs := make(map[string][]string)
	historyConfigs := make(map[string][]string)

	totalHistory := 0
	for p := range myregex {
		newConfigs[p] = []string{}
		historyConfigs[p] = []string{}
		fName := strings.ToLower(p) + "_iran.txt"
		content, err := os.ReadFile(fName)
		if err == nil {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				clean := strings.Split(line, "#")[0]
				clean = strings.Split(clean, "|")[0]
				historyConfigs[p] = append(historyConfigs[p], strings.TrimSpace(clean))
			}
			totalHistory += len(historyConfigs[p])
		}
	}
	gologger.Info().Msgf("📜 Loaded %d Historic Configs", totalHistory)

	var reports []ChannelReport
	totalScraped := 0

	gologger.Info().Msg("🐍 Processing Python Collector Dump...")
	pythonDump, err := os.ReadFile("telegram_dump.txt")
	if err == nil && len(pythonDump) > 0 {
		dumpText := string(pythonDump)
		count := 0
		foundProtos := make(map[string]bool)
		for pName, reg := range myregex {
			re := regexp.MustCompile(reg)
			matches := re.FindAllString(dumpText, -1)
			if len(matches) > 0 {
				newConfigs[pName] = append(newConfigs[pName], matches...)
				count += len(matches)
				foundProtos[pName] = true
				protocolsMu.Lock()
				allProtocols[pName] = true
				protocolsMu.Unlock()
			}
		}
		var pList []string
		for p := range foundProtos {
			pList = append(pList, p)
		}
		reports = append(reports, ChannelReport{
			Name:      "persianvpnhub",
			Protocols: pList,
			Count:     count,
			Message:   fmt.Sprintf("✅ %d Configs via API", count),
		})
		totalScraped += count
		gologger.Info().Msgf("✨ Extracted %d configs from Python Dump", count)
	} else {
		gologger.Warning().Msg("⚠️ No Python dump found or empty.")
	}

	gologger.Info().Msg("🕸️ Starting Stateful Web Scraper...")
	var wgScrape sync.WaitGroup
	semaphore := make(chan struct{}, 5)

	for _, channelURL := range channels {
		wgScrape.Add(1)
		semaphore <- struct{}{}
		go func(urlStr string) {
			defer wgScrape.Done()
			defer func() { <-semaphore }()

			uParts := strings.Split(strings.TrimSuffix(urlStr, "/"), "/")
			name := uParts[len(uParts)-1]

			extracted, _ := scrapeChannelStateful(name)

			checkpointsMu.Lock()
			report := ChannelReport{Name: name}
			for p, cfgs := range extracted {
				if len(cfgs) > 0 {
					newConfigs[p] = append(newConfigs[p], cfgs...)
					report.Protocols = append(report.Protocols, p)
					report.Count += len(cfgs)
					protocolsMu.Lock()
					allProtocols[p] = true
					protocolsMu.Unlock()
				}
			}
			if report.Count > 0 {
				report.Message = fmt.Sprintf("✅ %d found", report.Count)
				totalScraped += report.Count
			} else {
				report.Message = "💤 No new configs"
			}
			reports = append(reports, report)
			checkpointsMu.Unlock()

			if report.Count > 0 {
				gologger.Debug().Msgf("   + %s: Found %d", name, report.Count)
			}
		}(channelURL)
	}
	wgScrape.Wait()

	saveCheckpoints()
	savePersistentProtocols()

	gologger.Info().Msgf("📦 Total Raw Configs Harvested: %d", totalScraped)

	var allMixed []string
	protoStats := make(map[string][2]int)

	for p := range myregex {
		gologger.Info().Msgf("🛡️ Processing Protocol: %s", p)
		combined := append(newConfigs[p], historyConfigs[p]...)
		unique := removeDuplicates(combined)

		gologger.Info().Msgf("   ↳ Testing %d unique configs...", len(unique))
		healthy := fastPingTest(unique, p)
		gologger.Info().Msgf("   ✅ Alive: %d", len(healthy))

		protoStats[p] = [2]int{len(unique), len(healthy)}

		limit := len(healthy)
		if limit > maxLimit {
			limit = maxLimit
		}

		finalList := healthy[:limit]
		saveToFile(strings.ToLower(p)+"_iran.txt", finalList)
		allMixed = append(allMixed, finalList...)
	}

	sort.Slice(reports, func(i, j int) bool { return reports[i].Count > reports[j].Count })
	_ = os.WriteFile("report.md", []byte(generateImprovedReportStructure(reports, protoStats)), 0644)

	gologger.Info().Msg("🍹 Saving Mixed Configs...")
	saveToFile("mixed_iran.txt", removeDuplicates(allMixed))
	gologger.Info().Msg("🎉 All Done! Mission Accomplished.")
}

func scrapeChannelStateful(channelName string) (map[string][]string, int) {
	results := make(map[string][]string)
	checkpointsMu.Lock()
	lastSeenID := checkpoints[channelName]
	checkpointsMu.Unlock()

	baseURL := "https://t.me/s/" + channelName
	nextURL := baseURL
	maxIDFound := lastSeenID
	totalExtracted := 0
	pagesScraped := 0

	for pagesScraped < 5 {
		req, _ := http.NewRequest("GET", nextURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			break
		}

		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()

		minIDOnPage := 999999999
		foundAny := false

		doc.Find(".tgme_widget_message").Each(func(i int, s *goquery.Selection) {
			dataPost, exists := s.Attr("data-post")
			if !exists {
				return
			}

			parts := strings.Split(dataPost, "/")
			if len(parts) < 2 {
				return
			}

			msgID, err := strconv.Atoi(parts[len(parts)-1])
			if err != nil {
				return
			}

			if msgID > maxIDFound {
				maxIDFound = msgID
			}
			if msgID < minIDOnPage {
				minIDOnPage = msgID
			}

			if msgID > lastSeenID {
				foundAny = true
				text := s.Find(".tgme_widget_message_text").Text()
				for pName, reg := range myregex {
					matches := regexp.MustCompile(reg).FindAllString(text, -1)
					if len(matches) > 0 {
						results[pName] = append(results[pName], matches...)
						totalExtracted += len(matches)
					}
				}
			}
		})

		if foundAny && minIDOnPage > lastSeenID {
			nextURL = fmt.Sprintf("%s?before=%d", baseURL, minIDOnPage)
			pagesScraped++
			time.Sleep(2 * time.Second)
		} else {
			break
		}
	}

	if maxIDFound > lastSeenID {
		checkpointsMu.Lock()
		checkpoints[channelName] = maxIDFound
		checkpointsMu.Unlock()
	}

	return results, totalExtracted
}

func loadCheckpoints() {
	if gistID == "" || gistToken == "" {
		return
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/gists/"+gistID, nil)
	req.Header.Set("Authorization", "token "+gistToken)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var gistResp GistResponse
	if err := json.NewDecoder(resp.Body).Decode(&gistResp); err == nil {
		if file, ok := gistResp.Files["checkpoints.json"]; ok {
			_ = json.Unmarshal([]byte(file.Content), &checkpoints)
			gologger.Info().Msg("🧠 State loaded from Gist.")
		}
	}
}

func saveCheckpoints() {
	if gistID == "" || gistToken == "" {
		return
	}
	checkpointsMu.Lock()
	data, _ := json.Marshal(checkpoints)
	checkpointsMu.Unlock()

	payload := GistRequest{
		Files: map[string]GistFile{
			"checkpoints.json": {Content: string(data)},
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("PATCH", "https://api.github.com/gists/"+gistID, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "token "+gistToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		gologger.Info().Msg("💾 State saved to Gist.")
	}
}

func loadPersistentProtocols() {
	if gistID == "" || gistToken == "" {
		return
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/gists/"+gistID, nil)
	req.Header.Set("Authorization", "token "+gistToken)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var gistResp GistResponse
	if err := json.NewDecoder(resp.Body).Decode(&gistResp); err == nil {
		if file, ok := gistResp.Files["protocols.json"]; ok {
			var saved []string
			_ = json.Unmarshal([]byte(file.Content), &saved)
			protocolsMu.Lock()
			for _, p := range saved {
				allProtocols[p] = true
			}
			protocolsMu.Unlock()
			gologger.Info().Msg("📋 Loaded persistent protocols from Gist.")
		}
	}
}

func savePersistentProtocols() {
	if gistID == "" || gistToken == "" {
		return
	}
	protocolsMu.Lock()
	var protoList []string
	for p := range allProtocols {
		protoList = append(protoList, p)
	}
	protocolsMu.Unlock()

	sort.Strings(protoList)
	data, _ := json.Marshal(protoList)

	payload := GistRequest{
		Files: map[string]GistFile{
			"protocols.json": {Content: string(data)},
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("PATCH", "https://api.github.com/gists/"+gistID, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "token "+gistToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		gologger.Info().Msg("💾 Persistent protocols saved to Gist.")
	}
}

func fastPingTest(configs []string, protocol string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	healthy := []string{}
	sem := make(chan struct{}, 100)

	for _, cfg := range configs {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if checkAlive(c, protocol) {
				mu.Lock()
				healthy = append(healthy, labelWithGeo(c, len(healthy)+1))
				mu.Unlock()
			}
		}(cfg)
	}
	wg.Wait()
	return healthy
}

func checkAlive(config string, protocol string) bool {
	if strings.HasPrefix(strings.ToLower(config), "vmess://") {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		if i := len(b64) % 4; i != 0 {
			b64 += strings.Repeat("=", 4-i)
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(b64)
		}
		if err != nil {
			return false
		}
		var v VMessConfig
		if err := json.Unmarshal(decoded, &v); err != nil {
			return false
		}
		return tcpDial(fmt.Sprintf("%v", v.Add), fmt.Sprintf("%v", v.Port))
	}
	if strings.Contains(strings.ToLower(protocol), "hy2") {
		u, err := url.Parse(config)
		if err != nil {
			return false
		}
		if tcpDial(u.Hostname(), u.Port()) {
			return true
		}
		ips, err := net.LookupIP(u.Hostname())
		return err == nil && len(ips) > 0
	}
	u, err := url.Parse(config)
	if err != nil {
		return false
	}
	return tcpDial(u.Hostname(), u.Port())
}

func tcpDial(host, port string) bool {
	if host == "" || port == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func labelWithGeo(config string, index int) string {
	countryName, emoji := "Dynamic", "🏴"
	host := extractHost(config)

	if host == "" {
		return buildLabel(config, emoji, countryName, index)
	}

	geoCacheMu.Lock()
	if cached, ok := geoCache[host]; ok {
		geoCacheMu.Unlock()
		parts := strings.SplitN(cached, " ", 2)
		if len(parts) == 2 {
			emoji, countryName = parts[0], parts[1]
		}
		return buildLabel(config, emoji, countryName, index)
	}
	geoCacheMu.Unlock()

	lowerHost := strings.ToLower(host)

	domainHints := map[string]string{
		".de.": "Germany", ".fr.": "France", ".nl.": "Netherlands", ".ru.": "Russia",
		".ir.": "Iran", ".ae.": "UAE", ".sg.": "Singapore", ".hk.": "Hong Kong",
		".jp.": "Japan", ".kr.": "South Korea", ".tr.": "Turkey", ".pl.": "Poland",
		"fra-": "Germany", "ams-": "Netherlands", "lhr-": "UK", "sin-": "Singapore",
		"tyo-": "Japan", "syd-": "Australia", "blr-": "India", "bom-": "India",
		"cloudflare": "Cloudflare", "workers.dev": "Cloudflare", "pages.dev": "Cloudflare",
		"r2.dev": "Cloudflare", "trycloudflare.com": "Cloudflare", "isbgpsafeyet.com": "Cloudflare",
		"fastly": "Fastly", "akamai": "Akamai", "bunnycdn": "BunnyCDN", "vercel": "Vercel",
		"fly.dev": "Fly.io", "railway.app": "Railway", "render.com": "Render",
		"koyeb.app": "Koyeb", "deta.sh": "Deta", "deno.dev": "Deno", "replit.dev": "Replit",
		"oraclecloud": "Oracle", "digitalocean": "DigitalOcean", "linode": "Linode",
		"vultr": "Vultr", "hetzner": "Hetzner", "contabo": "Contabo",
	}
	for substr, country := range domainHints {
		if strings.Contains(lowerHost, substr) {
			countryName = country
			emoji = guessEmojiFromCountry(country)
			break
		}
	}

	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		sliceLen := min(3, len(ips))
		for _, ip := range ips[:sliceLen] {
			if ip.To4() == nil && len(ips) > 1 {
				continue
			}
			if !ip.IsPrivate() && !ip.IsLoopback() {
				if db != nil {
					record, err := db.Country(ip)
					if err == nil && record != nil && record.Country.IsoCode != "" {
						code := record.Country.IsoCode
						raw := record.Country.Names["en"]
						if raw != "" {
							switch raw {
							case "United States":
								countryName = "USA"
							case "United Kingdom":
								countryName = "UK"
							case "United Arab Emirates":
								countryName = "UAE"
							case "The Netherlands":
								countryName = "Netherlands"
							default:
								countryName = raw
							}
						}
						if len(code) == 2 {
							emoji = strings.Map(func(r rune) rune { return r + 127397 }, strings.ToUpper(code))
						}
						break
					}
				}
			}
		}
	}

	if countryName == "Dynamic" && len(ips) > 0 {
		names, err := net.LookupAddr(ips[0].String())
		if err == nil && len(names) > 0 {
			ptr := strings.ToLower(names[0])
			ptrHints := map[string]string{
				"fra": "Germany", "ams": "Netherlands", "lhr": "UK", "sin": "Singapore",
				"tyo": "Japan", "syd": "Australia", "blr": "India", "bom": "India",
				"cdg": "France", "par": "France", "arn": "Sweden", "hel": "Finland",
			}
			for code, country := range ptrHints {
				if strings.Contains(ptr, code) {
					countryName = country
					emoji = guessEmojiFromCountry(country)
					break
				}
			}
		}
	}

	geoCacheMu.Lock()
	geoCache[host] = emoji + " " + countryName
	geoCacheMu.Unlock()

	return buildLabel(config, emoji, countryName, index)
}

func buildLabel(config string, emoji, countryName string, index int) string {
	label := fmt.Sprintf("%s %s | Node-%d", emoji, countryName, index)

	if strings.HasPrefix(strings.ToLower(config), "vmess://") {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		if i := len(b64) % 4; i != 0 {
			b64 += strings.Repeat("=", 4-i)
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			decoded, _ = base64.URLEncoding.DecodeString(b64)
		}
		var v map[string]interface{}
		if err := json.Unmarshal(decoded, &v); err == nil {
			v["ps"] = label
			newJSON, _ := json.Marshal(v)
			return "vmess://" + base64.StdEncoding.EncodeToString(newJSON)
		}
		return config
	}

	cleanConfig := strings.Split(config, "#")[0]
	return fmt.Sprintf("%s#%s", cleanConfig, label)
}

func extractHost(config string) string {
	lower := strings.ToLower(config)

	if strings.HasPrefix(lower, "vmess://") {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		if i := len(b64) % 4; i != 0 {
			b64 += strings.Repeat("=", 4-i)
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			decoded, _ = base64.URLEncoding.DecodeString(b64)
		}
		var v map[string]interface{}
		if err := json.Unmarshal(decoded, &v); err == nil {
			if add, ok := v["add"].(string); ok && add != "" {
				return add
			}
			for _, key := range []string{"sni", "host", "peer", "serverName"} {
				if val, ok := v[key].(string); ok && val != "" {
					return val
				}
			}
		}
		return ""
	}

	u, err := url.Parse(config)
	if err != nil {
		return ""
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		q := u.Query()
		for _, key := range []string{"sni", "peer", "host", "serverName", "allowInsecure"} {
			if val := q.Get(key); val != "" {
				host = val
				break
			}
		}
	}

	return host
}

func resolveToIP(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4
		}
	}

	return ips[0]
}

func guessEmojiFromCountry(country string) string {
	switch strings.ToLower(country) {
	case "united states", "usa":
		return "🇺🇸"
	case "united kingdom", "uk":
		return "🇬🇧"
	case "germany":
		return "🇩🇪"
	case "france":
		return "🇫🇷"
	case "netherlands":
		return "🇳🇱"
	case "russia":
		return "🇷🇺"
	case "iran":
		return "🇮🇷"
	case "united arab emirates", "uae":
		return "🇦🇪"
	case "singapore":
		return "🇸🇬"
	case "hong kong":
		return "🇭🇰"
	case "japan":
		return "🇯🇵"
	case "south korea":
		return "🇰🇷"
	case "turkey":
		return "🇹🇷"
	case "poland":
		return "🇵🇱"
	case "cloudflare", "fastly", "akamai", "bunnycdn", "vercel", "fly.io", "railway", "render", "koyeb", "deta", "deno", "replit":
		return "☁️"
	default:
		return "🏴"
	}
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	var list []string
	for _, v := range slice {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		fingerprint := getConfigFingerprint(v)
		if fingerprint == "" {
			list = append(list, v)
			continue
		}
		if !seen[fingerprint] {
			seen[fingerprint] = true
			list = append(list, v)
		}
	}
	return list
}

func getConfigFingerprint(config string) string {
	reClean := regexp.MustCompile(`[[:cntrl:]]|[\x{200B}-\x{200D}\x{FEFF}]`)
	config = reClean.ReplaceAllString(config, "")

	lower := strings.ToLower(config)

	// VMess
	if strings.HasPrefix(lower, "vmess://") {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		if i := len(b64) % 4; i != 0 {
			b64 += strings.Repeat("=", 4-i)
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			decoded, _ = base64.URLEncoding.DecodeString(b64)
		}
		var v map[string]interface{}
		if err := json.Unmarshal(decoded, &v); err == nil {
			add := strings.ToLower(fmt.Sprint(v["add"]))
			port := fmt.Sprint(v["port"])
			id := fmt.Sprint(v["id"])
			net := strings.ToLower(fmt.Sprint(v["net"]))
			security := strings.ToLower(fmt.Sprint(v["security"]))
			tlsFingerprint := ""
			if tls, ok := v["tlsSettings"].(map[string]interface{}); ok {
				if fp, ok := tls["fingerprint"].(string); ok {
					tlsFingerprint = strings.ToLower(fp)
				}
			}
			return fmt.Sprintf("vmess|%s|%s|%s|%s|%s|%s", add, port, id, net, security, tlsFingerprint)
		}
		return md5hex(lower)
	}

	// URL protocols
	uParts := strings.Split(config, "#")
	serverOnly := uParts[0]

	u, err := url.Parse(serverOnly)
	if err != nil {
		return md5hex(lower)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "hy2" {
		scheme = "hysteria2"
	}

	host := strings.ToLower(u.Hostname())
	user := ""
	if u.User != nil {
		user = strings.ToLower(u.User.String())
	}

	path := strings.ToLower(u.Path)

	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var qb strings.Builder
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, val := range vals {
			qb.WriteString(strings.ToLower(k) + "=" + strings.ToLower(val) + "&")
		}
	}

	return fmt.Sprintf("%s|%s|%s|%s|%s|%s", scheme, user, host, u.Port(), path, qb.String())
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func saveToFile(name string, data []string) {
	_ = os.WriteFile(name, []byte(strings.Join(data, "\n")), 0644)
}

func printBanner() {
	fmt.Println(`
	██╗  ██╗██████╗  █████╗ ██╗   ██╗
	╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
	 ╚███╔╝ ██████╔╝███████║ ╚████╔╝ 
	 ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝  
	██╔╝ ██╗██║  ██║██║  ██║   ██║   
	╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
	    Xray Config Collector v2.0
	`)
}

func generateImprovedReportStructure(reports []ChannelReport, stats map[string][2]int) string {
	utcNow := time.Now().UTC()
	loc, _ := time.LoadLocation("Asia/Tehran")
	tehranNow := utcNow.In(loc)
	jy, jm, jd := toJalali(tehranNow.Year(), int(tehranNow.Month()), tehranNow.Day())

	totalUnique := 0
	totalLive := 0
	for _, s := range stats {
		totalUnique += s[0]
		totalLive += s[1]
	}

	var sb strings.Builder
	sb.WriteString("# 📊 Xray Config Collector Report\n\n")
	sb.WriteString("### 🕒 Last Update\n")
	sb.WriteString(fmt.Sprintf("- **Tehran Time:** 🇮🇷 `%d/%02d/%02d` | `%02d:%02d:%02d`\n", jy, jm, jd, tehranNow.Hour(), tehranNow.Minute(), tehranNow.Second()))
	sb.WriteString(fmt.Sprintf("- **International:** 🌐 `%s`\n\n", tehranNow.Format("Monday, 02 Jan 2006")))

	sb.WriteString("### ⚡ Global Statistics\n")
	sb.WriteString(fmt.Sprintf("- **Total Configs Processed:** `%d` (Total Unique)\n", totalUnique))
	sb.WriteString(fmt.Sprintf("- **Total Alive:** `%d` 🚀\n", totalLive))
	sb.WriteString("\n#### 🔍 Protocol Breakdown (this run):\n")

	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		s := stats[k]
		sb.WriteString(fmt.Sprintf("- **%s:** %d found (%d live)\n", k, s[0], s[1]))
	}

	protocolsMu.Lock()
	var allProtoList []string
	for p := range allProtocols {
		allProtoList = append(allProtoList, p)
	}
	protocolsMu.Unlock()
	sort.Strings(allProtoList)
	sb.WriteString("\n#### 🌐 All Known Bypass Methods (cumulative):\n")
	if len(allProtoList) > 0 {
		sb.WriteString("`" + strings.Join(allProtoList, ", ") + "`\n")
	} else {
		sb.WriteString("— (none detected yet)\n")
	}

	sb.WriteString("\n- **Status:** ` Operational ` ✅\n\n")
	sb.WriteString("### 📡 Source Analysis\n\n")
	sb.WriteString("| Source Channel | Available Protocols | Harvest Status |\n")
	sb.WriteString("| :--- | :--- | :--- |\n")

	for _, r := range reports {
		protos := strings.Join(r.Protocols, ", ")
		if protos == "" {
			protos = "—"
		}
		linkName := r.Name
		linkURL := "https://t.me/s/" + r.Name
		if r.Name == "Python-API-Collector" {
			linkName = "persianvpnhub"
			linkURL = "https://t.me/s/persianvpnhub"
		}
		sb.WriteString(fmt.Sprintf("| 📢 [%s](%s) | `%s` | %s |\n", linkName, linkURL, protos, r.Message))
	}
	sb.WriteString("\n---\n")
	sb.WriteString("*Auto-generated by Xray Config Collector v2.0* 🛠️")
	return sb.String()
}

func toJalali(gy, gm, gd int) (int, int, int) {
	var gDays = []int{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334}
	var jy, jm, jd int
	var gDayNo int
	gDayNo = 365*(gy-1600) + (gy-1597)/4 - (gy-1501)/100 + (gy-1201)/400
	gDayNo += gDays[gm-1]
	if gm > 2 && ((gy%4 == 0 && gy%100 != 0) || (gy%400 == 0)) {
		gDayNo++
	}
	gDayNo += gd - 1
	jDayNo := gDayNo - 79
	jNp := jDayNo / 12053
	jDayNo %= 12053
	jy = 979 + 33*jNp + 4*(jDayNo/1461)
	jDayNo %= 1461
	if jDayNo >= 366 {
		jy += (jDayNo - 1) / 365
		jDayNo = (jDayNo - 1) % 365
	}
	if jDayNo < 186 {
		jm = 1 + jDayNo/31
		jd = 1 + jDayNo%31
	} else {
		jm = 7 + (jDayNo-186)/30
		jd = 1 + (jDayNo-186)%30
	}
	return jy, jm, jd
}

func loadChannelsFromCSV(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	var u []string
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if len(row) > 0 {
			cleaned := strings.TrimSpace(row[0])
			if cleaned == "" || strings.Contains(strings.ToUpper(cleaned), "URL") {
				continue
			}
			if !strings.HasPrefix(cleaned, "http") {
				cleaned = "https://t.me/" + cleaned
			}
			u = append(u, strings.TrimSuffix(cleaned, "/"))
		}
	}
	return u, nil
}