package main

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
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

// VMessConfig structure
type VMessConfig struct {
	Add  string      `json:"add"`
	Port interface{} `json:"port"`
	Id   interface{} `json:"id"`
}

type ChannelReport struct {
	Name      string
	Protocols []string
	Count       int
	Message   string
}

// Gist Structure
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
	
	// Secrets for Statefulness
	gistID    = os.Getenv("GIST_ID")
	gistToken = os.Getenv("GIST_TOKEN")
	
	// Global Checkpoint Map
	checkpoints = make(map[string]int)
	checkpointsMu sync.Mutex

	myregex = map[string]string{
		"SS":     `(?i)ss://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"VMess":  `(?i)vmess://[A-Za-z0-9+/=]+`, 
		"Trojan": `(?i)trojan://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"VLess":  `(?i)vless://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"Hy2":    `(?i)(?:hysteria2|hy2)://[A-Za-z0-9./:=?#-_@!%&+=]+`,
	}
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()
	printBanner()

	// 1. Load GeoIP
	var err error
	db, err = geoip2.Open("Country.mmdb")
	if err != nil {
		gologger.Warning().Msg("⚠️ GeoIP database missing! Flags will be 🏴")
	} else {
		gologger.Info().Msg("🌍 GeoIP Database Loaded.")
		defer db.Close()
	}

	// 2. Load Checkpoints from Gist
	loadCheckpoints()

	// 3. Load Channels
	rawChannels, _ := loadChannelsFromCSV("channels.csv")
	channels := removeDuplicates(rawChannels) 
	gologger.Info().Msgf("📺 Loaded %d Source Channels", len(channels))

	newConfigs := make(map[string][]string)
	historyConfigs := make(map[string][]string)

	// 4. Load History
	for p := range myregex {
		newConfigs[p] = []string{}
		historyConfigs[p] = []string{}
		fName := strings.ToLower(p) + "_iran.txt"
		content, err := os.ReadFile(fName)
		if err == nil {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" { continue }
				clean := strings.Split(line, "#")[0]
				clean = strings.Split(clean, "|")[0]
				historyConfigs[p] = append(historyConfigs[p], strings.TrimSpace(clean))
			}
		}
	}

	var reports []ChannelReport
	totalScraped := 0

	// 5. Process Python Dump
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
			}
		}
		var pList []string
		for p := range foundProtos { pList = append(pList, p) }
		reports = append(reports, ChannelReport{
			Name: "Python-API-Collector", Count: count, Message: fmt.Sprintf("✅ %d Configs via API", count), Protocols: pList,
		})
		totalScraped += count
		gologger.Info().Msgf("✨ Extracted %d configs from Python Dump", count)
	} else {
		gologger.Warning().Msg("⚠️ No Python dump found or empty.")
	}

	// 6. Stateful Web Scraper
	gologger.Info().Msg("🕸️  Starting Stateful Web Scraper...")
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
				}
			}
			if report.Count > 0 {
				report.Message = fmt.Sprintf("✅ %d found (Stateful)", report.Count)
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

	gologger.Info().Msgf("📦 Total Raw Configs Harvested: %d", totalScraped)

	// Generate Report
	sort.Slice(reports, func(i, j int) bool { return reports[i].Count > reports[j].Count })
	_ = os.WriteFile("report.md", []byte(generateOriginalReportStructure(reports, totalScraped)), 0644)

	// 7. Testing & Merging
	var allMixed []string
	
	for p := range myregex {
		gologger.Info().Msgf("🛡️  Processing Protocol: %s", p)
		combined := append(newConfigs[p], historyConfigs[p]...)
		unique := removeDuplicates(combined) 
		
		gologger.Info().Msgf("   ↳ Testing %d unique configs...", len(unique))
		healthy := fastPingTest(unique, p)
		gologger.Info().Msgf("   ✅ Alive: %d", len(healthy))
		
		limit := len(healthy)
		if limit > maxLimit { limit = maxLimit }
		
		finalList := healthy[:limit]
		saveToFile(strings.ToLower(p)+"_iran.txt", finalList)
		allMixed = append(allMixed, finalList...)
	}
	
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
		if err != nil { break }
		
		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()

		minIDOnPage := 999999999
		foundAny := false

		doc.Find(".tgme_widget_message").Each(func(i int, s *goquery.Selection) {
			dataPost, exists := s.Attr("data-post")
			if !exists { return }
			
			parts := strings.Split(dataPost, "/")
			if len(parts) < 2 { return }
			
			msgID, err := strconv.Atoi(parts[len(parts)-1])
			if err != nil { return }

			if msgID > maxIDFound { maxIDFound = msgID }
			if msgID < minIDOnPage { minIDOnPage = msgID }

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
	if gistID == "" || gistToken == "" { return }
	req, _ := http.NewRequest("GET", "https://api.github.com/gists/"+gistID, nil)
	req.Header.Set("Authorization", "token "+gistToken)
	resp, err := client.Do(req)
	if err != nil { return }
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
	if gistID == "" || gistToken == "" { return }
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
		if i := len(b64) % 4; i != 0 { b64 += strings.Repeat("=", 4-i) }
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil { decoded, err = base64.URLEncoding.DecodeString(b64) }
		if err != nil { return false }
		var v VMessConfig
		if err := json.Unmarshal(decoded, &v); err != nil { return false }
		return tcpDial(fmt.Sprintf("%v", v.Add), fmt.Sprintf("%v", v.Port))
	}
	if strings.Contains(strings.ToLower(protocol), "hy2") {
		u, err := url.Parse(config)
		if err != nil { return false }
		if tcpDial(u.Hostname(), u.Port()) { return true }
		ips, err := net.LookupIP(u.Hostname())
		return err == nil && len(ips) > 0
	}
	u, err := url.Parse(config)
	if err != nil { return false }
	return tcpDial(u.Hostname(), u.Port())
}

func tcpDial(host, port string) bool {
	if host == "" || port == "" { return false }
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil { return false }
	conn.Close()
	return true
}

func labelWithGeo(config string, index int) string {
	countryName, emoji := "Dynamic", "🏴"
	host := ""
	isVMess := strings.HasPrefix(strings.ToLower(config), "vmess://")

	if isVMess {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		if i := len(b64) % 4; i != 0 { b64 += strings.Repeat("=", 4-i) }
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil { decoded, _ = base64.URLEncoding.DecodeString(b64) }
		var v map[string]interface{}
		// FIXED SYNTAX HERE
		if err == nil {
			err = json.Unmarshal(decoded, &v)
			if err == nil {
				if h, ok := v["add"].(string); ok { host = h }
			}
		}
	} else {
		u, _ := url.Parse(config)
		if u != nil { host = u.Hostname() }
	}

	if db != nil && host != "" {
		ip := net.ParseIP(host)
		if ip == nil {
			ips, err := net.LookupIP(host)
			if err == nil && len(ips) > 0 { ip = ips[0] }
		}
		if ip != nil {
			record, err := db.Country(ip)
			if err == nil && record != nil {
				raw := record.Country.Names["en"]
				code := record.Country.IsoCode
				if raw != "" {
					switch raw {
					case "United States": countryName = "USA"
					case "United Kingdom": countryName = "UK"
					case "United Arab Emirates": countryName = "UAE"
					case "The Netherlands": countryName = "Netherlands"
					default: countryName = raw
					}
				}
				if len(code) == 2 {
					emoji = strings.Map(func(r rune) rune { return r + 127397 }, strings.ToUpper(code))
				}
			}
		}
	}

	label := fmt.Sprintf("%s %s | Node-%d", emoji, countryName, index)

	if isVMess {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		if i := len(b64) % 4; i != 0 { b64 += strings.Repeat("=", 4-i) }
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil { decoded, _ = base64.URLEncoding.DecodeString(b64) }
		var v map[string]interface{}
		// FIXED SYNTAX HERE
		err = json.Unmarshal(decoded, &v)
		if err == nil {
			v["ps"] = label
			newJSON, _ := json.Marshal(v)
			return "vmess://" + base64.StdEncoding.EncodeToString(newJSON)
		}
		return config 
	} else {
		cleanConfig := strings.Split(config, "#")[0]
		return fmt.Sprintf("%s#%s", cleanConfig, label)
	}
}

func generateOriginalReportStructure(reports []ChannelReport, total int) string {
	utcNow := time.Now().UTC()
	loc, _ := time.LoadLocation("Asia/Tehran")
	tehranNow := utcNow.In(loc)
	jy, jm, jd := toJalali(tehranNow.Year(), int(tehranNow.Month()), tehranNow.Day())
	
	var sb strings.Builder
	sb.WriteString("# 📊 Status Report\n\n")
	sb.WriteString("### 🕒 Last Update\n")
	sb.WriteString(fmt.Sprintf("- **Tehran Time:** 🇮🇷 `%d/%02d/%02d` | `%02d:%02d:%02d`\n", jy, jm, jd, tehranNow.Hour(), tehranNow.Minute(), tehranNow.Second()))
	sb.WriteString(fmt.Sprintf("- **International:** 🌐 `%s`\n\n", tehranNow.Format("Monday, 02 Jan 2006")))
	sb.WriteString("### ⚡ Global Statistics\n")
	sb.WriteString(fmt.Sprintf("- **Active Nodes Found:** ` %d ` 🚀\n", total))
	sb.WriteString("- **Status:** ` Operational ` ✅\n\n")
	sb.WriteString("### 📡 Source Analysis\n\n")
	sb.WriteString("| Source Channel | Available Protocols | Harvest Status |\n")
	sb.WriteString("| :--- | :--- | :--- |\n")
	for _, r := range reports {
		protos := strings.Join(r.Protocols, ", ")
		if protos == "" { protos = "—" }
		sb.WriteString(fmt.Sprintf("| 📢 [%s](https://t.me/s/%s) | `%s` | %s |\n", r.Name, r.Name, protos, r.Message))
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
	if gm > 2 && ((gy%4 == 0 && gy%100 != 0) || (gy%400 == 0)) { gDayNo++ }
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
	f, err := os.Open(p); if err != nil { return nil, err }; defer f.Close()
	r := csv.NewReader(f); var u []string
	for {
		row, err := r.Read()
		if err == io.EOF { break }
		if len(row) > 0 {
			cleaned := strings.TrimSpace(row[0])
			if cleaned == "" || strings.Contains(strings.ToUpper(cleaned), "URL") { continue }
			if !strings.HasPrefix(cleaned, "http") { cleaned = "https://t.me/" + cleaned }
			u = append(u, strings.TrimSuffix(cleaned, "/"))
		}
	}
	return u, nil
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	var list []string
	for _, v := range slice {
		fingerprint := getConfigFingerprint(v)
		if !seen[fingerprint] {
			seen[fingerprint] = true
			list = append(list, v)
		}
	}
	return list
}

func getConfigFingerprint(config string) string {
	if strings.HasPrefix(strings.ToLower(config), "vmess://") {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		if i := len(b64) % 4; i != 0 { b64 += strings.Repeat("=", 4-i) }
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil { decoded, err = base64.URLEncoding.DecodeString(b64) }
		if err == nil {
			var v VMessConfig
			// FIXED SYNTAX HERE
			err = json.Unmarshal(decoded, &v)
			if err == nil { return fmt.Sprintf("vmess|%s|%v|%v", v.Add, v.Port, v.Id) }
		}
		return config 
	}
	parts := strings.Split(config, "#")
	if len(parts) > 0 { return parts[0] }
	return config
}

func saveToFile(name string, data []string) { _ = os.WriteFile(name, []byte(strings.Join(data, "\n")), 0644) }

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
