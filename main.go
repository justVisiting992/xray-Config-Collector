package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/oschwald/geoip2-golang"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

type ChannelReport struct {
	Name      string
	Protocols []string
	Count     int
	Message   string
}

var (
	client   = &http.Client{Timeout: 15 * time.Second}
	maxLimit = 200
	db       *geoip2.Reader
	myregex  = map[string]string{
		"SS":     `(?i)ss://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"Vmess":  `(?i)vmess://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"Trojan": `(?i)trojan://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"Vless":  `(?i)vless://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"Hy2":    `(?i)(?:hysteria2|hy2)://[A-Za-z0-9./:=?#-_@!%&+=]+`,
	}
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()

	db, _ = geoip2.Open("Country.mmdb")
	rawChannels, _ := loadChannelsFromCSV("channels.csv")
	channels := removeDuplicates(rawChannels)

	newConfigs := make(map[string][]string)
	historyConfigs := make(map[string][]string)

	for p := range myregex {
		newConfigs[p] = []string{}
		historyConfigs[p] = []string{}
		content, _ := os.ReadFile(strings.ToLower(p) + "_iran.txt")
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if u, err := url.Parse(strings.TrimSpace(line)); err == nil {
				u.Fragment = ""
				historyConfigs[p] = append(historyConfigs[p], u.String())
			}
		}
	}

	var reports []ChannelReport
	totalScraped := 0

	// 1. Load Python API Dump
	pythonDump, pyErr := os.ReadFile("telegram_dump.txt")
	if pyErr == nil && len(pythonDump) > 0 {
		count := 0
		foundProtos := make(map[string]bool)
		for pName, reg := range myregex {
			re := regexp.MustCompile(reg)
			matches := re.FindAllString(string(pythonDump), -1)
			if len(matches) > 0 {
				newConfigs[pName] = append(newConfigs[pName], matches...)
				count += len(matches)
				foundProtos[pName] = true
			}
		}
		var pList []string
		for p := range foundProtos { pList = append(pList, p) }
		reports = append(reports, ChannelReport{Name: "Python-API", Count: count, Message: "✅ API Success", Protocols: pList})
		totalScraped += count
	}

	// 2. Web Scraper (includes channels.csv + Web Backup for PersianVpnHub)
	for _, channelURL := range channels {
		uParts := strings.Split(strings.TrimSuffix(channelURL, "/"), "/")
		channelName := uParts[len(uParts)-1]
		
		report := ChannelReport{Name: channelName}
		req, _ := http.NewRequest("GET", "https://t.me/s/"+channelName, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil { continue }
		
		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()
		foundProtos := make(map[string]bool)
		doc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
			for pName, reg := range myregex {
				matches := regexp.MustCompile(reg).FindAllString(s.Text(), -1)
				if len(matches) > 0 {
					foundProtos[pName] = true
					newConfigs[pName] = append(newConfigs[pName], matches...)
					report.Count += len(matches)
				}
			}
		})
		for p := range foundProtos { report.Protocols = append(report.Protocols, p) }
		if report.Count > 0 { report.Message = fmt.Sprintf("✅ %d found", report.Count) }
		totalScraped += report.Count
		reports = append(reports, report)
	}

	sort.Slice(reports, func(i, j int) bool { return reports[i].Count > reports[j].Count })
	_ = os.WriteFile("report.md", []byte(generateOriginalReportStructure(reports, totalScraped)), 0644)

	var allMixed []string
	for p := range myregex {
		combined := append(newConfigs[p], historyConfigs[p]...)
		healthy := fastPingTest(removeDuplicates(combined))
		limit := len(healthy)
		if limit > maxLimit { limit = maxLimit }
		saveToFile(strings.ToLower(p)+"_iran.txt", healthy[:limit])
		allMixed = append(allMixed, healthy[:limit]...)
	}
	saveToFile("mixed_iran.txt", removeDuplicates(allMixed))
}

func labelWithGeo(config string, index int) string {
	u, err := url.Parse(config); if err != nil { return config }
	countryName, emoji := "Dynamic", "🏴"
	host := u.Hostname()
	if db != nil && host != "" {
		ip := net.ParseIP(host)
		if ip == nil {
			if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 { ip = ips[0] }
		}
		if ip != nil {
			if r, _ := db.Country(ip); r != nil {
				raw := r.Country.Names["en"]
				code := r.Country.IsoCode
				switch raw {
				case "United States": countryName = "USA"
				case "United Kingdom": countryName = "UK"
				case "United Arab Emirates": countryName = "UAE"
				case "The Netherlands": countryName = "Netherlands"
				default: countryName = raw
				}
				if len(code) == 2 {
					emoji = strings.Map(func(r rune) rune { return r + 127397 }, strings.ToUpper(code))
				}
			}
		}
	}
	// FIX: Use raw string concatenation for fragment to prevent percent-encoding in Hiddify
	u.Fragment = "" // Clear it first
	return fmt.Sprintf("%s#%s %s | Node-%d", strings.Split(u.String(), "#")[0], emoji, countryName, index)
}

func generateOriginalReportStructure(reports []ChannelReport, total int) string {
	loc, _ := time.LoadLocation("Asia/Tehran")
	tehranNow := time.Now().In(loc)
	jy, jm, jd := toJalali(tehranNow.Year(), int(tehranNow.Month()), tehranNow.Day())
	var sb strings.Builder
	sb.WriteString("# 💠 Xray Source Tribute & Report\n\n### 🕒 Last Update\n")
	sb.WriteString(fmt.Sprintf("- **Tehran:** `%d/%02d/%02d` | `%02d:%02d:%02d`\n", jy, jm, jd, tehranNow.Hour(), tehranNow.Minute(), tehranNow.Second()))
	sb.WriteString(fmt.Sprintf("- **International:** `%s`\n\n### ⚡ Stats\n- **Working Configs:** `%d`\n\n", tehranNow.Format("Monday, 02 Jan 2006"), total))
	sb.WriteString("| Source | Protocols | Status |\n| :--- | :--- | :--- |\n")
	for _, r := range reports {
		p := strings.Join(r.Protocols, ", "); if p == "" { p = "—" }
		sb.WriteString(fmt.Sprintf("| [%s](https://t.me/s/%s) | %s | %s |\n", r.Name, r.Name, p, r.Message))
	}
	return sb.String()
}

func toJalali(gy, gm, gd int) (int, int, int) {
	gDays := []int{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334}
	gy2 := gy; if gm > 2 { gy2++ }
	days := 365*(gy-1600) + (gy2-1597)/4 - (gy2-1501)/100 + (gy2-1201)/400 + gd + gDays[gm-1] - 79
	jy := 979 + 33*(days/12053) + 4*(days%12053/1461)
	days %= 12053; days %= 1461
	if days > 365 { jy += (days - 1) / 365; days = (days - 1) % 365 }
	jm, jd := 0, 0
	if days < 186 { jm = 1 + days/31; jd = 1 + days%31 } else { jm = 7 + (days-186)/30; jd = 1 + (days-186)%30 }
	return jy, jm, jd
}

func fastPingTest(configs []string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	healthy := []string{}
	sem := make(chan struct{}, 50)
	for i, cfg := range configs {
		wg.Add(1); go func(c string) {
			defer wg.Done(); sem <- struct{}{}; defer func() { <-sem }()
			if checkTCP(c) {
				mu.Lock()
				healthy = append(healthy, labelWithGeo(c, len(healthy)+1))
				mu.Unlock()
			}
		}(cfg)
	}
	wg.Wait(); return healthy
}

func checkTCP(config string) bool {
	u, err := url.Parse(config); if err != nil { return false }
	host, port := u.Hostname(), u.Port()
	if port == "" { port = "443" }
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil { return false }; conn.Close(); return true
}

func loadChannelsFromCSV(p string) ([]string, error) {
	f, _ := os.Open(p); defer f.Close()
	r := csv.NewReader(f); var u []string
	for {
		row, err := r.Read(); if err == io.EOF { break }
		if len(row) > 0 && !strings.Contains(row[0], "URL") {
			c := strings.TrimSpace(row[0])
			if !strings.HasPrefix(c, "http") { c = "https://t.me/" + c }
			u = append(u, strings.TrimSuffix(c, "/"))
		}
	}
	return u, nil
}

func removeDuplicates(s []string) []string {
	m := make(map[string]bool); var l []string
	for _, v := range s { if !m[v] { m[v] = true; l = append(l, v) } }
	return l
}

func saveToFile(n string, d []string) { _ = os.WriteFile(n, []byte(strings.Join(d, "\n")), 0644) }
