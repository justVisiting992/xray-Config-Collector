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
	client   = &http.Client{Timeout: 12 * time.Second}
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
	rawChannels, err := loadChannelsFromCSV("channels.csv")
	if err != nil {
		gologger.Fatal().Msg("CSV Error: " + err.Error())
	}
	channels := removeDuplicates(rawChannels)

	newConfigs := make(map[string][]string)
	historyConfigs := make(map[string][]string)

	// --- STEP 1: LOAD HISTORY ---
	for p := range myregex {
		newConfigs[p] = []string{}
		historyConfigs[p] = []string{}
		content, err := os.ReadFile(strings.ToLower(p) + "_iran.txt")
		if err == nil {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" { continue }
				u, err := url.Parse(line)
				if err == nil {
					u.Fragment = "" // Strip label for re-testing
					historyConfigs[p] = append(historyConfigs[p], u.String())
				}
			}
		}
	}

	// --- STEP 2: SCRAPE NEW CONTENT ---
	var reports []ChannelReport
	totalScraped := 0
	for i, channelURL := range channels {
		uParts := strings.Split(strings.TrimSuffix(channelURL, "/"), "/")
		channelName := uParts[len(uParts)-1]
		gologger.Info().Msgf("[%d/%d] Scraping: %s", i+1, len(channels), channelName)
		
		report := ChannelReport{Name: channelName}
		req, _ := http.NewRequest("GET", "https://t.me/s/"+channelName, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		
		resp, err := client.Do(req)
		if err != nil {
			report.Message = "❌ Timeout"; reports = append(reports, report); continue
		}
		if resp.StatusCode != 200 {
			report.Message = fmt.Sprintf("🚫 Status %d", resp.StatusCode); reports = append(reports, report); resp.Body.Close(); continue
		}

		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()

		foundProtos := make(map[string]bool)
		doc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
			text := s.Text()
			for pName, reg := range myregex {
				re := regexp.MustCompile(reg)
				matches := re.FindAllString(text, -1)
				if len(matches) > 0 {
					foundProtos[pName] = true
					newConfigs[pName] = append(newConfigs[pName], matches...)
					report.Count += len(matches)
				}
			}
		})
		
		for p := range foundProtos { report.Protocols = append(report.Protocols, p) }
		sort.Strings(report.Protocols)
		if report.Count > 0 { report.Message = fmt.Sprintf("✅ Found %d", report.Count) } else { report.Message = "💤 No new" }
		totalScraped += report.Count
		reports = append(reports, report)
		time.Sleep(1200 * time.Millisecond)
	}

	// --- STEP 3: MERGE (FRESH FIRST), TEST, AND SAVE ---
	sort.Slice(reports, func(i, j int) bool { return reports[i].Count > reports[j].Count })
	_ = os.WriteFile("report.md", []byte(generateReports(reports, totalScraped)), 0644)

	var allMixed []string
	for p := range myregex {
		// Priority: NEW scraped configs come first in the slice
		combined := append(newConfigs[p], historyConfigs[p]...)
		merged := removeDuplicates(combined) // Keeps the first occurrence (the new ones)
		
		healthy := fastPingTest(merged)
		
		limit := len(healthy)
		if limit > maxLimit { limit = maxLimit }
		
		saveToFile(strings.ToLower(p)+"_iran.txt", healthy[:limit])
		allMixed = append(allMixed, healthy[:limit]...)
		gologger.Info().Msgf("💾 %s: %d fresh/healthy configs saved", p, limit)
	}
	
	saveToFile("mixed_iran.txt", removeDuplicates(allMixed))
	gologger.Info().Msg("✨ Finished. History preserved and fresh configs prioritized.")
}

func fastPingTest(configs []string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	healthy := []string{}
	sem := make(chan struct{}, 50) 
	for i, cfg := range configs {
		wg.Add(1); go func(idx int, c string) {
			defer wg.Done(); sem <- struct{}{}; defer func() { <-sem }()
			if checkTCP(c) { 
				labeled := labelWithGeo(c, idx+1)
				mu.Lock(); healthy = append(healthy, labeled); mu.Unlock() 
			}
		}(i, cfg)
	}
	wg.Wait(); return healthy
}

func checkTCP(config string) bool {
	u, err := url.Parse(config); if err != nil { return false }
	host := u.Hostname(); port := u.Port(); if port == "" { port = "443" }
	if host == "" { return false }
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil { return false }; conn.Close(); return true
}

func labelWithGeo(config string, index int) string {
	u, err := url.Parse(config); if err != nil { return config }
	country := "🏴 Dynamic"
	if db != nil {
		ip := net.ParseIP(u.Hostname())
		if ip == nil { ips, _ := net.LookupIP(u.Hostname()); if len(ips) > 0 { ip = ips[0] } }
		if ip != nil {
			record, _ := db.Country(ip)
			if record != nil && record.Country.Names["en"] != "" { country = record.Country.Names["en"] }
		}
	}
	u.Fragment = url.PathEscape(fmt.Sprintf("%s | Node-%d", country, index))
	return u.String()
}

func loadChannelsFromCSV(p string) ([]string, error) {
	f, err := os.Open(p); if err != nil { return nil, err }; defer f.Close()
	r := csv.NewReader(f); var u []string
	for { 
		row, err := r.Read()
		if err == io.EOF { break }
		if len(row) > 0 { 
			cleaned := strings.TrimSpace(row[0])
			if cleaned == "" || strings.Contains(cleaned, "URL") { continue }
			if !strings.HasPrefix(cleaned, "http") { cleaned = "https://t.me/" + cleaned }
			u = append(u, strings.TrimSuffix(cleaned, "/")) 
		} 
	}
	return u, nil
}

func generateReports(reports []ChannelReport, total int) string {
	var sb strings.Builder
	sb.WriteString("# 💠 Xray Source Report\n\n")
	sb.WriteString(fmt.Sprintf("Last Update: `%s` (UTC)\n\n", time.Now().UTC().Format("2006-01-02 15:04:05")))
	sb.WriteString("| Source Channel | Protocols | Status |\n| :--- | :--- | :--- |\n")
	for _, r := range reports {
		sb.WriteString(fmt.Sprintf("| [%s](https://t.me/s/%s) | %s | %s |\n", r.Name, r.Name, strings.Join(r.Protocols, ","), r.Message))
	}
	return sb.String()
}

func removeDuplicates(slice []string) []string {
	m := make(map[string]bool); var list []string
	for _, v := range slice {
		if !m[v] { m[v] = true; list = append(list, v) }
	}
	return list
}

func saveToFile(name string, data []string) {
	_ = os.WriteFile(name, []byte(strings.Join(data, "\n")), 0644)
}
