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
	Name    string
	Count   int
	Status  string
	Message string
}

var (
	client   = &http.Client{Timeout: 12 * time.Second}
	maxLimit = 200
	db       *geoip2.Reader
	myregex  = map[string]string{
		"ss":     `ss://[A-Za-z0-9./:=?#-_@!%]+`,
		"vmess":  `vmess://[A-Za-z0-9./:=?#-_@!%]+`,
		"trojan": `trojan://[A-Za-z0-9./:=?#-_@!%]+`,
		"vless":  `vless://[A-Za-z0-9./:=?#-_@!%]+`,
		"hy2":    `hysteria2://[A-Za-z0-9./:=?#-_@!%]+`,
	}
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	_ = flag.Bool("sort", false, "compatibility flag")
	_ = flag.String("p", "", "compatibility flag")
	flag.Parse()

	// 1. Load GeoIP
	var err error
	db, err = geoip2.Open("Country.mmdb")
	if err != nil {
		gologger.Warning().Msg("Country.mmdb missing. Using generic labels.")
	} else {
		defer db.Close()
	}

	// 2. Load Channels
	channels, err := loadChannelsFromCSV("channels.csv")
	if err != nil {
		gologger.Fatal().Msg("CSV Error: " + err.Error())
	}

	rawConfigs := make(map[string][]string)
	protocols := []string{"ss", "vmess", "trojan", "vless", "hy2"}
	for _, p := range protocols {
		rawConfigs[p] = []string{}
	}

	var reports []ChannelReport
	totalRaw := 0

	// 3. Scraper Engine
	gologger.Info().Msg("🚀 Starting Smart Scraper Engine...")
	for _, channelURL := range channels {
		uParts := strings.Split(strings.TrimSuffix(channelURL, "/"), "/")
		channelName := uParts[len(uParts)-1]
		
		report := ChannelReport{Name: channelName, Status: "✅ Active", Message: "Found configs"}
		
		req, _ := http.NewRequest("GET", "https://t.me/s/"+channelName, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
		
		resp, err := client.Do(req)
		if err != nil {
			report.Status, report.Message = "❌ Error", "Connection Timeout"
			reports = append(reports, report); continue
		}

		if resp.StatusCode == 404 {
			report.Status, report.Message = "🚫 Dead", "Channel Username Not Found"
			reports = append(reports, report); resp.Body.Close(); continue
		}

		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()

		// Diagnostic: Pulse Check
		msgCount := 0
		doc.Find(".tgme_widget_message_wrap").Each(func(i int, s *goquery.Selection) { msgCount++ })

		if msgCount == 0 {
			report.Status, report.Message = "🔒 Private", "Channel is Private or Restricted"
		} else {
			countForChannel := 0
			doc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
				text := s.Text()
				for proto, reg := range myregex {
					re := regexp.MustCompile(reg)
					matches := re.FindAllString(text, -1)
					for _, m := range matches {
						rawConfigs[proto] = append(rawConfigs[proto], m)
						countForChannel++
					}
				}
			})
			report.Count = countForChannel
			if countForChannel == 0 {
				report.Status, report.Message = "⚠️ Inactive", "Posts found, but no config links"
			}
		}
		
		totalRaw += report.Count
		reports = append(reports, report)
		gologger.Info().Msgf("[%s] -> Found: %d", channelName, report.Count)
		time.Sleep(1200 * time.Millisecond)
	}

	// 4. Sort and Generate Reports
	sort.Slice(reports, func(i, j int) bool { return reports[i].Count > reports[j].Count })
	generateMarkdownSummary(reports, totalRaw)
	printConsoleReport(reports, totalRaw)

	// 5. Test & Save
	for _, proto := range protocols {
		unique := removeDuplicates(rawConfigs[proto])
		healthy := fastPingTest(unique)
		
		limit := len(healthy)
		if limit > maxLimit { limit = maxLimit }
		saveToFile(proto+"_iran.txt", healthy[:limit])
	}
	
	// Mixed Unlimited
	var allMixed []string
	for _, p := range protocols {
		allMixed = append(allMixed, rawConfigs[p]...)
	}
	saveToFile("mixed_iran.txt", removeDuplicates(allMixed))
	
	gologger.Info().Msg("✨ All tasks finished.")
}

// --- Internal Logic ---

func loadChannelsFromCSV(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	reader := csv.NewReader(f)
	var urls []string
	for {
		row, err := reader.Read()
		if err == io.EOF { break }
		if len(row) > 0 && strings.HasPrefix(row[0], "http") {
			urls = append(urls, strings.TrimSpace(row[0]))
		}
	}
	return urls, nil
}

func generateMarkdownSummary(reports []ChannelReport, total int) {
	var sb strings.Builder
	sb.WriteString("# 📊 Scraper Diagnostic Report\n\n")
	sb.WriteString(fmt.Sprintf("### Total Raw Configs Found: `%d`\n\n", total))
	sb.WriteString("| Channel Name | Status | Configs | Diagnostic Message |\n")
	sb.WriteString("| :--- | :---: | :---: | :--- |\n")
	for _, r := range reports {
		sb.WriteString(fmt.Sprintf("| %s | %s | %d | %s |\n", r.Name, r.Status, r.Count, r.Message))
	}
	_ = os.WriteFile("summary.md", []byte(sb.String()), 0644)
}

func printConsoleReport(reports []ChannelReport, total int) {
	fmt.Println("\n" + strings.Repeat("=", 55))
	fmt.Printf("%-20s | %-10s | %-5s | %-15s\n", "CHANNEL", "STATUS", "QTY", "DIAGNOSTIC")
	fmt.Println(strings.Repeat("-", 55))
	for _, r := range reports {
		fmt.Printf("%-20s | %-10s | %-5d | %-15s\n", r.Name, r.Status, r.Count, r.Message)
	}
	fmt.Println(strings.Repeat("=", 55))
}

func fastPingTest(configs []string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	healthy := []string{}
	sem := make(chan struct{}, 50) 
	for i, cfg := range configs {
		wg.Add(1)
		go func(idx int, c string) {
			defer wg.Done(); sem <- struct{}{}; defer func() { <-sem }()
			if checkTCP(c) {
				mu.Lock(); healthy = append(healthy, labelWithGeo(c, idx+1)); mu.Unlock()
			}
		}(i, cfg)
	}
	wg.Wait()
	return healthy
}

func checkTCP(config string) bool {
	u, err := url.Parse(config)
	if err != nil { return false }
	address := net.JoinHostPort(u.Hostname(), u.Port())
	if u.Port() == "" { address = net.JoinHostPort(u.Hostname(), "443") }
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil { return false }
	conn.Close(); return true
}

func labelWithGeo(config string, index int) string {
	u, _ := url.Parse(config)
	country := "🏴 Dynamic"
	if db != nil {
		ip := net.ParseIP(u.Hostname())
		if ip == nil {
			ips, _ := net.LookupIP(u.Hostname())
			if len(ips) > 0 { ip = ips[0] }
		}
		if ip != nil {
			record, _ := db.Country(ip)
			if record != nil && record.Country.Names["en"] != "" { country = record.Country.Names["en"] }
		}
	}
	u.Fragment = url.PathEscape(fmt.Sprintf("%s | Node-%d", country, index))
	return u.String()
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
