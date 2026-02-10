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
	_ = flag.Bool("sort", false, "compatibility")
	_ = flag.String("p", "", "compatibility")
	flag.Parse()

	db, _ = geoip2.Open("Country.mmdb")
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

	gologger.Info().Msg("🚀 Starting Smart Scraper Engine...")
	
	for i, channelURL := range channels {
		uParts := strings.Split(strings.TrimSuffix(channelURL, "/"), "/")
		channelName := uParts[len(uParts)-1]
		
		// Instant progress feedback
		gologger.Info().Msgf("[%d/%d] Working on: %s", i+1, len(channels), channelName)
		
		report := ChannelReport{Name: channelName, Status: "✅ Active", Message: "Found configs"}
		
		req, _ := http.NewRequest("GET", "https://t.me/s/"+channelName, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		
		resp, err := client.Do(req)
		if err != nil {
			report.Status, report.Message = "❌ Error", "Timeout"
			gologger.Error().Msgf("   └─ Failed: Connection timeout")
			reports = append(reports, report); continue
		}

		if resp.StatusCode == 404 {
			report.Status, report.Message = "🚫 Dead", "Not Found"
			gologger.Error().Msgf("   └─ Failed: Channel username doesn't exist")
			reports = append(reports, report); resp.Body.Close(); continue
		}

		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()

		msgCount := 0
		doc.Find(".tgme_widget_message_wrap").Each(func(i int, s *goquery.Selection) { msgCount++ })

		if msgCount == 0 {
			report.Status, report.Message = "🔒 Private", "Private or Restricted"
			gologger.Warning().Msgf("   └─ Warning: Channel is private/locked")
		} else {
			count := 0
			doc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
				for proto, reg := range myregex {
					re := regexp.MustCompile(reg)
					matches := re.FindAllString(s.Text(), -1)
					for _, m := range matches {
						rawConfigs[proto] = append(rawConfigs[proto], m)
						count++
					}
				}
			})
			report.Count = count
			if count == 0 { 
				report.Status, report.Message = "⚠️ Inactive", "No links in batch" 
				gologger.Debug().Msgf("   └─ Info: No configs found in recent posts")
			} else {
				gologger.Info().Msgf("   └─ Success: Collected %d configs", count)
			}
		}
		totalRaw += report.Count
		reports = append(reports, report)
		
		// Safety delay
		time.Sleep(1200 * time.Millisecond)
	}

	sort.Slice(reports, func(i, j int) bool { return reports[i].Count > reports[j].Count })

	// Generate reports
	finalMarkdown := generateReports(reports, totalRaw)
	_ = os.WriteFile("summary.md", []byte(finalMarkdown), 0644)
	_ = os.WriteFile("report.md", []byte(finalMarkdown), 0644)

	// Test and Save
	for _, proto := range protocols {
		gologger.Info().Msgf("🧪 Testing %s configs...", strings.ToUpper(proto))
		healthy := fastPingTest(removeDuplicates(rawConfigs[proto]))
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

	gologger.Info().Msg("✨ Reports generated and configs updated.")
}

// --- Report & Time Logic ---

func generateReports(reports []ChannelReport, total int) string {
	utcNow := time.Now().UTC()
	loc, _ := time.LoadLocation("Asia/Tehran")
	tehranNow := utcNow.In(loc)
	jy, jm, jd := toJalali(tehranNow.Year(), int(tehranNow.Month()), tehranNow.Day())

	var sb strings.Builder
	sb.WriteString("# 📊 Collector Diagnostic Report\n\n")
	sb.WriteString("### 🕒 Generation Time\n")
	sb.WriteString(fmt.Sprintf("- **Tehran:** `%d/%02d/%02d` | `%02d:%02d:%02d`\n", jy, jm, jd, tehranNow.Hour(), tehranNow.Minute(), tehranNow.Second()))
	sb.WriteString(fmt.Sprintf("- **International:** `%s`\n", tehranNow.Format("Monday, 02 Jan 2006")))
	sb.WriteString(fmt.Sprintf("- **UTC:** `%s`\n\n", utcNow.Format("15:04:05")))
	
	sb.WriteString(fmt.Sprintf("### ⚡ Statistics\n- Total Raw Configs Found: `%d`\n\n", total))
	
	sb.WriteString("| Channel Name | Status | Qty | Diagnostic |\n")
	sb.WriteString("| :--- | :---: | :---: | :--- |\n")
	for _, r := range reports {
		sb.WriteString(fmt.Sprintf("| %s | %s | %d | %s |\n", r.Name, r.Status, r.Count, r.Message))
	}
	return sb.String()
}

func toJalali(gy, gm, gd int) (int, int, int) {
	gDays := []int{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334}
	gy2 := gy
	if gm > 2 { gy2++ }
	days := 365*(gy-1600) + (gy2-1597)/4 - (gy2-1501)/100 + (gy2-1201)/400 + gd + gDays[gm-1] - 79
	jy := 979 + 33*(days/12053) + 4*(days%12053/1461)
	days %= 12053; days %= 1461
	if days > 365 { jy += (days - 1) / 365; days = (days - 1) % 365 }
	jm := 0; jd := 0
	if days < 186 { jm = 1 + days/31; jd = 1 + days%31 } else { jm = 7 + (days-186)/30; jd = 1 + (days-186)%30 }
	return jy, jm, jd
}

// --- Standard Helpers ---

func loadChannelsFromCSV(p string) ([]string, error) {
	f, err := os.Open(p); if err != nil { return nil, err }; defer f.Close()
	r := csv.NewReader(f); var u []string
	for { row, err := r.Read(); if err == io.EOF { break }; if len(row) > 0 { u = append(u, row[0]) } }
	return u, nil
}

func fastPingTest(configs []string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	healthy := []string{}
	sem := make(chan struct{}, 50) 
	for i, cfg := range configs {
		wg.Add(1); go func(idx int, c string) {
			defer wg.Done(); sem <- struct{}{}; defer func() { <-sem }()
			if checkTCP(c) { mu.Lock(); healthy = append(healthy, labelWithGeo(c, idx+1)); mu.Unlock() }
		}(i, cfg)
	}
	wg.Wait(); return healthy
}

func checkTCP(config string) bool {
	u, err := url.Parse(config); if err != nil { return false }
	host := u.Hostname(); port := u.Port(); if port == "" { port = "443" }
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil { return false }; conn.Close(); return true
}

func labelWithGeo(config string, index int) string {
	u, _ := url.Parse(config)
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

func removeDuplicates(slice []string) []string {
	m := make(map[string]bool); var list []string
	for _, v := range slice { if !m[v] { m[v] = true; list = append(list, v) } }
	return list
}

func saveToFile(name string, data []string) {
	_ = os.WriteFile(name, []byte(strings.Join(data, "\n")), 0644)
}
