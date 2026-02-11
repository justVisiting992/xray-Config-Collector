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

	var err error
	db, err = geoip2.Open("Country.mmdb")
	if err != nil {
		gologger.Error().Msg("❌ GeoIP database (Country.mmdb) missing.")
	} else {
		defer db.Close()
	}

	rawChannels, _ := loadChannelsFromCSV("channels.csv")
	channels := removeDuplicates(rawChannels)

	newConfigs := make(map[string][]string)
	historyConfigs := make(map[string][]string)

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
					u.Fragment = ""
					historyConfigs[p] = append(historyConfigs[p], u.String())
				}
			}
		}
	}

	var reports []ChannelReport
	totalScraped := 0

	// 1. Process Python Dump (API Results)
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
		var protoList []string
		for p := range foundProtos { protoList = append(protoList, p) }
		reports = append(reports, ChannelReport{
			Name: "Python-API-Collector",
			Count: count,
			Message: fmt.Sprintf("✅ %d Configs via API", count),
			Protocols: protoList,
		})
		totalScraped += count
	}

	// 2. Web Scraper
	for _, channelURL := range channels {
		uParts := strings.Split(strings.TrimSuffix(channelURL, "/"), "/")
		channelName := uParts[len(uParts)-1]
		report := ChannelReport{Name: channelName}
		req, _ := http.NewRequest("GET", "https://t.me/s/"+channelName, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			report.Message = "❌ Timeout"
			reports = append(reports, report)
			continue
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
		if report.Count > 0 { report.Message = fmt.Sprintf("✅ %d found", report.Count) } else { report.Message = "💤 No recent configs" }
		totalScraped += report.Count
		reports = append(reports, report)
	}

	sort.Slice(reports, func(i, j int) bool { return reports[i].Count > reports[j].Count })
	_ = os.WriteFile("report.md", []byte(generateOriginalReportStructure(reports, totalScraped)), 0644)

	// 3. Testing and Saving
	var allMixed []string
	for p := range myregex {
		combined := append(newConfigs[p], historyConfigs[p]...)
		unique := removeDuplicates(combined)
		healthy := fastPingTest(unique)
		limit := len(healthy)
		if limit > maxLimit { limit = maxLimit }
		finalList := healthy[:limit]
		saveToFile(strings.ToLower(p)+"_iran.txt", finalList)
		allMixed = append(allMixed, finalList...)
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
					if len(code) == 2 {
						emoji = strings.Map(func(r rune) rune { return r + 127397 }, strings.ToUpper(code))
					}
				}
			}
		}
	}
	u.Fragment = "" 
	baseConfig := strings.Split(u.String(), "#")[0]
	return fmt.Sprintf("%s#%s %s | Node-%d", baseConfig, emoji, countryName, index)
}

func generateOriginalReportStructure(reports []ChannelReport, total int) string {
	utcNow := time.Now().UTC()
	loc, _ := time.LoadLocation("Asia/Tehran")
	tehranNow := utcNow.In(loc)
	jy, jm, jd := toJalali(tehranNow.Year(), int(tehranNow.Month()), tehranNow.Day())
	var sb strings.Builder
	sb.WriteString("# 💠 Xray Source Tribute & Report\n\n### 🕒 Last Update\n")
	sb.WriteString(fmt.Sprintf("- **Tehran:** `%d/%02d/%02d` | `%02d:%02d:%02d`\n", jy, jm, jd, tehranNow.Hour(), tehranNow.Minute(), tehranNow.Second()))
	sb.WriteString(fmt.Sprintf("- **International:** `%s`\n\n### ⚡ Global Stats\n- **Total Working Configs:** `%d`\n\n", tehranNow.Format("Monday, 02 Jan 2006"), total))
	sb.WriteString("| Source Channel | Available Protocols | Harvest Status |\n| :--- | :--- | :--- |\n")
	for _, r := range reports {
		protos := strings.Join(r.Protocols, ", ")
		if protos == "" { protos = "—" }
		sb.WriteString(fmt.Sprintf("| [%s](https://t.me/s/%s) | %s | %s |\n", r.Name, r.Name, protos, r.Message))
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
	jm, jd := 0, 0
	if days < 186 { jm = 1 + days/31; jd = 1 + days%31 } else { jm = 7 + (days-186)/30; jd = 1 + (days-186)%30 }
	return jy, jm, jd
}

func fastPingTest(configs []string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	healthy := []string{}
	sem := make(chan struct{}, 50)
	// FIXED: Changed 'i' to '_' because index was unused
	for _, cfg := range configs {
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
	if host == "" { return false }
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil { return false }; conn.Close(); return true
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
	m := make(map[string]bool); var list []string
	for _, v := range slice { if !m[v] { m[v] = true; list = append(list, v) } }
	return list
}

func saveToFile(name string, data []string) { _ = os.WriteFile(name, []byte(strings.Join(data, "\n")), 0644) }
