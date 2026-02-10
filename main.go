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
		"SS":     `ss://[A-Za-z0-9./:=?#-_@!%]+`,
		"Vmess":  `vmess://[A-Za-z0-9./:=?#-_@!%]+`,
		"Trojan": `trojan://[A-Za-z0-9./:=?#-_@!%]+`,
		"Vless":  `vless://[A-Za-z0-9./:=?#-_@!%]+`,
		"Hy2":    `hysteria2://[A-Za-z0-9./:=?#-_@!%]+`,
	}
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	_ = flag.Bool("sort", false, "compatibility")
	_ = flag.String("p", "", "compatibility")
	flag.Parse()

	db, _ = geoip2.Open("Country.mmdb")
	rawChannels, err := loadChannelsFromCSV("channels.csv")
	if err != nil {
		gologger.Fatal().Msg("CSV Error: " + err.Error())
	}
	channels := removeDuplicates(rawChannels)

	rawConfigs := make(map[string][]string)
	for p := range myregex {
		rawConfigs[p] = []string{}
	}

	var reports []ChannelReport
	totalRaw := 0

	gologger.Info().Msgf("🚀 Starting Engine... (Processing %d unique sources)", len(channels))
	
	for i, channelURL := range channels {
		uParts := strings.Split(strings.TrimSuffix(channelURL, "/"), "/")
		channelName := uParts[len(uParts)-1]
		
		gologger.Info().Msgf("[%d/%d] Analyzing: %s", i+1, len(channels), channelName)
		report := ChannelReport{Name: channelName, Protocols: []string{}}
		
		req, _ := http.NewRequest("GET", "https://t.me/s/"+channelName, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		
		resp, err := client.Do(req)
		if err != nil {
			report.Message = "❌ Connection Timeout"
			reports = append(reports, report); continue
		}
		if resp.StatusCode == 404 {
			report.Message = "🚫 Channel Not Found"
			reports = append(reports, report); resp.Body.Close(); continue
		}

		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()

		msgCount := 0
		doc.Find(".tgme_widget_message_wrap").Each(func(i int, s *goquery.Selection) { msgCount++ })

		if msgCount == 0 {
			report.Message = "🔒 Private/Restricted"
		} else {
			foundProtos := make(map[string]bool)
			hasAlt := false
			
			doc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
				text := s.Text()
				for pName, reg := range myregex {
					re := regexp.MustCompile(reg)
					matches := re.FindAllString(text, -1)
					if len(matches) > 0 {
						foundProtos[pName] = true
						rawConfigs[pName] = append(rawConfigs[pName], matches...)
						report.Count += len(matches)
					}
				}
				lowText := strings.ToLower(text)
				if strings.Contains(lowText, "tg:proxy") || strings.Contains(lowText, ".npv2") || 
				   strings.Contains(lowText, ".sks") || strings.Contains(lowText, "mtproto") {
					hasAlt = true
				}
			})
			
			for p := range foundProtos {
				report.Protocols = append(report.Protocols, p)
			}
			sort.Strings(report.Protocols)

			if report.Count > 0 {
				report.Message = fmt.Sprintf("✅ %d Xray configs found", report.Count)
			} else if hasAlt {
				report.Protocols = append(report.Protocols, "MTProto/Files")
				report.Message = "📂 Active (Non-Xray content)"
			} else {
				report.Message = "💤 No recent configs found"
			}
		}
		totalRaw += report.Count
		reports = append(reports, report)
		time.Sleep(1200 * time.Millisecond)
	}

	sort.Slice(reports, func(i, j int) bool { return reports[i].Count > reports[j].Count })

	finalMarkdown := generateReports(reports, totalRaw)
	_ = os.WriteFile("summary.md", []byte(finalMarkdown), 0644)
	_ = os.WriteFile("report.md", []byte(finalMarkdown), 0644)

	// Ping Test and Save (unchanged logic)
	for p := range myregex {
		healthy := fastPingTest(removeDuplicates(rawConfigs[p]))
		limit := len(healthy)
		if limit > maxLimit { limit = maxLimit }
		saveToFile(strings.ToLower(p)+"_iran.txt", healthy[:limit])
	}
	
	var allMixed []string
	for p := range myregex {
		allMixed = append(allMixed, rawConfigs[p]...)
	}
	saveToFile("mixed_iran.txt", removeDuplicates(allMixed))

	gologger.Info().Msg("✨ Tribute report and configs generated.")
}

func generateReports(reports []ChannelReport, total int) string {
	utcNow := time.Now().UTC()
	loc, _ := time.LoadLocation("Asia/Tehran")
	tehranNow := utcNow.In(loc)
	jy, jm, jd := toJalali(tehranNow.Year(), int(tehranNow.Month()), tehranNow.Day())

	var sb strings.Builder
	sb.WriteString("# 💠 Xray Source Tribute & Report\n\n")
	sb.WriteString("This page is a tribute to the channel admins providing free configurations. Data is updated every 2 hours.\n\n")
	sb.WriteString("### 🕒 Last Update\n")
	sb.WriteString(fmt.Sprintf("- **Tehran:** `%d/%02d/%02d` | `%02d:%02d:%02d`\n", jy, jm, jd, tehranNow.Hour(), tehranNow.Minute(), tehranNow.Second()))
	sb.WriteString(fmt.Sprintf("- **International:** `%s`\n", tehranNow.Format("Monday, 02 Jan 2006")))
	
	sb.WriteString(fmt.Sprintf("\n### ⚡ Global Stats\n- **Total Working Configs Harvested:** `%d`\n\n", total))
	
	sb.WriteString("| Source Channel | Available Protocols | Harvest Status |\n")
	sb.WriteString("| :--- | :--- | :--- |\n")
	for _, r := range reports {
		channelLink := fmt.Sprintf("[%s](https://t.me/s/%s)", r.Name, r.Name)
		protos := strings.Join(r.Protocols, ", ")
		if protos == "" { protos = "—" }
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", channelLink, protos, r.Message))
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

func loadChannelsFromCSV(p string) ([]string, error) {
	f, err := os.Open(p); if err != nil { return nil, err }; defer f.Close()
	r := csv.NewReader(f); var u []string
	for { 
		row, err := r.Read()
		if err == io.EOF { break }
		if len(row) > 0 { 
			cleaned := strings.TrimSpace(row[0])
			if cleaned != "" && strings.HasPrefix(cleaned, "http") {
				u = append(u, strings.TrimSuffix(cleaned, "/")) 
			}
		} 
	}
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
	for _, v := range slice {
		if !m[v] { m[v] = true; list = append(list, v) }
	}
	return list
}

func saveToFile(name string, data []string) {
	_ = os.WriteFile(name, []byte(strings.Join(data, "\n")), 0644)
}
