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

var (
	client   = &http.Client{Timeout: 10 * time.Second}
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
	flag.Parse()

	// 1. Load GeoIP Database
	var err error
	db, err = geoip2.Open("Country.mmdb")
	if err != nil {
		gologger.Warning().Msg("Country.mmdb not found. IP labeling will be skipped.")
	} else {
		defer db.Close()
	}

	// 2. Load Channels using built-in CSV logic
	channels, err := loadChannelsFromCSV("channels.csv")
	if err != nil {
		gologger.Fatal().Msg("Could not read channels.csv: " + err.Error())
	}

	rawConfigs := make(map[string][]string)
	protocols := []string{"ss", "vmess", "trojan", "vless", "hy2"}
	for _, p := range protocols {
		rawConfigs[p] = []string{}
	}

	channelStats := make(map[string]int)
	totalFound := 0

	// 3. Scraper Engine
	gologger.Info().Msg("🚀 Starting Scraper Engine...")
	for _, channelURL := range channels {
		uParts := strings.Split(strings.TrimSuffix(channelURL, "/"), "/")
		channelName := uParts[len(uParts)-1]
		
		req, _ := http.NewRequest("GET", "https://t.me/s/"+channelName, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err := client.Do(req)
		
		if err != nil || resp.StatusCode != 200 {
			gologger.Error().Msgf("Failed to reach: %s", channelName)
			continue
		}
		
		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()

		countForThisChannel := 0
		doc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
			text := s.Text()
			for proto, reg := range myregex {
				re := regexp.MustCompile(reg)
				matches := re.FindAllString(text, -1)
				for _, m := range matches {
					rawConfigs[proto] = append(rawConfigs[proto], m)
					countForThisChannel++
				}
			}
		})
		
		channelStats[channelName] = countForThisChannel
		totalFound += countForThisChannel
		gologger.Info().Msgf("✅ Scraped %d configs from [%s]", countForThisChannel, channelName)
		
		// Anti-ban delay
		time.Sleep(1200 * time.Millisecond)
	}

	// 4. Print Summary to GitHub Logs
	printFinalReport(channelStats, totalFound)

	// 5. Test and Save
	var allHealthyConfigs []string
	for proto, configs := range rawConfigs {
		uniqueConfigs := removeDuplicates(configs)
		gologger.Info().Msgf("🧪 Testing %d unique %s configs...", len(uniqueConfigs), strings.ToUpper(proto))
		
		healthy := fastPingTest(uniqueConfigs)
		allHealthyConfigs = append(allHealthyConfigs, healthy...)

		// Save categorized (Top 200)
		limit := len(healthy)
		if limit > maxLimit {
			limit = maxLimit
		}
		saveToFile(proto+"_iran.txt", healthy[:limit])
	}

	// Save Unlimited Mixed
	saveToFile("mixed_iran.txt", allHealthyConfigs)
	gologger.Info().Msg("✨ Task completed successfully. Configs updated.")
}

// --- Helper Functions ---

func loadChannelsFromCSV(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var channels []string
	reader := csv.NewReader(f)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// Assuming URL is in the first column
		if len(record) > 0 && strings.HasPrefix(record[0], "http") {
			channels = append(channels, strings.TrimSpace(record[0]))
		}
	}
	return channels, nil
}

func fastPingTest(configs []string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	healthy := []string{}
	sem := make(chan struct{}, 50) 

	for i, cfg := range configs {
		wg.Add(1)
		go func(idx int, c string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if checkTCP(c) {
				labeled := labelWithGeo(c, idx+1)
				mu.Lock()
				healthy = append(healthy, labeled)
				mu.Unlock()
			}
		}(i, cfg)
	}
	wg.Wait()
	return healthy
}

func checkTCP(config string) bool {
	u, err := url.Parse(config)
	if err != nil {
		return false
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443" // Default for most TLS configs
	}
	
	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func labelWithGeo(config string, index int) string {
	u, _ := url.Parse(config)
	host := u.Hostname()
	country := "🏴 Dynamic"
	
	if db != nil {
		ip := net.ParseIP(host)
		if ip == nil {
			ips, _ := net.LookupIP(host)
			if len(ips) > 0 {
				ip = ips[0]
			}
		}
		if ip != nil {
			record, _ := db.Country(ip)
			if record != nil && record.Country.Names["en"] != "" {
				country = record.Country.Names["en"]
			}
		}
	}
	u.Fragment = url.PathEscape(fmt.Sprintf("%s | Node-%d", country, index))
	return u.String()
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func saveToFile(filename string, configs []string) {
	_ = os.WriteFile(filename, []byte(strings.Join(configs, "\n")), 0644)
}

func printFinalReport(stats map[string]int, total int) {
	fmt.Println("\n" + strings.Repeat("=", 45))
	fmt.Println("📊 TELEGRAM SCRAPER SUMMARY")
	fmt.Println(strings.Repeat("-", 45))
	
	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, name := range keys {
		fmt.Printf("%-25s : %d\n", name, stats[name])
	}
	fmt.Println(strings.Repeat("-", 45))
	fmt.Printf("TOTAL RAW CONFIGS FOUND: %d\n", total)
	fmt.Println(strings.Repeat("=", 45) + "\n")
}
