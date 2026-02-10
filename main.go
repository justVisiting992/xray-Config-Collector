package main

import (
	"bufio"
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
		gologger.Warning().Msg("GeoIP database not found. Labels will be generic.")
	} else {
		defer db.Close()
	}

	// 2. Load Channels manually (No external CSV lib needed)
	channels, err := loadChannels("channels.csv")
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
	gologger.Info().Msg("Starting Scraper Engine...")
	for _, channelURL := range channels {
		uParts := strings.Split(strings.TrimSuffix(channelURL, "/"), "/")
		channelName := uParts[len(uParts)-1]
		
		req, _ := http.NewRequest("GET", "https://t.me/s/"+channelName, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err := client.Do(req)
		
		if err != nil || resp.StatusCode != 200 {
			gologger.Error().Msgf("Failed: %s", channelName)
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
		gologger.Info().Msgf("Collected %d from [%s]", countForThisChannel, channelName)
		time.Sleep(1200 * time.Millisecond)
	}

	// 4. Print Summary
	printSummary(channelStats, totalFound)

	// 5. Test & Save
	var allHealthyConfigs []string
	for proto, configs := range rawConfigs {
		uniqueConfigs := removeDuplicates(configs)
		healthy := fastPingTest(uniqueConfigs)
		allHealthyConfigs = append(allHealthyConfigs, healthy...)

		limit := len(healthy)
		if limit > maxLimit {
			limit = maxLimit
		}
		saveToFile(proto+"_iran.txt", healthy[:limit])
	}
	saveToFile("mixed_iran.txt", allHealthyConfigs)
	gologger.Info().Msg("Success! Files updated.")
}

// --- Logic Helpers ---

func loadChannels(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var channels []string
	reader := csv.NewReader(f)
	// Skip header if necessary, but here we assume first col is URL
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(record) > 0 && strings.HasPrefix(record[0], "http") {
			channels = append(channels, record[0])
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

			// Simple TCP Check
			if isHealthy(c) {
				labeled := labelConfig(c, idx+1)
				mu.Lock()
				healthy = append(healthy, labeled)
				mu.Unlock()
			}
		}(i, cfg)
	}
	wg.Wait()
	return healthy
}

func isHealthy(config string) bool {
	u, err := url.Parse(config)
	if err != nil {
		return false
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func labelConfig(config string, index int) string {
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

func removeDuplicates(s []string) []string {
	m := make(map[string]bool)
	var res []string
	for _, v := range s {
		if !m[v] {
			m[v] = true
			res = append(res, v)
		}
	}
	return res
}

func saveToFile(name string, data []string) {
	os.WriteFile(name, []byte(strings.Join(data, "\n")), 0644)
}

func printSummary(stats map[string]int, total int) {
	fmt.Println("\n" + strings.Repeat("=", 45))
	fmt.Println("📊 TELEGRAM SCRAPER SUMMARY")
	fmt.Println(strings.Repeat("-", 45))
	for name, count := range stats {
		fmt.Printf("%-25s : %d\n", name, count)
	}
	fmt.Printf("TOTAL FOUND: %d\n", total)
	fmt.Println(strings.Repeat("=", 45) + "\n")
}
