package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

type ChannelReport struct {
	Name      string
	Protocols []string
	Count     int
}

var (
	maxLimit = 200
	db       *geoip2.Reader
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	_ = flag.Bool("sort", false, "compatibility")
	_ = flag.String("p", "", "compatibility")
	flag.Parse()

	db, _ = geoip2.Open("Country.mmdb")

	// 1. Read links from Python Scout
	file, err := os.Open("raw_collected.txt")
	if err != nil {
		gologger.Fatal().Msg("raw_collected.txt not found. Run collector.py first.")
	}
	defer file.Close()

	var allRawLinks []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			allRawLinks = append(allRawLinks, line)
		}
	}
	allRawLinks = removeDuplicates(allRawLinks)

	// 2. Categorize and Test
	rawConfigs := make(map[string][]string)
	protos := []string{"vless", "vmess", "trojan", "ss", "hy2"}
	for _, p := range protos {
		rawConfigs[p] = []string{}
	}

	for _, link := range allRawLinks {
		l := strings.ToLower(link)
		if strings.HasPrefix(l, "vless") { rawConfigs["vless"] = append(rawConfigs["vless"], link) }
		if strings.HasPrefix(l, "vmess") { rawConfigs["vmess"] = append(rawConfigs["vmess"], link) }
		if strings.HasPrefix(l, "trojan") { rawConfigs["trojan"] = append(rawConfigs["trojan"], link) }
		if strings.HasPrefix(l, "ss") { rawConfigs["ss"] = append(rawConfigs["ss"], link) }
		if strings.HasPrefix(l, "hysteria2") || strings.HasPrefix(l, "hy2") { rawConfigs["hy2"] = append(rawConfigs["hy2"], link) }
	}

	for _, p := range protos {
		if len(rawConfigs[p]) > 0 {
			healthy := fastPingTest(rawConfigs[p])
			limit := len(healthy)
			if limit > maxLimit { limit = maxLimit }
			saveToFile(p+"_iran.txt", healthy[:limit])
		}
	}

	// 3. Final Report Generation (Tribute Style)
	generateTributeReport(len(allRawLinks))
	
	gologger.Info().Msg("✨ Hybrid Processing Complete.")
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

func generateTributeReport(total int) {
	now := time.Now().Format("2006-01-02 15:04:05")
	var sb strings.Builder
	sb.WriteString("# 💠 Xray Source Tribute & Report\n\n")
	sb.WriteString("A tribute to the admins providing free configs. Updated every 2 hours.\n\n")
	sb.WriteString(fmt.Sprintf("- **Last Update:** `%s` UTC\n", now))
	sb.WriteString(fmt.Sprintf("- **Total Configs Processed:** `%d`\n\n", total))
	sb.WriteString("| Source Channel | Protocols Found | Status |\n")
	sb.WriteString("| :--- | :--- | :--- |\n")
	sb.WriteString("| *Consolidated Hybrid Data* | Vless, Vmess, Trojan, SS, Hy2 | ✅ Active |\n")
	
	_ = os.WriteFile("report.md", []byte(sb.String()), 0644)
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
