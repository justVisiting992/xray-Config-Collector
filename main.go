package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/http"
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

// ChannelReport is kept for structure, though Python now handles the scouting
type ChannelReport struct {
	Name      string
	Protocols []string
	Count     int
	Message   string
}

var (
	maxLimit = 200
	db       *geoip2.Reader
)

func main() {
	// Initialize Logger
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	
	// Compatibility flags (if needed for older scripts)
	_ = flag.Bool("sort", false, "compatibility")
	_ = flag.String("p", "", "compatibility")
	flag.Parse()

	// Load GeoIP Database for labeling
	var err error
	db, err = geoip2.Open("Country.mmdb")
	if err != nil {
		gologger.Warning().Msg("Country.mmdb not found. Proceeding without GeoIP labels.")
	} else {
		defer db.Close()
	}

	// 1. Read the links collected by the Python Scout (collector.py)
	file, err := os.Open("raw_collected.txt")
	if err != nil {
		gologger.Fatal().Msg("Python output (raw_collected.txt) not found! Ensure collector.py runs first.")
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

	// Remove duplicates before processing
	allRawLinks = removeDuplicates(allRawLinks)
	gologger.Info().Msgf("🔋 Hybrid Engine: Loaded %d unique links from Python Collector", len(allRawLinks))

	// 2. Organize links by protocol
	rawConfigs := make(map[string][]string)
	protocols := []string{"vless", "vmess", "trojan", "ss", "hy2"}
	for _, p := range protocols {
		rawConfigs[p] = []string{}
	}

	for _, link := range allRawLinks {
		lower := strings.ToLower(link)
		switch {
		case strings.HasPrefix(lower, "vless://"):
			rawConfigs["vless"] = append(rawConfigs["vless"], link)
		case strings.HasPrefix(lower, "vmess://"):
			rawConfigs["vmess"] = append(rawConfigs["vmess"], link)
		case strings.HasPrefix(lower, "trojan://"):
			rawConfigs["trojan"] = append(rawConfigs["trojan"], link)
		case strings.HasPrefix(lower, "ss://"):
			rawConfigs["ss"] = append(rawConfigs["ss"], link)
		case strings.HasPrefix(lower, "hysteria2://") || strings.HasPrefix(lower, "hy2://"):
			rawConfigs["hy2"] = append(rawConfigs["hy2"], link)
		}
	}

	// 3. Fast Parallel Ping Testing
	for _, proto := range protocols {
		if len(rawConfigs[proto]) == 0 {
			continue
		}
		gologger.Info().Msgf("🧪 Testing %s configs...", strings.ToUpper(proto))
		healthy := fastPingTest(rawConfigs[proto])
		
		// Sort and limit results
		sort.Strings(healthy)
		limit := len(healthy)
		if limit > maxLimit {
			limit = maxLimit
		}
		
		saveToFile(proto+"_iran.txt", healthy[:limit])
		gologger.Info().Msgf("✅ Saved %d working %s configs", limit, proto)
	}

	// 4. Save the Mixed file for convenience
	var allMixed []string
	for _, p := range protocols {
		allMixed = append(allMixed, rawConfigs[p]...)
	}
	saveToFile("mixed_iran.txt", removeDuplicates(allMixed))

	gologger.Info().Msg("✨ All tasks complete. The Hybrid Engine has finished processing.")
}

// --- Standard Helpers ---

// fastPingTest uses a semaphore pattern to limit concurrency while testing nodes
func fastPingTest(configs []string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	healthy := []string{}
	
	// Limit to 50 concurrent connections to avoid crashing the runner
	sem := make(chan struct{}, 50) 

	for i, cfg := range configs {
		wg.Add(1)
		go func(idx int, c string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release
			
			if checkTCP(c) {
				mu.Lock()
				healthy = append(healthy, labelWithGeo(c, idx+1))
				mu.Unlock()
			}
		}(i, cfg)
	}
	wg.Wait()
	return healthy
}

// checkTCP attempts a quick handshake to see if the server is alive
func checkTCP(config string) bool {
	u, err := url.Parse(config)
	if err != nil {
		return false
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443" // Default for most modern protocols
	}
	
	// 2 second timeout is plenty for a valid config
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// labelWithGeo adds a country flag and node number to the config name (fragment)
func labelWithGeo(config string, index int) string {
	u, err := url.Parse(config)
	if err != nil {
		return config
	}
	
	country := "🏴 Dynamic"
	if db != nil {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if ip == nil {
			// Basic DNS lookup if it's a domain
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
	
	// Update the Fragment (the name part of the link)
	u.Fragment = url.PathEscape(fmt.Sprintf("%s | Node-%d", country, index))
	return u.String()
}

// removeDuplicates keeps the list clean
func removeDuplicates(slice []string) []string {
	m := make(map[string]bool)
	var list []string
	for _, v := range slice {
		if !m[v] && v != "" {
			m[v] = true
			list = append(list, v)
		}
	}
	return list
}

// saveToFile writes the slice to disk
func saveToFile(name string, data []string) {
	_ = os.WriteFile(name, []byte(strings.Join(data, "\n")), 0644)
}
