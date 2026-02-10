package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mrvcoder/V2rayCollector/collector"
	"github.com/oschwald/geoip2-golang"

	"github.com/PuerkitoBio/goquery"
	"github.com/jszwec/csvutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	client   = &http.Client{Timeout: 15 * time.Second}
	maxLimit = 200
	myregex  = map[string]string{
		"ss":     `(?m)ss:\/\/[A-Za-z0-9\.\%\-\_\:\@\/\?\&\=\+]+`,
		"vmess":  `(?m)vmess:\/\/[A-Za-z0-9\+\/\=]+`,
		"trojan": `(?m)trojan:\/\/[A-Za-z0-9\.\%\-\_\:\@\/\?\&\=\+]+`,
		"vless":  `(?m)vless:\/\/[A-Za-z0-9\.\%\-\_\:\@\/\?\&\=\+]+`,
		"hy2":    `(?m)(hy2|hysteria2):\/\/[A-Za-z0-9\.\%\-\_\:\@\/\?\&\=\+]+`,
	}
	sortFlag = flag.Bool("sort", false, "sort latest to oldest")
	db       *geoip2.Reader
)

type ChannelsType struct {
	URL             string `csv:"URL"`
	AllMessagesFlag bool   `csv:"AllMessagesFlag"`
}

// Thread-safe counter for country numbering
type CountryCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (c *CountryCounter) GetNext(country string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[country]++
	return c.counts[country]
}

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()

	// 1. Load GeoIP Database
	var err error
	db, err = geoip2.Open("Country.mmdb")
	if err != nil {
		gologger.Fatal().Msg("Could not load GeoIP database: " + err.Error())
	}
	defer db.Close()

	fileData, err := collector.ReadFileContent("channels.csv")
	var channels []ChannelsType
	if err = csvutil.Unmarshal([]byte(fileData), &channels); err != nil {
		gologger.Fatal().Msg("CSV Error: " + err.Error())
	}

	rawConfigs := make(map[string][]string)
	protocols := []string{"ss", "vmess", "trojan", "vless", "hy2"}
	for _, p := range protocols {
		rawConfigs[p] = []string{}
	}

	for _, channel := range channels {
		uParts := strings.Split(strings.TrimSuffix(channel.URL, "/"), "/")
		channelName := uParts[len(uParts)-1]
		gologger.Info().Msg("Scraping " + channelName)

		req, _ := http.NewRequest("GET", "https://t.me/s/"+channelName, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()

		doc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
			text := s.Text()
			for proto, reg := range myregex {
				re := regexp.MustCompile(reg)
				matches := re.FindAllString(text, -1)
				for _, m := range matches {
					rawConfigs[proto] = append(rawConfigs[proto], m)
				}
			}
		})
	}

	var allHealthyConfigs []string

	for _, proto := range protocols {
		list := unique(rawConfigs[proto])
		gologger.Info().Msgf("Testing %d %s configs...", len(list), proto)

		// Create a fresh counter for this protocol list
		counter := &CountryCounter{counts: make(map[string]int)}
		
		healthyOnes := fastPingTest(list, proto, 9999, counter)

		allHealthyConfigs = append(allHealthyConfigs, healthyOnes...)

		capped := healthyOnes
		if len(capped) > maxLimit {
			capped = capped[:maxLimit]
		}
		if *sortFlag {
			capped = reverse(capped)
		}
		collector.WriteToFile(strings.Join(capped, "\n"), proto+"_iran.txt")
	}

	if *sortFlag {
		allHealthyConfigs = reverse(allHealthyConfigs)
	}
	gologger.Info().Msgf("Saving %d configs to Mixed list...", len(allHealthyConfigs))
	collector.WriteToFile(strings.Join(allHealthyConfigs, "\n"), "mixed_iran.txt")
}

func fastPingTest(configs []string, proto string, limit int, counter *CountryCounter) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := []string{}
	sem := make(chan struct{}, 50)

	for _, item := range configs {
		wg.Add(1)
		go func(conf string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if isAlive(conf, proto) {
				// Pass the counter to the rename function
				renamed := renameConfigWithFlag(conf, proto, counter)
				mu.Lock()
				if len(results) < limit {
					results = append(results, renamed)
				}
				mu.Unlock()
			}
		}(item)
	}
	wg.Wait()
	return results
}

func isAlive(conf, proto string) bool {
	cleanConf := strings.Split(conf, "#")[0]
	var addr string
	if proto == "vmess" {
		data := decodeVmess(cleanConf)
		if data == nil {
			return false
		}
		addr = fmt.Sprintf("%v:%v", data["add"], data["port"])
	} else {
		re := regexp.MustCompile(`@([^:/?#\s]+):(\d+)`)
		match := re.FindStringSubmatch(cleanConf)
		if len(match) > 2 {
			addr = net.JoinHostPort(match[1], match[2])
		}
	}
	if addr == "" {
		return false
	}
	network := "tcp"
	if proto == "hy2" {
		network = "udp"
	}
	conn, err := net.DialTimeout(network, addr, 2000*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func renameConfigWithFlag(conf, proto string, counter *CountryCounter) string {
	// 1. Extract Address
	cleanConf := strings.Split(conf, "#")[0]
	var address string
	
	// VMess handling
	if proto == "vmess" {
		data := decodeVmess(conf)
		if data != nil {
			address = fmt.Sprintf("%v", data["add"])
			
			// Resolve Country
			flagEmoji, countryName := getGeoInfo(address)
			
			// Get unique number for this country
			num := counter.GetNext(countryName)
			
			// Format: 🇺🇸 US 1
			newName := fmt.Sprintf("%s %s %d", flagEmoji, countryName, num)
			
			data["ps"] = newName
			newJson, _ := json.Marshal(data)
			return "vmess://" + base64.StdEncoding.EncodeToString(newJson)
		}
		return conf
	}

	// URI Handling (VLESS, Trojan, Hy2, SS)
	re := regexp.MustCompile(`@([^:/?#\s]+):(\d+)`)
	match := re.FindStringSubmatch(cleanConf)
	if len(match) > 2 {
		address = match[1]
	} else {
		// Fallback for SS simple format
		reSS := regexp.MustCompile(`ss://[^@]+@([^:/?#\s]+):(\d+)`)
		mSS := reSS.FindStringSubmatch(cleanConf)
		if len(mSS) > 2 {
			address = mSS[1]
		}
	}

	if address != "" {
		flagEmoji, countryName := getGeoInfo(address)
		
		// Get unique number for this country
		num := counter.GetNext(countryName)
		
		// Format: 🇺🇸 US 1
		newName := fmt.Sprintf("%s %s %d", flagEmoji, countryName, num)
		
		// Reassemble URI with new name fragment
		return fmt.Sprintf("%s#%s", cleanConf, newName)
	}

	return conf
}

func getGeoInfo(host string) (string, string) {
	// Robust Retry Loop for DNS
	var ip net.IP
	var err error
	
	// Try to look up IP up to 3 times
	for i := 0; i < 3; i++ {
		// If it's already an IP, parse it
		ip = net.ParseIP(host)
		if ip != nil {
			break
		}
		
		// If it's a domain, resolve it
		ips, lookupErr := net.LookupIP(host)
		if lookupErr == nil && len(ips) > 0 {
			ip = ips[0]
			break
		}
		// Wait a bit before retry
		time.Sleep(500 * time.Millisecond)
	}

	// If failed after retries, return Dynamic
	if ip == nil {
		return "🏴", "Dynamic"
	}

	record, err := db.Country(ip)
	if err != nil {
		return "🏴", "Dynamic"
	}

	countryName := record.Country.Names["en"]
	if countryName == "" {
		return "🏴", "Dynamic"
	}
	
	cleanName := cleanCountryName(countryName)
	isoCode := record.Country.IsoCode
	return getFlagEmoji(isoCode), cleanName
}

func cleanCountryName(name string) string {
	// Remove "The " prefix
	name = strings.TrimPrefix(name, "The ")
	
	// Acronym mappings
	switch name {
	case "United Arab Emirates":
		return "UAE"
	case "United States":
		return "US"
	case "United Kingdom":
		return "UK"
	case "Islamic Republic of Iran":
		return "Iran"
	case "Russian Federation":
		return "Russia"
	}
	return name
}

func getFlagEmoji(countryCode string) string {
	if len(countryCode) != 2 {
		return "🏴"
	}
	countryCode = strings.ToUpper(countryCode)
	// Cast to rune to prevent overflow
	return string(rune(countryCode[0]) - 'A' + 0x1F1E6) + string(rune(countryCode[1]) - 'A' + 0x1F1E6)
}

func decodeVmess(conf string) map[string]interface{} {
	b64 := strings.TrimPrefix(conf, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil
	}
	var data map[string]interface{}
	json.Unmarshal(decoded, &data)
	return data
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func reverse(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}
