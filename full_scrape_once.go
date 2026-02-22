// full_scrape_once.go
// ONE-TIME FULL HISTORICAL SCRAPE to populate bypass methods in report.md table
// Run once: go run full_scrape_once.go
// Then delete this file forever.
// Does NOT save configs to txt — only updates Gist + report.md

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	client   = &http.Client{Timeout: 15 * time.Second}
	gistID    = os.Getenv("GIST_ID")
	gistToken = os.Getenv("GIST_TOKEN")

	checkpoints   = make(map[string]int)
	checkpointsMu sync.Mutex

	channelProtocols   = make(map[string]map[string]bool) // channel -> set of bypass methods
	channelProtocolsMu sync.Mutex

	myregex = map[string]string{
		"SS":     `(?i)ss://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"VMess":  `(?i)vmess://[A-Za-z0-9+/=]+`,
		"Trojan": `(?i)trojan://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"VLess":  `(?i)vless://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"Hy2":    `(?i)(?:hysteria2|hy2)://[A-Za-z0-9./:=?#-_@!%&+=]+`,
	}

	// Keywords for extra bypass tools (case-insensitive)
	extraTools = map[string]string{
		"npv":          "NPV/NPVT",
		"npvt":         "NPV/NPVT",
		"napsternet":   "NPV/NPVT",
		"mtproto":      "MTProto",
		"proxy.mtproto": "MTProto",
		"wireguard":    "WireGuard",
		"wg":           "WireGuard",
		"hiddify":      "Hiddify/HA",
		"ha":           "Hiddify/HA",
		"clash":        "Clash",
		"sing-box":     "Sing-box",
		"sing":         "Sing-box",
		"shadowrocket": "Shadowrocket",
		"nekobox":      "Nekobox/NekoRay",
		"openvpn":      "OpenVPN",
		"psiphon":      "Psiphon",
		// Add more keywords here if needed
	}
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	fmt.Println("=== ONE-TIME FULL SCRAPE for bypass methods ===")
	fmt.Println("This will scrape 20 pages per channel, detect all tools, update Gist & report.md")
	fmt.Println("After this run, DELETE this file — main.go will handle future updates")

	if gistID == "" || gistToken == "" {
		fmt.Println("ERROR: GIST_ID and GIST_TOKEN env vars required")
		os.Exit(1)
	}

	loadCheckpoints()
	loadChannelProtocols()

	rawChannels, err := loadChannelsFromCSV("channels.csv")
	if err != nil {
		fmt.Printf("ERROR loading channels.csv: %v\n", err)
		os.Exit(1)
	}
	channels := removeDuplicates(rawChannels)
	fmt.Printf("Loaded %d channels\n", len(channels))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, urlStr := range channels {
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()

			uParts := strings.Split(strings.TrimSuffix(url, "/"), "/")
			name := uParts[len(uParts)-1]
			fmt.Printf("Scraping full history: %s\n", name)

			_, _ = fullScrapeChannel(name) // ignore extracted configs, we only care about methods
		}(urlStr)
	}
	wg.Wait()

	saveChannelProtocols()
	fmt.Println("Gist updated with all detected bypass methods")

	// Generate report.md with enriched table
	// (Dummy reports just to reuse generateReportStructure — we only need the table)
	var reports []ChannelReport
	channelProtocolsMu.Lock()
	for ch := range channelProtocols {
		protos := getChannelProtocols(ch)
		sort.Strings(protos)
		reports = append(reports, ChannelReport{
			Name:      ch,
			Protocols: protos,
			Count:     0, // dummy
			Message:   "—", // dummy
		})
	}
	channelProtocolsMu.Unlock()

	// Dummy stats (not used)
	dummyStats := make(map[string][2]int)
	content := generateReportStructure(reports, dummyStats)
	_ = os.WriteFile("report.md", []byte(content), 0644)

	fmt.Println("Done! report.md updated with full bypass methods table.")
	fmt.Println("You can now DELETE full_scrape_once.go")
	fmt.Println("Future runs of main.go will keep the table cumulative.")
}

// Full historical scrape — ignores checkpoint, scrapes 20 pages, collects methods
func fullScrapeChannel(channelName string) (int, int) {
	baseURL := "https://t.me/s/" + channelName
	nextURL := baseURL
	totalExtracted := 0
	pagesScraped := 0
	const maxPages = 20

	for pagesScraped < maxPages {
		req, _ := http.NewRequest("GET", nextURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			break
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()
		if err != nil {
			break
		}

		foundAny := false

		doc.Find(".tgme_widget_message").Each(func(i int, s *goquery.Selection) {
			text := s.Find(".tgme_widget_message_text").Text()
			if text == "" {
				return
			}

			foundAny = true

			// Extract your 5 core protocols (for completeness)
			for pName, reg := range myregex {
				if regexp.MustCompile(reg).MatchString(text) {
					updateChannelProtocols(channelName, []string{pName})
					totalExtracted++
				}
			}

			// Scan for extra bypass tools
			lowerText := strings.ToLower(text)
			for kw, toolName := range extraTools {
				if strings.Contains(lowerText, kw) {
					updateChannelProtocols(channelName, []string{toolName})
				}
			}
		})

		// Try to go older
		var minIDOnPage int = 999999999
		doc.Find(".tgme_widget_message").Each(func(i int, s *goquery.Selection) {
			dataPost, exists := s.Attr("data-post")
			if !exists {
				return
			}
			parts := strings.Split(dataPost, "/")
			if len(parts) < 2 {
				return
			}
			msgID, err := strconv.Atoi(parts[len(parts)-1])
			if err == nil && msgID < minIDOnPage {
				minIDOnPage = msgID
			}
		})

		if foundAny && minIDOnPage < 999999999 {
			nextURL = fmt.Sprintf("%s?before=%d", baseURL, minIDOnPage)
			pagesScraped++
			time.Sleep(2 * time.Second)
			fmt.Printf("  %s: scraped page %d\n", channelName, pagesScraped)
		} else {
			break
		}
	}

	fmt.Printf("%s: scraped %d pages, found methods: %v\n",
		channelName, pagesScraped, getChannelProtocols(channelName))

	return totalExtracted, pagesScraped
}

// Reuse your cumulative functions (copy-pasted minimal version)
func updateChannelProtocols(channel string, newProtos []string) {
	channelProtocolsMu.Lock()
	if _, ok := channelProtocols[channel]; !ok {
		channelProtocols[channel] = make(map[string]bool)
	}
	for _, p := range newProtos {
		channelProtocols[channel][p] = true
	}
	channelProtocolsMu.Unlock()
}

func getChannelProtocols(channel string) []string {
	channelProtocolsMu.Lock()
	protos := channelProtocols[channel]
	channelProtocolsMu.Unlock()

	var list []string
	for p := range protos {
		list = append(list, p)
	}
	sort.Strings(list)
	return list
}

func loadChannelProtocols() {
	if gistID == "" || gistToken == "" {
		return
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/gists/"+gistID, nil)
	req.Header.Set("Authorization", "token "+gistToken)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var gistResp GistResponse
	if err := json.NewDecoder(resp.Body).Decode(&gistResp); err == nil {
		if file, ok := gistResp.Files["channel_protocols.json"]; ok {
			var saved map[string][]string
			_ = json.Unmarshal([]byte(file.Content), &saved)
			channelProtocolsMu.Lock()
			for ch, ps := range saved {
				if _, ok := channelProtocols[ch]; !ok {
					channelProtocols[ch] = make(map[string]bool)
				}
				for _, p := range ps {
					channelProtocols[ch][p] = true
				}
			}
			channelProtocolsMu.Unlock()
		}
	}
}

func saveChannelProtocols() {
	if gistID == "" || gistToken == "" {
		return
	}
	channelProtocolsMu.Lock()
	saved := make(map[string][]string)
	for ch, protos := range channelProtocols {
		var list []string
		for p := range protos {
			list = append(list, p)
		}
		sort.Strings(list)
		saved[ch] = list
	}
	channelProtocolsMu.Unlock()

	data, _ := json.Marshal(saved)

	payload := GistRequest{
		Files: map[string]GistFile{
			"channel_protocols.json": {Content: string(data)},
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("PATCH", "https://api.github.com/gists/"+gistID, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "token "+gistToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// Minimal loadChannelsFromCSV + removeDuplicates (copied from your main.go)
func loadChannelsFromCSV(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	var u []string
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		if len(row) > 0 {
			cleaned := strings.TrimSpace(row[0])
			if cleaned == "" || strings.Contains(strings.ToUpper(cleaned), "URL") {
				continue
			}
			if !strings.HasPrefix(cleaned, "http") {
				cleaned = "https://t.me/" + cleaned
			}
			u = append(u, strings.TrimSuffix(cleaned, "/"))
		}
	}
	return u, nil
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	var list []string
	for _, v := range slice {
		if !seen[v] {
			seen[v] = true
			list = append(list, v)
		}
	}
	return list
}

// Reuse your generateReportStructure (minimal copy — only table part matters)
func generateReportStructure(reports []ChannelReport, _ map[string][2]int) string {
	var sb strings.Builder
	sb.WriteString("# 📊 Status Report\n\n")
	sb.WriteString("### 📡 Source Analysis\n\n")
	sb.WriteString("| Source Channel | Available Protocols | Harvest Status |\n")
	sb.WriteString("| :--- | :--- | :--- |\n")

	for _, r := range reports {
		protos := strings.Join(r.Protocols, ", ")
		if protos == "" {
			protos = "—"
		}
		linkName := r.Name
		linkURL := "https://t.me/s/" + r.Name
		if r.Name == "persianvpnhub" {
			linkName = "persianvpnhub"
			linkURL = "https://t.me/s/persianvpnhub"
		}
		sb.WriteString(fmt.Sprintf("| 📢 [%s](%s) | `%s` | %s |\n", linkName, linkURL, protos, r.Message))
	}
	sb.WriteString("\n---\n")
	sb.WriteString("*One-time full scrape for bypass methods — main.go will keep it updated*")
	return sb.String()
}