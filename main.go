package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/justVisiting992/xray-Config-Collector/internal/sharelink"
	"github.com/oschwald/geoip2-golang"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"gopkg.in/yaml.v3"
)

type VMessConfig struct {
	Add  string      `json:"add"`
	Port interface{} `json:"port"`
	Id   interface{} `json:"id"`
	Aid  interface{} `json:"aid"`
	Net  string      `json:"net"`
	TLS  string      `json:"tls"`
	Host string      `json:"host"`
	Path string      `json:"path"`
	SNI  string      `json:"sni"`
}

type ChannelReport struct {
	Name    string
	Count   int
	Message string
}

type GistRequest struct {
	Files map[string]GistFile `json:"files"`
}
type GistResponse struct {
	Files map[string]GistFile `json:"files"`
}
type GistFile struct {
	Content string `json:"content"`
}

var (
	client   = &http.Client{Timeout: 15 * time.Second}
	maxLimit = 200
	db       *geoip2.Reader

	gistID    = os.Getenv("GIST_ID")
	gistToken = os.Getenv("GIST_TOKEN")

	checkpoints   = make(map[string]int)
	checkpointsMu sync.Mutex

	geoCache   = make(map[string]string)
	geoCacheMu sync.Mutex

	myregex = map[string]string{
		"SS":     `(?i)ss://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"VMess":  `(?i)vmess://[A-Za-z0-9+/=_-]+`,
		"Trojan": `(?i)trojan://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"VLess":  `(?i)vless://[A-Za-z0-9./:=?#-_@!%&+=]+`,
		"Hy2":    `(?i)(?:hysteria2|hy2)://[A-Za-z0-9./:=?#-_@!%&+=]+`,
	}
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()
	printBanner()

	var err error
	db, err = geoip2.Open("Country.mmdb")
	if err != nil {
		gologger.Warning().Msg("⚠️ GeoIP database missing! Flags will be 🏴")
	} else {
		gologger.Info().Msg("🌍 GeoIP Database Loaded.")
		defer db.Close()
	}

	loadCheckpoints()
	mergePythonCheckpoint()

	rawChannels, _ := loadChannelsFromCSV("channels.csv")
	channels := removeDuplicates(rawChannels)
	gologger.Info().Msgf("📺 Loaded %d Source Channels", len(channels))

	newConfigs := make(map[string][]string)
	historyConfigs := make(map[string][]string)

	totalHistory := 0
	for p := range myregex {
		newConfigs[p] = []string{}
		historyConfigs[p] = []string{}
		fName := strings.ToLower(p) + "_iran.txt"
		content, err := os.ReadFile(fName)
		if err == nil {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				clean := strings.Split(line, "#")[0]
				clean = strings.Split(clean, "|")[0]
				historyConfigs[p] = append(historyConfigs[p], strings.TrimSpace(clean))
			}
			totalHistory += len(historyConfigs[p])
		}
	}
	gologger.Info().Msgf("📜 Loaded %d Historic Configs", totalHistory)

	var reports []ChannelReport
	totalScraped := 0

	gologger.Info().Msg("🐍 Processing Python Collector Dump...")
	pythonDump, err := os.ReadFile("telegram_dump.txt")
	if err == nil && len(pythonDump) > 0 {
		extracted, count := extractConfigsFromText(string(pythonDump))
		for pName, matches := range extracted {
			newConfigs[pName] = append(newConfigs[pName], matches...)
		}
		channelName := "persianvpnhub"
		reports = append(reports, ChannelReport{
			Name:    channelName,
			Count:   count,
			Message: fmt.Sprintf("✅ %d Configs via API", count),
		})
		totalScraped += count
		gologger.Info().Msgf("✨ Extracted %d configs from Python Dump", count)
	} else {
		gologger.Warning().Msg("⚠️ No Python dump found or empty.")
	}

	gologger.Info().Msg("🕸️ Starting Stateful Web Scraper...")
	var wgScrape sync.WaitGroup
	semaphore := make(chan struct{}, 5)

	for _, channelURL := range channels {
		wgScrape.Add(1)
		semaphore <- struct{}{}
		go func(urlStr string) {
			defer wgScrape.Done()
			defer func() { <-semaphore }()

			uParts := strings.Split(strings.TrimSuffix(urlStr, "/"), "/")
			name := uParts[len(uParts)-1]

			extracted, _ := scrapeChannelStateful(name)

			checkpointsMu.Lock()
			report := ChannelReport{Name: name}
			for p, cfgs := range extracted {
				if len(cfgs) > 0 {
					newConfigs[p] = append(newConfigs[p], cfgs...)
					report.Count += len(cfgs)
				}
			}
			if report.Count > 0 {
				report.Message = fmt.Sprintf("✅ %d found", report.Count)
				totalScraped += report.Count
			} else {
				report.Message = "💤 No new configs"
			}
			reports = append(reports, report)
			checkpointsMu.Unlock()

			if report.Count > 0 {
				gologger.Debug().Msgf("   + %s: Found %d", name, report.Count)
			}
		}(channelURL)
	}
	wgScrape.Wait()

	gologger.Info().Msg("🔗 Processing Subscription Sources...")
	subURLs := loadSubscriptions("subscriptions.txt")
	gologger.Info().Msgf("📋 Loaded %d Subscription Sources", len(subURLs))
	// Fetch sources concurrently (10 at a time): fetching 200+
	// sources one by one lets every slow or dead host add its full
	// timeout to the run in series. Results land in per-source slots
	// and are merged below in file order, so reports and totals are
	// identical to the sequential version.
	type subResult struct {
		extracted map[string][]string
		count     int
		err       error
	}
	subResults := make([]subResult, len(subURLs))
	var wgSubs sync.WaitGroup
	semSubs := make(chan struct{}, 10)
	for i, subURL := range subURLs {
		wgSubs.Add(1)
		semSubs <- struct{}{}
		go func(i int, u string) {
			defer wgSubs.Done()
			defer func() { <-semSubs }()
			extracted, count, ferr := fetchSubscription(u)
			subResults[i] = subResult{extracted: extracted, count: count, err: ferr}
		}(i, subURL)
	}
	wgSubs.Wait()
	for i, subURL := range subURLs {
		extracted, count, ferr := subResults[i].extracted, subResults[i].count, subResults[i].err
		report := ChannelReport{Name: subURL}
		if ferr != nil {
			// A failed source is reported, never skipped silently.
			report.Message = "❌ Fetch failed"
			gologger.Warning().Msgf("⚠️ Subscription failed: %s (%v)", subURL, ferr)
		} else {
			for p, cfgs := range extracted {
				if len(cfgs) > 0 {
					newConfigs[p] = append(newConfigs[p], cfgs...)
				}
			}
			report.Count = count
			totalScraped += count
			if count > 0 {
				report.Message = fmt.Sprintf("✅ %d found", count)
			} else {
				report.Message = "💤 No configs"
			}
			gologger.Info().Msgf("✨ Extracted %d configs from subscription: %s", count, subURL)
		}
		reports = append(reports, report)
	}

	gologger.Info().Msgf("📦 Total Raw Configs Harvested: %d", totalScraped)

	var allMixed []string
	protoStats := make(map[string][2]int)

	for p := range myregex {
		gologger.Info().Msgf("🛡️ Processing Protocol: %s", p)
		combined := append(newConfigs[p], historyConfigs[p]...)
		unique := removeDuplicates(combined)

		// --- FIX: Keep only genuine Shadowsocks URIs (base64-encoded method:password) ---
		if p == "SS" {
			var validSS []string
			for _, cfg := range unique {
				if isValidShadowsocks(cfg) {
					validSS = append(validSS, cfg)
				}
			}
			gologger.Info().Msgf("   ↳ Filtered to %d valid SS configs", len(validSS))
			unique = validSS
		}
		// --- END FIX ---

		gologger.Info().Msgf("   ↳ Testing %d unique configs...", len(unique))
		healthy := fastPingTest(unique, p)
		gologger.Info().Msgf("   ✅ Alive: %d", len(healthy))

		protoStats[p] = [2]int{len(unique), len(healthy)}

		limit := len(healthy)
		if limit > maxLimit {
			limit = maxLimit
		}

		finalList := healthy[:limit]
		saveToFile(strings.ToLower(p)+"_iran.txt", finalList)
		allMixed = append(allMixed, healthy...)
	}

	sort.Slice(reports, func(i, j int) bool { return reports[i].Count > reports[j].Count })
	_ = os.WriteFile("report.md", []byte(generateReportStructure(reports, protoStats)), 0644)

	gologger.Info().Msg("🍹 Saving Mixed Configs...")
	saveToFile("mixed_iran.txt", removeDuplicates(allMixed))

	// Checkpoints are persisted only now — after every output file has
	// been written — so a crash anywhere above leaves the Gist state at
	// the previous run's values and the same messages are re-fetched
	// next run instead of being skipped forever.
	saveCheckpoints()

	gologger.Info().Msg("🎉 All Done! Mission Accomplished.")
}

// Fixed trait extraction - SS now handles extended format with query params
func getTraitTag(config string) string {
	lower := strings.ToLower(config)
	var traits []string

	if strings.HasPrefix(lower, "vmess://") {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		if rem := len(b64) % 4; rem != 0 {
			b64 += strings.Repeat("=", 4-rem)
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			decoded, _ = base64.URLEncoding.DecodeString(b64)
		}
		var v map[string]interface{}
		if json.Unmarshal(decoded, &v) == nil {
			net, _ := v["net"].(string)
			net = strings.ToLower(net)
			sec, _ := v["security"].(string)
			sec = strings.ToLower(sec)
			fp := ""
			if tlsSettings, ok := v["tlsSettings"].(map[string]interface{}); ok {
				if f, ok := tlsSettings["fingerprint"].(string); ok {
					fp = strings.ToLower(f)
				}
			}

			if net != "" && net != "tcp" {
				if net == "httpupgrade" {
					traits = append(traits, "HTTPup")
				} else if net == "grpc" {
					traits = append(traits, "gRPC")
				} else {
					traits = append(traits, strings.ToUpper(net))
				}
			}

			if sec == "tls" {
				traits = append(traits, "TLS")
			} else if sec != "" && sec != "none" && sec != "auto" {
				traits = append(traits, strings.ToUpper(sec))
			}

			if fp != "" {
				traits = append(traits, fp)
			}
		}
	} else if strings.HasPrefix(lower, "vless://") {
		u, err := url.Parse(config)
		if err == nil {
			q := u.Query()
			sec := strings.ToLower(q.Get("security"))
			net := strings.ToLower(q.Get("type"))
			flow := strings.ToLower(q.Get("flow"))

			if sec == "tls" {
				traits = append(traits, "TLS")
			} else if sec == "reality" {
				traits = append(traits, "Reality")
			} else if sec != "" && sec != "none" {
				traits = append(traits, strings.ToUpper(sec))
			}

			if net != "" && net != "tcp" {
				if net == "httpupgrade" {
					traits = append(traits, "HTTPup")
				} else if net == "grpc" {
					traits = append(traits, "gRPC")
				} else {
					traits = append(traits, strings.ToUpper(net))
				}
			}

			if flow == "xtls-rprx-vision" {
				traits = append(traits, "Vision")
			}
		}
	} else if strings.HasPrefix(lower, "trojan://") {
		u, err := url.Parse(config)
		if err == nil {
			q := u.Query()
			fp := strings.ToLower(q.Get("fp"))

			traits = append(traits, "TLS")

			if fp != "" {
				traits = append(traits, fp)
			}
		}
	} else if strings.HasPrefix(lower, "ss://") {
		ssPart := strings.TrimPrefix(lower, "ss://")

		// Modern extended format with query params (your cases)
		if strings.Contains(ssPart, "?") {
			// Parse as URL (add dummy scheme if needed)
			if !strings.Contains(ssPart, "://") {
				ssPart = "ss://" + ssPart
			}
			u, err := url.Parse(ssPart)
			if err == nil {
				q := u.Query()
				typ := strings.ToLower(q.Get("type"))
				sec := strings.ToLower(q.Get("security"))
				fp := strings.ToLower(q.Get("fp"))

				// Transport type
				if typ != "" {
					typUpper := strings.ToUpper(typ)
					switch typ {
					case "httpupgrade":
						traits = append(traits, "HTTPup")
					case "xhttp":
						traits = append(traits, "XHTTP")
					case "grpc":
						traits = append(traits, "gRPC")
					default:
						traits = append(traits, typUpper)
					}
				}

				// Security
				if sec == "tls" {
					traits = append(traits, "TLS")
				} else if sec == "none" || sec != "" {
					traits = append(traits, "NONE")
				}

				// Fingerprint
				if fp != "" {
					traits = append(traits, fp)
				}
			}
		} else {
			// Classic base64-encoded SS (method:pass@host:port)
			padded := ssPart + strings.Repeat("=", (4-len(ssPart)%4)%4)
			decoded, err := base64.URLEncoding.DecodeString(padded)
			if err != nil {
				decoded, _ = base64.StdEncoding.DecodeString(padded)
			}
			if err == nil && len(decoded) > 0 {
				decStr := string(decoded)
				atSplit := strings.SplitN(decStr, "@", 2)
				if len(atSplit) == 2 {
					auth := atSplit[0]
					colonSplit := strings.SplitN(auth, ":", 2)
					if len(colonSplit) == 2 {
						method := strings.ToLower(colonSplit[0])
						short := getShortMethod(method)
						if short != "" {
							traits = append(traits, short)
						}
					}
				}
			}
		}
	} else if strings.HasPrefix(lower, "hy2://") || strings.HasPrefix(lower, "hysteria2://") {
		u, err := url.Parse(config)
		if err == nil {
			q := u.Query()
			obfs := strings.ToLower(q.Get("obfs"))
			brutalStr := q.Get("brutal")
			brutal := brutalStr != "" && brutalStr != "0" && brutalStr != "false"

			traits = append(traits, "TLS")

			if obfs == "salamander" {
				traits = append(traits, "Salamander")
			}

			if brutal {
				traits = append(traits, "Brutal")
			}
		}
	}

	if len(traits) == 0 {
		return "Basic"
	}

	tag := strings.Join(traits, " • ")
	return strings.Trim(tag, " •")
}

func getShortMethod(method string) string {
	m := strings.ToLower(method)
	switch {
	case strings.Contains(m, "aes-128"):
		return "AES128"
	case strings.Contains(m, "aes-256"):
		return "AES256"
	case strings.Contains(m, "chacha"):
		return "ChaCha"
	case strings.Contains(m, "2022"):
		return "2022"
	default:
		return ""
	}
}

// extractConfigsFromText runs every protocol regex over text and
// returns the matches grouped by protocol plus the total count. It is
// the single extraction path for channel pages, the Python dump and
// subscription bodies, so all sources are parsed identically.
func extractConfigsFromText(text string) (map[string][]string, int) {
	results := make(map[string][]string)
	total := 0
	for pName, reg := range myregex {
		matches := regexp.MustCompile(reg).FindAllString(text, -1)
		if len(matches) > 0 {
			results[pName] = append(results[pName], matches...)
			total += len(matches)
		}
	}
	return results, total
}

// loadSubscriptions reads subscription URLs from a plain-text file:
// one URL per line, blank lines and lines starting with # ignored.
// URLs are deduplicated by exact string match — deliberately NOT via
// removeDuplicates, whose config fingerprinting can map two different
// URLs to the same fingerprint and silently drop one. A missing file
// simply yields no sources.
func loadSubscriptions(path string) []string {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var urls []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		seen[line] = true
		urls = append(urls, line)
	}
	return urls
}

// decodeSubscriptionBody returns the text to extract configs from. Most
// subscription links serve the URI list base64-encoded; if the body is
// not already a URI list, a base64 decode is attempted (standard and
// URL-safe alphabets, padded or not) and used when it yields one.
// Bodies in the structured Clash YAML / sing-box JSON formats are
// first converted to share URIs (structuredSubscriptionURIs, below)
// — before the "://" shortcut, because a full Clash config contains
// "://" in its DNS section while holding no extractable URIs at all.
func decodeSubscriptionBody(body []byte) string {
	if uris := structuredSubscriptionURIs(body); len(uris) > 0 {
		return strings.Join(uris, "\n")
	}
	text := strings.TrimSpace(string(body))
	if strings.Contains(text, "://") {
		return text
	}
	compact := strings.Join(strings.Fields(text), "")
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(compact)
		if err == nil && strings.Contains(string(decoded), "://") {
			return string(decoded)
		}
	}
	return text
}

// fetchSubscription downloads one subscription URL and extracts its
// configs exactly like any other source. The body is capped at 10 MiB
// so a hostile or broken endpoint cannot exhaust memory.
func fetchSubscription(rawURL string) (map[string][]string, int, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, 0, err
	}
	extracted, count := extractConfigsFromText(decodeSubscriptionBody(body))
	return extracted, count, nil
}

func scrapeChannelStateful(channelName string) (map[string][]string, int) {
	results := make(map[string][]string)
	checkpointsMu.Lock()
	lastSeenID := checkpoints[channelName]
	checkpointsMu.Unlock()

	baseURL := "https://t.me/s/" + channelName
	nextURL := baseURL
	maxIDFound := lastSeenID
	totalExtracted := 0
	pagesScraped := 0
	// caughtUp records whether paging actually reached the previously
	// seen messages. The checkpoint may only advance when it did:
	// stopping early (page cap or a failed request) leaves a window of
	// unfetched messages between lastSeenID and the oldest fetched
	// page, and advancing past them would skip them forever.
	caughtUp := false

	for pagesScraped < 5 {
		req, _ := http.NewRequest("GET", nextURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			break
		}

		doc, _ := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()

		minIDOnPage := 999999999
		foundAny := false

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
			if err != nil {
				return
			}

			if msgID > maxIDFound {
				maxIDFound = msgID
			}
			if msgID < minIDOnPage {
				minIDOnPage = msgID
			}

			if msgID > lastSeenID {
				foundAny = true
				text := s.Find(".tgme_widget_message_text").Text()
				for pName, reg := range myregex {
					matches := regexp.MustCompile(reg).FindAllString(text, -1)
					if len(matches) > 0 {
						results[pName] = append(results[pName], matches...)
						totalExtracted += len(matches)
					}
				}
			}
		})

		if foundAny && minIDOnPage > lastSeenID {
			nextURL = fmt.Sprintf("%s?before=%d", baseURL, minIDOnPage)
			pagesScraped++
			time.Sleep(2 * time.Second)
		} else {
			// This page reached messages at or below lastSeenID (or
			// held nothing new): everything up to maxIDFound has now
			// been seen, so advancing the checkpoint is safe.
			caughtUp = true
			break
		}
	}

	if caughtUp && maxIDFound > lastSeenID {
		checkpointsMu.Lock()
		checkpoints[channelName] = maxIDFound
		checkpointsMu.Unlock()
	}

	return results, totalExtracted
}

func loadCheckpoints() {
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
		if file, ok := gistResp.Files["checkpoints.json"]; ok {
			_ = json.Unmarshal([]byte(file.Content), &checkpoints)
			gologger.Info().Msg("🧠 State loaded from Gist.")
		}
	}
}

// mergePythonCheckpoint folds the persianvpnhub checkpoint handed over
// by collector.py (telegram_checkpoint.txt) into the in-memory
// checkpoints. The Python collector no longer advances the Gist
// checkpoint itself: it only records the highest message ID it dumped,
// and the value is persisted by saveCheckpoints() at the end of this
// run — after every output file has been written — so a failed run
// re-fetches the same messages next time instead of losing them.
// Only a strictly greater value is merged, so a stale sidecar file can
// never move the checkpoint backwards or forwards on its own.
func mergePythonCheckpoint() {
	data, err := os.ReadFile("telegram_checkpoint.txt")
	if err != nil {
		return
	}
	id, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return
	}
	checkpointsMu.Lock()
	defer checkpointsMu.Unlock()
	if id > checkpoints["persianvpnhub"] {
		checkpoints["persianvpnhub"] = id
		gologger.Info().Msgf("🐍 Python checkpoint for persianvpnhub merged: %d", id)
	}
}

func saveCheckpoints() {
	if gistID == "" || gistToken == "" {
		return
	}
	checkpointsMu.Lock()
	data, _ := json.Marshal(checkpoints)
	checkpointsMu.Unlock()

	payload := GistRequest{
		Files: map[string]GistFile{
			"checkpoints.json": {Content: string(data)},
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("PATCH", "https://api.github.com/gists/"+gistID, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "token "+gistToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		gologger.Info().Msg("💾 State saved to Gist.")
	}
}

func fastPingTest(configs []string, protocol string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	raw := []string{}
	sem := make(chan struct{}, 100)

	for _, cfg := range configs {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// One retry: a single 3s dial is at the mercy of transient
			// congestion, and a config dropped here never comes back —
			// its channel checkpoint has already advanced.
			alive := checkAlive(c, protocol)
			if !alive {
				alive = checkAlive(c, protocol)
			}
			if alive {
				mu.Lock()
				raw = append(raw, c)
				mu.Unlock()
			}
		}(cfg)
	}
	wg.Wait()

	// Labelling does a DNS lookup for every new host. It used to run
	// inside the results lock above, which serialized all of those
	// lookups behind one another — invisible at a few thousand
	// configs, but at tens of thousands of unique hosts it dominated
	// the whole run. Label in parallel instead, preserving order.
	healthy := make([]string, len(raw))
	var wgLabel sync.WaitGroup
	semLabel := make(chan struct{}, 50)
	for i, c := range raw {
		wgLabel.Add(1)
		semLabel <- struct{}{}
		go func(i int, c string) {
			defer wgLabel.Done()
			defer func() { <-semLabel }()
			healthy[i] = labelWithGeo(c, i+1)
		}(i, c)
	}
	wgLabel.Wait()
	return healthy
}

func checkAlive(config string, protocol string) bool {
	if strings.HasPrefix(strings.ToLower(config), "vmess://") {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		if i := len(b64) % 4; i != 0 {
			b64 += strings.Repeat("=", 4-i)
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(b64)
		}
		if err != nil {
			return false
		}
		var v VMessConfig
		if err := json.Unmarshal(decoded, &v); err != nil {
			return false
		}
		addStr := fmt.Sprintf("%v", v.Add)
		portStr := "443"
		if port, ok := v.Port.(string); ok && port != "" {
			portStr = port
		} else if portFloat, ok := v.Port.(float64); ok {
			portStr = fmt.Sprintf("%.0f", portFloat)
		} else if v.Port != nil {
			portStr = fmt.Sprintf("%v", v.Port)
		}
		return tcpDial(addStr, portStr)
	}
	if strings.Contains(strings.ToLower(protocol), "hy2") {
		u, err := url.Parse(config)
		if err != nil {
			return false
		}
		if tcpDial(u.Hostname(), u.Port()) {
			return true
		}
		ips, err := lookupIPs(u.Hostname())
		return err == nil && len(ips) > 0
	}
	u, err := url.Parse(config)
	if err != nil {
		return false
	}
	return tcpDial(u.Hostname(), u.Port())
}

func tcpDial(host, port string) bool {
	if host == "" || port == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func labelWithGeo(config string, index int) string {
	countryName, emoji := "Dynamic", "🏴"
	host := extractHost(config)

	if host == "" {
		return buildLabel(config, emoji, countryName, index)
	}

	geoCacheMu.Lock()
	if cached, ok := geoCache[host]; ok {
		geoCacheMu.Unlock()
		parts := strings.SplitN(cached, " ", 2)
		if len(parts) == 2 {
			emoji, countryName = parts[0], parts[1]
		}
		return buildLabel(config, emoji, countryName, index)
	}
	geoCacheMu.Unlock()

	lowerHost := strings.ToLower(host)

	domainHints := map[string]string{
		".de.": "Germany", ".fr.": "France", ".nl.": "Netherlands", ".ru.": "Russia",
		".ir.": "Iran", ".ae.": "UAE", ".sg.": "Singapore", ".hk.": "Hong Kong",
		".jp.": "Japan", ".kr.": "South Korea", ".tr.": "Turkey", ".pl.": "Poland",
		"fra-": "Germany", "ams-": "Netherlands", "lhr-": "UK", "sin-": "Singapore",
		"tyo-": "Japan", "syd-": "Australia", "blr-": "India", "bom-": "India",
		"cloudflare": "Cloudflare", "workers.dev": "Cloudflare", "pages.dev": "Cloudflare",
		"r2.dev": "Cloudflare", "trycloudflare.com": "Cloudflare", "isbgpsafeyet.com": "Cloudflare",
		"fastly": "Fastly", "akamai": "Akamai", "bunnycdn": "BunnyCDN", "vercel": "Vercel",
		"fly.dev": "Fly.io", "railway.app": "Railway", "render.com": "Render",
		"koyeb.app": "Koyeb", "deta.sh": "Deta", "deno.dev": "Deno", "replit.dev": "Replit",
		"oraclecloud": "Oracle", "digitalocean": "DigitalOcean", "linode": "Linode",
		"vultr": "Vultr", "hetzner": "Hetzner", "contabo": "Contabo",
	}
	for substr, country := range domainHints {
		if strings.Contains(lowerHost, substr) {
			countryName = country
			emoji = guessEmojiFromCountry(country)
			break
		}
	}

	ips, err := lookupIPs(host)
	if err == nil && len(ips) > 0 {
		sliceLen := min(3, len(ips))
		for _, ip := range ips[:sliceLen] {
			if ip.To4() == nil && len(ips) > 1 {
				continue
			}
			if !ip.IsPrivate() && !ip.IsLoopback() {
				if db != nil {
					record, err := db.Country(ip)
					if err == nil && record != nil && record.Country.IsoCode != "" {
						code := record.Country.IsoCode
						raw := record.Country.Names["en"]
						if raw != "" {
							switch raw {
							case "United States":
								countryName = "USA"
							case "United Kingdom":
								countryName = "UK"
							case "United Arab Emirates":
								countryName = "UAE"
							case "The Netherlands":
								countryName = "Netherlands"
							default:
								countryName = raw
							}
						}
						if len(code) == 2 {
							emoji = strings.Map(func(r rune) rune { return r + 127397 }, strings.ToUpper(code))
						}
						break
					}
				}
			}
		}
	}

	if countryName == "Dynamic" && len(ips) > 0 {
		names, err := net.LookupAddr(ips[0].String())
		if err == nil && len(names) > 0 {
			ptr := strings.ToLower(names[0])
			ptrHints := map[string]string{
				"fra": "Germany", "ams": "Netherlands", "lhr": "UK", "sin": "Singapore",
				"tyo": "Japan", "syd": "Australia", "blr": "India", "bom": "India",
				"cdg": "France", "par": "France", "arn": "Sweden", "hel": "Finland",
			}
			for code, country := range ptrHints {
				if strings.Contains(ptr, code) {
					countryName = country
					emoji = guessEmojiFromCountry(country)
					break
				}
			}
		}
	}

	geoCacheMu.Lock()
	geoCache[host] = emoji + " " + countryName
	geoCacheMu.Unlock()

	return buildLabel(config, emoji, countryName, index)
}

func buildLabel(config string, emoji, countryName string, index int) string {
	trait := getTraitTag(config)
	label := fmt.Sprintf("%s %s | %s", emoji, countryName, trait)

	// Special handling for VMess: update ps in JSON
	if strings.HasPrefix(strings.ToLower(config), "vmess://") {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		if i := len(b64) % 4; i != 0 {
			b64 += strings.Repeat("=", 4-i)
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			decoded, _ = base64.URLEncoding.DecodeString(b64)
		}
		var v map[string]interface{}
		if err := json.Unmarshal(decoded, &v); err == nil {
			v["ps"] = label
			newJSON, _ := json.Marshal(v)
			return "vmess://" + base64.StdEncoding.EncodeToString(newJSON)
		}
		return config
	}

	// For other protocols: append #label
	cleanConfig := strings.Split(config, "#")[0]
	return fmt.Sprintf("%s#%s", cleanConfig, label)
}

func extractHost(config string) string {
	lower := strings.ToLower(config)

	if strings.HasPrefix(lower, "vmess://") {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		decoded, _ := sharelink.DecodeBase64Loose(b64)
		var v map[string]interface{}
		if err := json.Unmarshal(decoded, &v); err == nil {
			if add, ok := v["add"].(string); ok && add != "" {
				return add
			}
			for _, key := range []string{"sni", "host", "peer", "serverName"} {
				if val, ok := v[key].(string); ok && val != "" {
					return val
				}
			}
		}
		return ""
	}

	u, err := url.Parse(config)
	if err != nil {
		return ""
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		q := u.Query()
		for _, key := range []string{"sni", "peer", "host", "serverName", "allowInsecure"} {
			if val := q.Get(key); val != "" {
				host = val
				break
			}
		}
	}

	return host
}

// lookupIPs resolves host with a hard 3s bound. The system resolver
// can block far longer on a dead or slow nameserver, and these
// lookups sit in per-config hot paths (the Hy2 liveness fallback and
// geo labelling, which runs once per unique host).
func lookupIPs(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func resolveToIP(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}

	ips, err := lookupIPs(host)
	if err != nil || len(ips) == 0 {
		return nil
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4
		}
	}

	return ips[0]
}

func guessEmojiFromCountry(country string) string {
	switch strings.ToLower(country) {
	case "united states", "usa":
		return "🇺🇸"
	case "united kingdom", "uk":
		return "🇬🇧"
	case "germany":
		return "🇩🇪"
	case "france":
		return "🇫🇷"
	case "netherlands":
		return "🇳🇱"
	case "russia":
		return "🇷🇺"
	case "iran":
		return "🇮🇷"
	case "united arab emirates", "uae":
		return "🇦🇪"
	case "singapore":
		return "🇸🇬"
	case "hong kong":
		return "🇭🇰"
	case "japan":
		return "🇯🇵"
	case "south korea":
		return "🇰🇷"
	case "turkey":
		return "🇹🇷"
	case "poland":
		return "🇵🇱"
	case "cloudflare", "fastly", "akamai", "bunnycdn", "vercel", "fly.io", "railway", "render", "koyeb", "deta", "deno", "replit":
		return "☁️"
	default:
		return "🏴"
	}
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	var list []string
	for _, v := range slice {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		fingerprint := getConfigFingerprint(v)
		if fingerprint == "" {
			list = append(list, v)
			continue
		}
		if !seen[fingerprint] {
			seen[fingerprint] = true
			list = append(list, v)
		}
	}
	return list
}

func getConfigFingerprint(config string) string {
	reClean := regexp.MustCompile(`[[:cntrl:]]|[\x{200B}-\x{200D}\x{FEFF}]`)
	config = reClean.ReplaceAllString(config, "")

	lower := strings.ToLower(config)

	if strings.HasPrefix(lower, "vmess://") {
		b64 := strings.TrimPrefix(config, "vmess://")
		b64 = strings.TrimPrefix(b64, "VMess://")
		decoded, _ := sharelink.DecodeBase64Loose(b64)
		var v VMessConfig
		if err := json.Unmarshal(decoded, &v); err == nil {
			// Transport fields are part of the identity: two configs
			// sharing server, port and UUID but differing in network,
			// TLS, host, path or SNI are different proxies (typical
			// CDN variants) and must not dedupe into one.
			return fmt.Sprintf("vmess|%s|%v|%v|%v|%s|%s|%s|%s|%s",
				strings.ToLower(v.Add), v.Port, v.Id, v.Aid,
				v.Net, v.TLS, v.Host, v.Path, v.SNI)
		}
		return ""
	}

	uParts := strings.Split(config, "#")
	serverOnly := uParts[0]

	u, err := url.Parse(serverOnly)
	if err != nil {
		return strings.ToLower(serverOnly)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "hy2" {
		scheme = "hysteria2"
	}

	host := strings.ToLower(u.Hostname())
	user := ""
	if u.User != nil {
		user = u.User.String()
	}

	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var queryBuilder strings.Builder
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		queryBuilder.WriteString(k + "=" + strings.Join(vals, ",") + "&")
	}

	return fmt.Sprintf("%s|%s|%s|%s|%s|%s", scheme, user, host, u.Port(), u.Path, queryBuilder.String())
}

func saveToFile(name string, data []string) {
	_ = os.WriteFile(name, []byte(strings.Join(data, "\n")), 0644)
}

func printBanner() {
	fmt.Println(`
	██╗  ██╗██████╗  █████╗ ██╗   ██╗
	╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
	 ╚███╔╝ ██████╔╝███████║ ╚████╔╝ 
	 ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝  
	██╔╝ ██╗██║  ██║██║  ██║   ██║   
	╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
	    Xray Config Collector v2.0
	`)
}

// subscriptionDisplayName derives a short human-readable name for a
// subscription source URL: the repository name for GitHub URLs
// (raw.githubusercontent.com/<owner>/<repo>/... and
// github.com/<owner>/<repo>/...), the host for anything else. The
// result is capped at maxSourceNameLen runes — some repos and hosts
// carry names of 60+ characters, which wreck the report table.
func subscriptionDisplayName(rawURL string) string {
	const maxSourceNameLen = 24
	name := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if (u.Host == "raw.githubusercontent.com" || u.Host == "github.com") && len(parts) >= 2 && parts[1] != "" {
			name = parts[1]
		} else {
			name = strings.TrimPrefix(u.Host, "www.")
		}
	}
	if r := []rune(name); len(r) > maxSourceNameLen {
		name = string(r[:maxSourceNameLen]) + "…"
	}
	return name
}

func generateReportStructure(reports []ChannelReport, stats map[string][2]int) string {
	utcNow := time.Now().UTC()
	loc, _ := time.LoadLocation("Asia/Tehran")
	tehranNow := utcNow.In(loc)
	jy, jm, jd := toJalali(tehranNow.Year(), int(tehranNow.Month()), tehranNow.Day())

	totalUnique := 0
	totalLive := 0
	for _, s := range stats {
		totalUnique += s[0]
		totalLive += s[1]
	}

	var sb strings.Builder
	sb.WriteString("# 📊 Status Report\n\n")
	sb.WriteString("### 🕒 Last Update\n")
	sb.WriteString(fmt.Sprintf("- **Tehran Time:** 🇮🇷 `%d/%02d/%02d` | `%02d:%02d:%02d`\n", jy, jm, jd, tehranNow.Hour(), tehranNow.Minute(), tehranNow.Second()))
	sb.WriteString(fmt.Sprintf("- **International:** 🌐 `%s`\n\n", tehranNow.Format("Monday, 02 Jan 2006")))

	sb.WriteString("### ⚡ Global Statistics\n")
	sb.WriteString(fmt.Sprintf("- **Total Configs Processed:** `%d` (Total Unique)\n", totalUnique))
	sb.WriteString(fmt.Sprintf("- **Total Alive:** `%d` 🚀\n", totalLive))
	sb.WriteString("\n#### 🔍 Protocol Breakdown:\n")

	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		s := stats[k]
		sb.WriteString(fmt.Sprintf("- **%s:** %d found (%d live) ⚡\n", k, s[0], s[1]))
	}

	sb.WriteString("\n- **Status:** ` Operational ` ✅\n\n")

	sb.WriteString("### 📡 Source Analysis\n\n")
	sb.WriteString("| Source Channel | Harvest Status |\n")
	sb.WriteString("| :--- | :--- |\n")

	for _, r := range reports {
		linkName := r.Name
		linkURL := "https://t.me/s/" + r.Name
		icon := "📢"
		if strings.HasPrefix(r.Name, "http://") || strings.HasPrefix(r.Name, "https://") {
			// Subscription source: link its own address under a
			// short display name — not the full URL wrapped in a
			// (broken) t.me link. The <...> form keeps URLs with
			// parentheses or fragments valid Markdown.
			linkName = subscriptionDisplayName(r.Name)
			linkURL = "<" + r.Name + ">"
			icon = "🔗"
		} else if r.Name == "persianvpnhub" {
			linkName = "persianvpnhub"
			linkURL = "https://t.me/s/persianvpnhub"
		}
		sb.WriteString(fmt.Sprintf("| %s [%s](%s) | %s |\n", icon, linkName, linkURL, r.Message))
	}
	sb.WriteString("\n---\n")
	sb.WriteString("*Auto-generated by Xray Config Collector v2.0* 🛠️")
	return sb.String()
}

func toJalali(gy, gm, gd int) (int, int, int) {
	var gDays = []int{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334}
	var jy, jm, jd int
	var gDayNo int
	gDayNo = 365*(gy-1600) + (gy-1597)/4 - (gy-1501)/100 + (gy-1201)/400
	gDayNo += gDays[gm-1]
	if gm > 2 && ((gy%4 == 0 && gy%100 != 0) || (gy%400 == 0)) {
		gDayNo++
	}
	gDayNo += gd - 1
	jDayNo := gDayNo - 79
	jNp := jDayNo / 12053
	jDayNo %= 12053
	jy = 979 + 33*jNp + 4*(jDayNo/1461)
	jDayNo %= 1461
	if jDayNo >= 366 {
		jy += (jDayNo - 1) / 365
		jDayNo = (jDayNo - 1) % 365
	}
	if jDayNo < 186 {
		jm = 1 + jDayNo/31
		jd = 1 + jDayNo%31
	} else {
		jm = 7 + (jDayNo-186)/30
		jd = 1 + (jDayNo-186)%30
	}
	return jy, jm, jd
}

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
		if err == io.EOF {
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

// isValidShadowsocks checks if an ss:// URI is a genuine Shadowsocks config:
// - userinfo must be base64 and decode to "method:password" with a known method
// - method cannot be empty or "none"
func isValidShadowsocks(config string) bool {
	base := strings.Split(config, "#")[0]
	if !strings.HasPrefix(strings.ToLower(base), "ss://") {
		return false
	}
	rest := strings.TrimPrefix(base, "ss://")
	atIdx := strings.Index(rest, "@")
	if atIdx == -1 {
		return false
	}
	userinfo := rest[:atIdx]
	// Both userinfo forms (plain method:password and the classic
	// base64 form) are decoded by internal/sharelink, the same code
	// converter.go uses, so a link cannot be valid here and
	// unparseable there or the other way round.
	method, _, ok := sharelink.DecodeSSUserinfo(userinfo)
	if !ok {
		return false
	}
	return isKnownSSMethod(strings.ToLower(method))
}

// isKnownSSMethod reports whether method is a real Shadowsocks
// encryption method. The implementation lives in internal/sharelink
// (sharelink.KnownSSMethod); this wrapper keeps the existing call
// sites unchanged.
func isKnownSSMethod(method string) bool {
	return sharelink.KnownSSMethod(method)
}

// This file teaches the subscription fetcher the two structured
// formats some sources serve instead of URI lists: Clash YAML
// (a full config or a bare proxies: document) and sing-box JSON.
// Each proxy entry is converted back into the share URI the rest of
// the pipeline already understands, so dedupe, validation, live
// testing, labelling and reporting behave exactly as they do for
// URI-list sources. Entries whose type has no share-URI form in the
// Collector's protocol set (ssr, selector, urltest, direct, ...)
// are skipped.

// proxyEntry is the protocol-neutral form both structured parsers
// fill in; entryURI renders it as a share URI.
type proxyEntry struct {
	Name           string
	Type           string // vless, vmess, trojan, ss, hysteria2
	Server         string
	Port           int
	UUID           string
	Password       string
	Cipher         string // vmess security / ss method
	AlterId        int
	Network        string // tcp, ws, grpc, xhttp, httpupgrade, http, h2
	TLS            bool
	Reality        bool
	PublicKey      string
	ShortId        string
	ServerName     string // SNI / servername
	Flow           string
	Fingerprint    string
	SkipCertVerify bool
	Path           string // ws / httpupgrade / xhttp path
	Host           string // ws Host header / xhttp host
	ServiceName    string // grpc service name
	Obfs           string // hysteria2 obfs (salamander)
	ObfsPassword   string
	PortHopping    string // hysteria2 port range, URI form "35000-45000"
}

// structuredSubscriptionURIs converts a Clash YAML or sing-box JSON
// subscription body into share URIs. It returns nil when the body is
// neither format, so plain and base64 URI lists are untouched. The
// cheap substring pre-checks keep the parsers off the (potentially
// multi-megabyte) URI lists every other source serves.
func structuredSubscriptionURIs(body []byte) []string {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") && strings.Contains(trimmed, `"outbounds"`) {
		if uris := singboxURIs([]byte(trimmed)); len(uris) > 0 {
			return uris
		}
	}
	if strings.Contains(trimmed, "proxies:") {
		if uris := clashYAMLURIs([]byte(trimmed)); len(uris) > 0 {
			return uris
		}
	}
	return nil
}

// --- Clash YAML ---

type clashProxy struct {
	Name           string            `yaml:"name"`
	Type           string            `yaml:"type"`
	Server         string            `yaml:"server"`
	Port           interface{}       `yaml:"port"`
	UUID           string            `yaml:"uuid"`
	Password       string            `yaml:"password"`
	Cipher         string            `yaml:"cipher"`
	AlterId        interface{}       `yaml:"alterId"`
	Network        string            `yaml:"network"`
	TLS            bool              `yaml:"tls"`
	ServerName     string            `yaml:"servername"`
	SNI            string            `yaml:"sni"`
	Flow           string            `yaml:"flow"`
	Fingerprint    string            `yaml:"client-fingerprint"`
	SkipCertVerify bool              `yaml:"skip-cert-verify"`
	Obfs           string            `yaml:"obfs"`
	ObfsPassword   string            `yaml:"obfs-password"`
	RealityOpts    map[string]string `yaml:"reality-opts"`
	WSOpts         *clashTransport   `yaml:"ws-opts"`
	GrpcOpts       map[string]string `yaml:"grpc-opts"`
	// Legacy flat dialect served by some proxy pools: the ws path
	// and headers sit on the entry itself instead of under ws-opts.
	WSPath    string            `yaml:"ws-path"`
	WSHeaders map[string]string `yaml:"ws-headers"`
}

type clashTransport struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

func clashYAMLURIs(body []byte) []string {
	var doc struct {
		Proxies []clashProxy `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var uris []string
	for _, p := range doc.Proxies {
		e := proxyEntry{
			Name:           sanitizeRemark(p.Name),
			Type:           strings.ToLower(strings.TrimSpace(p.Type)),
			Server:         strings.TrimSpace(p.Server),
			Port:           portNumber(p.Port),
			UUID:           p.UUID,
			Password:       p.Password,
			Cipher:         p.Cipher,
			AlterId:        portNumber(p.AlterId),
			Network:        mapNetwork(p.Network),
			TLS:            p.TLS,
			ServerName:     firstNonEmpty(p.ServerName, p.SNI),
			Flow:           p.Flow,
			Fingerprint:    p.Fingerprint,
			SkipCertVerify: p.SkipCertVerify,
			Obfs:           p.Obfs,
			ObfsPassword:   p.ObfsPassword,
		}
		if pk := p.RealityOpts["public-key"]; pk != "" {
			e.Reality = true
			e.PublicKey = pk
			e.ShortId = p.RealityOpts["short-id"]
		}
		if p.WSOpts != nil {
			e.Path = p.WSOpts.Path
			e.Host = headerHost(p.WSOpts.Headers)
		}
		if e.Path == "" {
			e.Path = p.WSPath
		}
		if e.Host == "" {
			e.Host = headerHost(p.WSHeaders)
		}
		if p.GrpcOpts != nil {
			e.ServiceName = p.GrpcOpts["grpc-service-name"]
		}
		if uri := entryURI(e); uri != "" {
			uris = append(uris, uri)
		}
	}
	return uris
}

// --- sing-box JSON ---

type singboxOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	// Port-hopping range in sing-box form "35000:45000"; some
	// configs use server_port 0 as a placeholder and carry the
	// real ports only here.
	ServerPorts string        `json:"server_ports"`
	UUID        string        `json:"uuid"`
	Password    string        `json:"password"`
	Method      string        `json:"method"`
	AlterId     int           `json:"alter_id"`
	Flow        string        `json:"flow"`
	Network     string        `json:"network"`
	Obfs        *singboxObfs  `json:"obfs"`
	Transport   *singboxTrans `json:"transport"`
	TLS         *singboxTLS   `json:"tls"`
}

type singboxObfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type singboxTrans struct {
	Type        string            `json:"type"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
	ServiceName string            `json:"service_name"`
	Host        []string          `json:"host"`
}

type singboxTLS struct {
	Enabled     bool   `json:"enabled"`
	ServerName  string `json:"server_name"`
	Insecure    bool   `json:"insecure"`
	Fingerprint string `json:"-"` // filled from UTLS below
	UTLS        *struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"utls"`
	Reality *struct {
		PublicKey string `json:"public_key"`
		ShortId   string `json:"short_id"`
	} `json:"reality"`
}

func singboxURIs(body []byte) []string {
	var doc struct {
		Outbounds []singboxOutbound `json:"outbounds"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var uris []string
	for _, o := range doc.Outbounds {
		e := proxyEntry{
			Name:     sanitizeRemark(o.Tag),
			Type:     strings.ToLower(strings.TrimSpace(o.Type)),
			Server:   strings.TrimSpace(o.Server),
			Port:     o.ServerPort,
			UUID:     o.UUID,
			Password: o.Password,
			Cipher:   o.Method,
			AlterId:  o.AlterId,
			Flow:     o.Flow,
			Network:  mapNetwork(o.Network),
		}
		if o.ServerPorts != "" {
			e.PortHopping = strings.Replace(o.ServerPorts, ":", "-", 1)
			if e.Port == 0 {
				start, _, _ := strings.Cut(o.ServerPorts, ":")
				e.Port, _ = strconv.Atoi(start)
			}
		}
		if o.Obfs != nil {
			e.Obfs = o.Obfs.Type
			e.ObfsPassword = o.Obfs.Password
		}
		if o.Transport != nil {
			if e.Network == "" || e.Network == "tcp" {
				e.Network = mapNetwork(o.Transport.Type)
			}
			e.Path = o.Transport.Path
			e.ServiceName = o.Transport.ServiceName
			e.Host = headerHost(o.Transport.Headers)
			if e.Host == "" && len(o.Transport.Host) > 0 {
				e.Host = o.Transport.Host[0]
			}
		}
		if o.TLS != nil {
			e.TLS = o.TLS.Enabled
			e.ServerName = o.TLS.ServerName
			e.SkipCertVerify = o.TLS.Insecure
			if o.TLS.UTLS != nil {
				e.Fingerprint = o.TLS.UTLS.Fingerprint
			}
			if o.TLS.Reality != nil && o.TLS.Reality.PublicKey != "" {
				e.Reality = true
				e.PublicKey = o.TLS.Reality.PublicKey
				e.ShortId = o.TLS.Reality.ShortId
			}
		}
		if uri := entryURI(e); uri != "" {
			uris = append(uris, uri)
		}
	}
	return uris
}

// --- shared helpers ---

// mapNetwork normalises the transport vocabulary of Clash and
// sing-box to share-URI type values: raw and none are Mihomo's
// spellings of plain TCP.
func mapNetwork(n string) string {
	switch strings.ToLower(strings.TrimSpace(n)) {
	case "", "tcp", "raw", "none":
		return "tcp"
	default:
		return strings.ToLower(strings.TrimSpace(n))
	}
}

// portNumber converts the loosely typed YAML/JSON numeric fields
// (int, float, or string in the wild) to an int.
func portNumber(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		p, _ := strconv.Atoi(strings.TrimSpace(n))
		return p
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// headerHost reads the Host header from a ws headers map whose key
// casing differs per source (Host, host, HOST all occur).
func headerHost(headers map[string]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "host") {
			return v
		}
	}
	return ""
}

// sanitizeRemark makes a proxy name safe for the one-URI-per-line
// list format: sing-box tags in the wild contain literal newlines,
// which would otherwise corrupt the list.
func sanitizeRemark(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, name)
	return strings.TrimSpace(name)
}

func hostPort(server string, port int) string {
	if strings.Contains(server, ":") && !strings.HasPrefix(server, "[") {
		server = "[" + server + "]"
	}
	return fmt.Sprintf("%s:%d", server, port)
}

func fragment(name string) string {
	u := url.URL{Fragment: name}
	return u.String() // "#<escaped name>"
}

// entryURI renders one proxy entry as a share URI, or "" when the
// entry lacks the fields its protocol cannot work without.
func entryURI(e proxyEntry) string {
	if e.Server == "" || e.Port < 1 || e.Port > 65535 {
		return ""
	}
	switch e.Type {
	case "vless":
		if e.UUID == "" {
			return ""
		}
		q := url.Values{}
		q.Set("encryption", "none")
		switch {
		case e.Reality:
			q.Set("security", "reality")
			q.Set("pbk", e.PublicKey)
			if e.ShortId != "" {
				q.Set("sid", e.ShortId)
			}
		case e.TLS:
			q.Set("security", "tls")
		default:
			q.Set("security", "none")
		}
		if e.ServerName != "" && (e.TLS || e.Reality) {
			q.Set("sni", e.ServerName)
		}
		if e.Fingerprint != "" {
			q.Set("fp", e.Fingerprint)
		}
		if e.Flow != "" {
			q.Set("flow", e.Flow)
		}
		network := e.Network
		if network == "" {
			network = "tcp"
		}
		q.Set("type", network)
		switch network {
		case "ws", "httpupgrade", "xhttp":
			if e.Path != "" {
				q.Set("path", e.Path)
			}
			if e.Host != "" {
				q.Set("host", e.Host)
			}
		case "grpc":
			if e.ServiceName != "" {
				q.Set("serviceName", e.ServiceName)
			}
		}
		u := url.URL{Scheme: "vless", User: url.User(e.UUID), Host: hostPort(e.Server, e.Port), RawQuery: q.Encode(), Fragment: e.Name}
		return u.String()

	case "vmess":
		if e.UUID == "" {
			return ""
		}
		network := e.Network
		if network == "" {
			network = "tcp"
		}
		tls := ""
		if e.TLS {
			tls = "tls"
		}
		v := map[string]interface{}{
			"v":    "2",
			"ps":   e.Name,
			"add":  e.Server,
			"port": strconv.Itoa(e.Port),
			"id":   e.UUID,
			"aid":  e.AlterId,
			"scy":  firstNonEmpty(e.Cipher, "auto"),
			"net":  network,
			"type": "none",
			"host": e.Host,
			"path": e.Path,
			"tls":  tls,
			"sni":  e.ServerName,
		}
		if network == "grpc" {
			// In the VMess JSON dialect the grpc service name
			// travels in the path field.
			v["path"] = e.ServiceName
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(raw)

	case "trojan":
		if e.Password == "" {
			return ""
		}
		q := url.Values{}
		if e.ServerName != "" {
			q.Set("sni", e.ServerName)
		}
		if e.SkipCertVerify {
			q.Set("allowInsecure", "1")
		}
		if e.Fingerprint != "" {
			q.Set("fp", e.Fingerprint)
		}
		network := e.Network
		if network != "" && network != "tcp" {
			q.Set("type", network)
			switch network {
			case "ws", "httpupgrade":
				if e.Path != "" {
					q.Set("path", e.Path)
				}
				if e.Host != "" {
					q.Set("host", e.Host)
				}
			case "grpc":
				if e.ServiceName != "" {
					q.Set("serviceName", e.ServiceName)
				}
			}
		}
		u := url.URL{Scheme: "trojan", User: url.User(e.Password), Host: hostPort(e.Server, e.Port), RawQuery: q.Encode(), Fragment: e.Name}
		return u.String()

	case "ss":
		if e.Cipher == "" || e.Password == "" {
			return ""
		}
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(e.Cipher + ":" + e.Password))
		return "ss://" + userinfo + "@" + hostPort(e.Server, e.Port) + fragment(e.Name)

	case "hysteria2", "hy2":
		if e.Password == "" {
			return ""
		}
		q := url.Values{}
		if e.ServerName != "" {
			q.Set("sni", e.ServerName)
		}
		if e.Obfs != "" {
			q.Set("obfs", e.Obfs)
		}
		if e.ObfsPassword != "" {
			q.Set("obfs-password", e.ObfsPassword)
		}
		if e.SkipCertVerify {
			q.Set("insecure", "1")
		}
		if e.PortHopping != "" {
			q.Set("mport", e.PortHopping)
		}
		u := url.URL{Scheme: "hysteria2", User: url.User(e.Password), Host: hostPort(e.Server, e.Port), RawQuery: q.Encode(), Fragment: e.Name}
		return u.String()
	}
	return ""
}
