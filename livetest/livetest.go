package livetest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/main/distro/all"
)

// DefaultProbeURL is fetched through the proxy to prove it carries
// traffic: it answers 204 with no body when reached directly.
const DefaultProbeURL = "http://gstatic.com/generate_204"

// exitIPURL returns the caller's public IP in its "ip=" line; fetched
// through the proxy it reveals the proxy's exit IP.
const exitIPURL = "https://cloudflare.com/cdn-cgi/trace"

// Options controls a live test run.
type Options struct {
	// ProbeURL is fetched through each proxy. Default DefaultProbeURL.
	ProbeURL string
	// Timeout bounds each individual config test. Default 5s.
	Timeout time.Duration
	// Concurrency is the worker-pool size for TestAll. Default 50.
	Concurrency int
	// ExitIP, when true, fetches the exit IP after a passing probe.
	ExitIP bool
	// TraceURL is the endpoint fetched to learn the exit IP. Default
	// "https://cloudflare.com/cdn-cgi/trace".
	TraceURL string
}

func (o *Options) applyDefaults() {
	if o.ProbeURL == "" {
		o.ProbeURL = DefaultProbeURL
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 50
	}
	if o.TraceURL == "" {
		o.TraceURL = exitIPURL
	}
}

// Result is the outcome of live-testing one link.
type Result struct {
	Link       string
	Protocol   string
	OK         bool
	Latency    time.Duration
	StatusCode int
	ExitIP     string
	Err        string
}

// startInstance builds and starts an in-memory xray-core instance whose
// only outbound is the one converted from a share link.
func startInstance(outbound map[string]any) (*core.Instance, error) {
	full := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"outbounds": []any{outbound},
	}
	data, err := json.Marshal(full)
	if err != nil {
		return nil, err
	}
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, err
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, err
	}
	return inst, nil
}

// httpClientThrough returns an HTTP client whose connections are dialed
// by the xray instance, so all traffic goes through the proxy. No local
// listening port is opened.
func httpClientThrough(inst *core.Instance) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := xnet.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, inst, dest)
		},
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: transport}
}

func getThrough(ctx context.Context, client *http.Client, url string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

func parseTraceIP(body []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "ip="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// TestOne live-tests a single link: it converts the link to an Xray
// outbound, starts an embedded core instance, and fetches the probe URL
// through the proxy. OK is true only when real traffic came back with
// HTTP 200 or 204.
func TestOne(ctx context.Context, link string, opts Options) (res Result) {
	opts.applyDefaults()
	res.Link = link
	res.Protocol = ProtocolOf(link)
	start := time.Now()
	defer func() { res.Latency = time.Since(start) }()
	defer func() {
		if r := recover(); r != nil {
			res.OK = false
			res.Err = fmt.Sprintf("panic: %v", r)
		}
	}()

	outbound, err := Convert(link)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	inst, err := startInstance(outbound)
	if err != nil {
		res.Err = "start xray: " + err.Error()
		return res
	}
	defer inst.Close()

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	client := httpClientThrough(inst)

	code, _, err := getThrough(ctx, client, opts.ProbeURL)
	res.StatusCode = code
	if err != nil {
		res.Err = "probe: " + err.Error()
		return res
	}
	if code != http.StatusNoContent && code != http.StatusOK {
		res.Err = fmt.Sprintf("probe returned HTTP %d", code)
		return res
	}
	res.OK = true

	if opts.ExitIP {
		if _, body, err := getThrough(ctx, client, opts.TraceURL); err == nil {
			res.ExitIP = parseTraceIP(body)
		}
	}
	return res
}

// TestAll live-tests links with a worker pool and returns one Result per
// input link, in input order.
func TestAll(ctx context.Context, links []string, opts Options) []Result {
	opts.applyDefaults()
	results := make([]Result, len(links))
	if len(links) == 0 {
		return results
	}
	workers := opts.Concurrency
	if workers > len(links) {
		workers = len(links)
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = TestOne(ctx, links[i], opts)
			}
		}()
	}
	for i := range links {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}
