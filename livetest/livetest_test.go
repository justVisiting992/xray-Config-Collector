package livetest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

const (
	e2eMethod   = "aes-128-gcm"
	e2ePassword = "livetest-e2e-password"
)

// freePort returns a currently-free TCP port on 127.0.0.1.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startSSServer starts a local xray instance with a Shadowsocks inbound
// (freedom outbound) on 127.0.0.1:port.
func startSSServer(t *testing.T, port int, password string) *core.Instance {
	t.Helper()
	cfgJSON := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "shadowsocks",
			"settings": map[string]any{
				"method":   e2eMethod,
				"password": password,
				"network":  "tcp,udp",
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	}
	data, err := json.Marshal(cfgJSON)
	if err != nil {
		t.Fatalf("marshal server config: %v", err)
	}
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("load server config: %v", err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		t.Fatalf("core.New server: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { inst.Close() })
	return inst
}

func ssLink(port int, password string) string {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(e2eMethod + ":" + password))
	return fmt.Sprintf("ss://%s@127.0.0.1:%d", userinfo, port)
}

// End-to-end on localhost only: a real Shadowsocks proxy chain must pass
// the live test, the same server with a wrong password must fail, and a
// link to a dead port must fail. No external network is touched.
func TestLiveTestEndToEnd(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	port := freePort(t)
	startSSServer(t, port, e2ePassword)

	ctx := context.Background()
	opts := Options{ProbeURL: target.URL, Timeout: 5 * time.Second}

	good := TestOne(ctx, ssLink(port, e2ePassword), opts)
	if !good.OK {
		t.Fatalf("correct-password link should pass, got %+v", good)
	}
	if good.StatusCode != http.StatusNoContent {
		t.Errorf("StatusCode = %d, want 204", good.StatusCode)
	}
	if good.Protocol != "ss" {
		t.Errorf("Protocol = %q, want ss", good.Protocol)
	}

	bad := TestOne(ctx, ssLink(port, "wrong-password"), opts)
	if bad.OK {
		t.Fatalf("wrong-password link should not pass, got %+v", bad)
	}

	deadPort := freePort(t)
	deadLink := fmt.Sprintf("vless://dc7d45c9-c942-41e3-b880-9a7fd5b64e2f@127.0.0.1:%d?encryption=none&security=none&type=tcp", deadPort)
	dead := TestOne(ctx, deadLink, Options{ProbeURL: target.URL, Timeout: 3 * time.Second})
	if dead.OK {
		t.Fatalf("dead-port link should not pass, got %+v", dead)
	}
}

// The exit-IP fetch must go through the proxy too: a local trace
// server stands in for Cloudflare's /cdn-cgi/trace (via Options.TraceURL)
// and its ip= line must land in Result.ExitIP. Localhost only.
func TestExitIPThroughProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	trace := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("fl=123\nh=cloudflare.com\nip=203.0.113.7\nts=1700000000\nloc=NL\n"))
	}))
	defer trace.Close()

	port := freePort(t)
	startSSServer(t, port, e2ePassword)

	res := TestOne(context.Background(), ssLink(port, e2ePassword), Options{
		ProbeURL: target.URL,
		TraceURL: trace.URL,
		ExitIP:   true,
		Timeout:  5 * time.Second,
	})
	if !res.OK {
		t.Fatalf("correct-password link should pass, got %+v", res)
	}
	if res.ExitIP != "203.0.113.7" {
		t.Errorf("ExitIP = %q, want %q", res.ExitIP, "203.0.113.7")
	}
}

// TestAll preserves input order and reports per-link results.
func TestTestAllOrderAndCount(t *testing.T) {
	links := []string{
		"ssr://unsupported",
		"garbage",
		"vless://dc7d45c9-c942-41e3-b880-9a7fd5b64e2f@127.0.0.1:1?encryption=none",
	}
	results := TestAll(context.Background(), links, Options{Timeout: 2 * time.Second, Concurrency: 2})
	if len(results) != len(links) {
		t.Fatalf("got %d results for %d links", len(results), len(links))
	}
	for i, r := range results {
		if r.Link != links[i] {
			t.Errorf("results[%d].Link = %q, want %q", i, r.Link, links[i])
		}
		if r.OK {
			t.Errorf("results[%d] unexpectedly OK", i)
		}
	}
}
