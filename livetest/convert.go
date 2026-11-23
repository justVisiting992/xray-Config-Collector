// Package livetest converts proxy share links (vless, vmess, trojan,
// shadowsocks, hysteria2) into Xray outbound configurations and verifies
// them by passing real HTTP traffic through an embedded xray-core
// instance. The converter is written against the public link formats and
// the Xray JSON configuration format.
package livetest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Convert parses a proxy share link and returns the corresponding Xray
// outbound object (ready to be placed in a config's "outbounds" array).
// It returns an error for unsupported protocols and malformed links.
func Convert(link string) (map[string]any, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return nil, fmt.Errorf("empty link")
	}
	switch proto := ProtocolOf(link); proto {
	case "vless":
		return convertVLESS(link)
	case "vmess":
		return convertVMess(link)
	case "trojan":
		return convertTrojan(link)
	case "ss":
		return convertSS(link)
	case "hy2":
		return convertHysteria2(link)
	default:
		return nil, fmt.Errorf("unsupported protocol in link %q", truncate(link))
	}
}

// ProtocolOf returns the normalized protocol name for a share link
// ("vless", "vmess", "trojan", "ss", "hy2"), or "" if it has no scheme.
// hysteria2:// is normalized to "hy2".
func ProtocolOf(link string) string {
	link = strings.TrimSpace(link)
	i := strings.Index(link, "://")
	if i <= 0 {
		return ""
	}
	scheme := strings.ToLower(link[:i])
	if scheme == "hysteria2" {
		return "hy2"
	}
	return scheme
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// b64DecodeLoose decodes base64 in any of the standard / URL-safe,
// padded / unpadded variants used by share links.
func b64DecodeLoose(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	var lastErr error
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		} else {
			lastErr = err
		}
	}
	// Last resort: add padding ourselves and try the URL-safe alphabet.
	if m := len(s) % 4; m != 0 {
		if b, err := base64.URLEncoding.DecodeString(s + strings.Repeat("=", 4-m)); err == nil {
			return b, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}

// hostPort extracts and validates host/port from a parsed URL.
func hostPort(u *url.URL) (string, int, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("missing host")
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// transport carries the stream-settings inputs shared by the URL-style
// protocols (vless, trojan, vmess URL form).
type transport struct {
	network       string // tcp, ws, grpc, xhttp, splithttp, httpupgrade
	security      string // "", none, tls, reality
	sni           string
	fingerprint   string
	alpn          string // comma separated
	allowInsecure bool
	host          string
	path          string
	serviceName   string
	mode          string
	headerType    string
	publicKey     string
	shortID       string
	spiderX       string
}

func transportFromQuery(q url.Values) transport {
	t := transport{
		network:     strings.ToLower(q.Get("type")),
		security:    strings.ToLower(q.Get("security")),
		sni:         q.Get("sni"),
		fingerprint: q.Get("fp"),
		alpn:        q.Get("alpn"),
		host:        q.Get("host"),
		path:        q.Get("path"),
		serviceName: q.Get("serviceName"),
		mode:        q.Get("mode"),
		headerType:  q.Get("headerType"),
		publicKey:   q.Get("pbk"),
		shortID:     q.Get("sid"),
		spiderX:     q.Get("spx"),
	}
	if t.sni == "" {
		t.sni = q.Get("peer")
	}
	if v := q.Get("allowInsecure"); v != "" {
		t.allowInsecure = truthy(v)
	} else if v := q.Get("insecure"); v != "" {
		t.allowInsecure = truthy(v)
	}
	return t
}

// validURLHost reports whether host can be placed in a URL's host
// position and survive a String/Parse round-trip unchanged. Xray's
// SplitHTTP dialer builds its request URL from the configured host
// and re-parses it with url.Parse, ignoring the error — a host with
// spaces, slashes or bad percent-escapes makes Parse return nil and
// the core then panics on a nil *url.URL, killing the whole process.
// Rejecting such hosts at conversion time turns that poison into a
// plain per-config failure.
func validURLHost(host string) bool {
	if host == "" {
		return false
	}
	s := (&url.URL{Scheme: "https", Host: host, Path: "/"}).String()
	u, err := url.Parse(s)
	return err == nil && u.Host == host
}

// streamSettings builds the Xray streamSettings object for t.
func (t transport) streamSettings() (map[string]any, error) {
	network := t.network
	if network == "" {
		network = "tcp"
	}
	ss := map[string]any{"network": network}

	switch network {
	case "ws":
		ws := map[string]any{}
		if t.path != "" {
			ws["path"] = t.path
		}
		if t.host != "" {
			ws["headers"] = map[string]any{"Host": t.host}
		}
		ss["wsSettings"] = ws
	case "grpc":
		g := map[string]any{}
		if t.serviceName != "" {
			g["serviceName"] = t.serviceName
		}
		if t.mode == "multi" {
			g["multiMode"] = true
		}
		ss["grpcSettings"] = g
	case "xhttp", "splithttp":
		// The SplitHTTP dialer re-parses a URL built from this host
		// (or, when empty, from the TLS/Reality server name) and
		// dereferences the result without checking the parse error:
		// an invalid host panics the whole xray-core process. Reject
		// such configs here instead (see validURLHost).
		for _, h := range []string{t.host, t.sni} {
			if h != "" && !validURLHost(h) {
				return nil, fmt.Errorf("xhttp: invalid host %q", h)
			}
		}
		x := map[string]any{}
		if t.path != "" {
			x["path"] = t.path
		}
		if t.host != "" {
			x["host"] = t.host
		}
		if t.mode != "" {
			x["mode"] = t.mode
		}
		ss[network+"Settings"] = x
	case "httpupgrade":
		h := map[string]any{}
		if t.path != "" {
			h["path"] = t.path
		}
		if t.host != "" {
			h["host"] = t.host
		}
		ss["httpupgradeSettings"] = h
	case "tcp":
		if t.headerType == "http" {
			ss["tcpSettings"] = map[string]any{
				"header": map[string]any{"type": "http"},
			}
		}
	}

	switch t.security {
	case "", "none":
		// No security layer.
	case "tls":
		tls := map[string]any{}
		if t.sni != "" {
			tls["serverName"] = t.sni
		}
		if t.fingerprint != "" {
			tls["fingerprint"] = t.fingerprint
		}
		if t.alpn != "" {
			tls["alpn"] = splitCSV(t.alpn)
		}
		if t.allowInsecure {
			tls["allowInsecure"] = true
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = tls
	case "reality":
		fp := t.fingerprint
		if fp == "" {
			fp = "chrome"
		}
		r := map[string]any{
			"serverName":  t.sni,
			"fingerprint": fp,
			"publicKey":   t.publicKey,
		}
		if t.shortID != "" {
			r["shortId"] = t.shortID
		}
		if t.spiderX != "" {
			r["spiderX"] = t.spiderX
		}
		ss["security"] = "reality"
		ss["realitySettings"] = r
	}
	return ss, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// --- VLESS ---

func convertVLESS(link string) (map[string]any, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	uuid := u.User.Username()
	if uuid == "" {
		return nil, fmt.Errorf("vless: missing uuid")
	}
	host, port, err := hostPort(u)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	q := u.Query()
	enc := q.Get("encryption")
	if enc == "" {
		enc = "none"
	}
	user := map[string]any{"id": uuid, "encryption": enc, "level": 0}
	if flow := q.Get("flow"); flow != "" {
		user["flow"] = flow
	}
	ss, err := transportFromQuery(q).streamSettings()
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	return map[string]any{
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": host,
				"port":    port,
				"users":   []any{user},
			}},
		},
		"streamSettings": ss,
	}, nil
}

// --- VMess ---

func convertVMess(link string) (map[string]any, error) {
	rest := strings.TrimPrefix(link, "vmess://")
	// URL form: vmess://uuid@host:port?query
	if strings.Contains(rest, "@") {
		return convertVMessURL(link)
	}
	raw, err := b64DecodeLoose(rest)
	if err != nil {
		return nil, fmt.Errorf("vmess: base64 decode: %w", err)
	}
	// The base64-JSON form is decoded into a map because its numeric
	// fields (port, aid) appear both as numbers and as strings in the wild.
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("vmess: json decode: %w", err)
	}
	getStr := func(k string) string {
		if s, ok := m[k].(string); ok {
			return s
		}
		return ""
	}
	getInt := func(k string) int {
		switch n := m[k].(type) {
		case json.Number:
			i, _ := n.Int64()
			return int(i)
		case string:
			i, _ := strconv.Atoi(n)
			return i
		}
		return 0
	}

	host := getStr("add")
	if host == "" {
		return nil, fmt.Errorf("vmess: missing add")
	}
	port := getInt("port")
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("vmess: invalid port %v", m["port"])
	}
	uuid := getStr("id")
	if uuid == "" {
		return nil, fmt.Errorf("vmess: missing id")
	}
	cipher := getStr("scy")
	if cipher == "" {
		cipher = getStr("security")
	}
	if cipher == "" {
		cipher = "auto"
	}
	user := map[string]any{
		"id":       uuid,
		"alterId":  getInt("aid"),
		"security": cipher,
		"level":    0,
	}
	t := transport{
		network:       strings.ToLower(getStr("net")),
		security:      strings.ToLower(getStr("tls")),
		sni:           getStr("sni"),
		fingerprint:   getStr("fp"),
		alpn:          getStr("alpn"),
		host:          getStr("host"),
		path:          getStr("path"),
		headerType:    getStr("type"),
		publicKey:     getStr("pbk"),
		shortID:       getStr("sid"),
		allowInsecure: false,
	}
	if b, ok := m["skip-cert-verify"].(bool); ok && b {
		t.allowInsecure = true
	}
	if t.network == "http" {
		// Legacy VMess "http" transport: HTTP/2-style; XHTTP is its
		// successor in current xray-core.
		t.network = "xhttp"
	}
	ss, err := t.streamSettings()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": host,
				"port":    port,
				"users":   []any{user},
			}},
		},
		"streamSettings": ss,
	}, nil
}

func convertVMessURL(link string) (map[string]any, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	uuid := u.User.Username()
	if uuid == "" {
		return nil, fmt.Errorf("vmess: missing uuid")
	}
	host, port, err := hostPort(u)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	q := u.Query()
	cipher := q.Get("security")
	if cipher == "" {
		cipher = "auto"
	}
	user := map[string]any{"id": uuid, "alterId": 0, "security": cipher, "level": 0}
	t := transportFromQuery(q)
	if sec := strings.ToLower(q.Get("tls")); sec == "tls" || sec == "reality" {
		t.security = sec
	}
	ss, err := t.streamSettings()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": host,
				"port":    port,
				"users":   []any{user},
			}},
		},
		"streamSettings": ss,
	}, nil
}

// --- Trojan ---

func convertTrojan(link string) (map[string]any, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	password := u.User.Username()
	if password == "" {
		return nil, fmt.Errorf("trojan: missing password")
	}
	host, port, err := hostPort(u)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	q := u.Query()
	t := transportFromQuery(q)
	if t.security == "" {
		t.security = "tls" // Trojan defaults to TLS.
	}
	ss, err := t.streamSettings()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"protocol": "trojan",
		"settings": map[string]any{
			"servers": []any{map[string]any{
				"address":  host,
				"port":     port,
				"password": password,
				"level":    0,
			}},
		},
		"streamSettings": ss,
	}, nil
}

// --- Shadowsocks ---

// convertSS handles both SIP002 forms:
//
//	ss://base64(method:password)@host:port
//	ss://method:password@host:port        (plain userinfo)
//
// and the classic form where the base64 userinfo is decoded to obtain
// the real method and password, plus the legacy variant where the
// entire method:password@host:port string is base64-encoded.
func convertSS(link string) (map[string]any, error) {
	rest := link[len("ss://"):]
	if i := strings.Index(rest, "#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		rest = rest[:i] // plugin options are not supported; base proxy still converts
	}
	rest = strings.TrimSuffix(rest, "/")

	var userinfo, hostport string
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		userinfo, hostport = rest[:at], rest[at+1:]
	} else {
		// Legacy: the whole thing is base64(method:password@host:port).
		raw, err := b64DecodeLoose(rest)
		if err != nil {
			return nil, fmt.Errorf("ss: base64 decode: %w", err)
		}
		s := string(raw)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return nil, fmt.Errorf("ss: malformed legacy link")
		}
		userinfo, hostport = s[:at], s[at+1:]
	}

	method, password, err := parseSSUserinfo(userinfo)
	if err != nil {
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	if host == "" {
		return nil, fmt.Errorf("ss: missing host")
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	return map[string]any{
		"protocol": "shadowsocks",
		"settings": map[string]any{
			"servers": []any{map[string]any{
				"address":  host,
				"port":     port,
				"method":   method,
				"password": password,
				"level":    0,
			}},
		},
	}, nil
}

// parseSSUserinfo extracts method and password from an ss userinfo part,
// which is either plain "method:password" or base64("method:password").
func parseSSUserinfo(userinfo string) (string, string, error) {
	if userinfo == "" {
		return "", "", fmt.Errorf("ss: missing userinfo")
	}
	// Plain form: a literal ':' separates method and password. Base64
	// alphabets never contain ':', so its presence is unambiguous.
	if strings.Contains(userinfo, ":") {
		m, p, _ := strings.Cut(userinfo, ":")
		m, err1 := url.PathUnescape(m)
		p, err2 := url.PathUnescape(p)
		if err1 == nil && err2 == nil {
			if m == "" {
				return "", "", fmt.Errorf("ss: missing method")
			}
			return m, p, nil
		}
		return m, p, nil
	}
	raw, err := b64DecodeLoose(userinfo)
	if err != nil {
		return "", "", fmt.Errorf("ss: userinfo base64 decode: %w", err)
	}
	m, p, ok := strings.Cut(string(raw), ":")
	if !ok || m == "" {
		return "", "", fmt.Errorf("ss: decoded userinfo has no method:password")
	}
	return m, p, nil
}

// --- Hysteria2 ---

func convertHysteria2(link string) (map[string]any, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	auth := u.User.Username()
	q := u.Query()
	if auth == "" {
		auth = q.Get("auth")
	}
	host, port, err := hostPort(u)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = host
	}
	tls := map[string]any{"serverName": sni}
	if truthy(q.Get("insecure")) || truthy(q.Get("allowInsecure")) {
		tls["allowInsecure"] = true
	}
	if fp := q.Get("fp"); fp != "" {
		tls["fingerprint"] = fp
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = splitCSV(alpn)
	} else {
		tls["alpn"] = []string{"h3"}
	}
	// Shape for the pinned xray-core (v1.260113.0): the client settings
	// carry only address/port; auth and bandwidth live in the stream's
	// hysteriaSettings, and UDP obfs masks in streamSettings.udpmasks.
	hs := map[string]any{
		"version": 2,
		"auth":    auth,
	}
	if up := normalizeBandwidth(q.Get("up")); up != "" {
		hs["up"] = up
	}
	if down := normalizeBandwidth(q.Get("down")); down != "" {
		hs["down"] = down
	}
	stream := map[string]any{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      tls,
		"hysteriaSettings": hs,
	}
	if obfs := q.Get("obfs"); obfs == "salamander" {
		stream["udpmasks"] = []any{map[string]any{
			"type":     "salamander",
			"settings": map[string]any{"password": q.Get("obfs-password")},
		}}
	}
	return map[string]any{
		"protocol": "hysteria",
		"settings": map[string]any{
			"address": host,
			"port":    port,
		},
		"streamSettings": stream,
	}, nil
}

// normalizeBandwidth turns a link bandwidth value ("100", "100mbps",
// "100 mbps") into the string form xray-core's Bandwidth parser expects.
// Bare numbers in hy2 links are Mbps by convention.
func normalizeBandwidth(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return s + " mbps"
	}
	return s
}
