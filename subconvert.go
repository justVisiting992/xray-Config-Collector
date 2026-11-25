package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

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
