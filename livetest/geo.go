package livetest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

// GeoLabeler looks up countries in a MaxMind GeoLite2/GeoIP2 country
// database. It is used to label configs by the country of the exit IP
// observed through the proxy — not by the proxy server's own address,
// which is what an entry-side lookup would give.
type GeoLabeler struct {
	db *geoip2.Reader
}

// OpenGeoLabeler opens the country database at dbPath.
func OpenGeoLabeler(dbPath string) (*GeoLabeler, error) {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return &GeoLabeler{db: db}, nil
}

// Close releases the underlying database.
func (g *GeoLabeler) Close() error {
	if g == nil || g.db == nil {
		return nil
	}
	return g.db.Close()
}

// CountryLabel returns "<flag-emoji> <CountryName>" for an IP, e.g.
// "🇺🇸 USA". ok is false when the IP is unparseable or has no country
// in the database, so callers can leave the original remark untouched
// instead of guessing.
func (g *GeoLabeler) CountryLabel(ipStr string) (string, bool) {
	if g == nil || g.db == nil {
		return "", false
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", false
	}
	record, err := g.db.Country(ip)
	if err != nil || record == nil || record.Country.IsoCode == "" {
		return "", false
	}
	code := record.Country.IsoCode
	raw := record.Country.Names["en"]
	if raw == "" {
		return "", false
	}
	name := normalizeCountryName(raw)
	emoji := strings.Map(func(r rune) rune { return r + 127397 }, strings.ToUpper(code))
	return fmt.Sprintf("%s %s", emoji, name), true
}

// normalizeCountryName mirrors the collector's label conventions in
// main.go's labelWithGeo.
func normalizeCountryName(raw string) string {
	switch raw {
	case "United States":
		return "USA"
	case "United Kingdom":
		return "UK"
	case "United Arab Emirates":
		return "UAE"
	case "The Netherlands":
		return "Netherlands"
	default:
		return raw
	}
}

// RewriteRemark replaces a link's display remark with label. VMess links
// carry the remark in the "ps" field of their base64 JSON payload; every
// other protocol carries it in the #fragment. This mirrors main.go's
// buildLabel. If a VMess payload cannot be decoded, the link is returned
// unchanged.
func RewriteRemark(link, label string) string {
	if strings.HasPrefix(strings.ToLower(link), "vmess://") {
		b64 := link[len("vmess://"):]
		payload := b64
		if i := len(payload) % 4; i != 0 {
			payload += strings.Repeat("=", 4-i)
		}
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(payload)
			if err != nil {
				return link
			}
		}
		var v map[string]any
		if err := json.Unmarshal(decoded, &v); err != nil {
			return link
		}
		v["ps"] = label
		newJSON, err := json.Marshal(v)
		if err != nil {
			return link
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(newJSON)
	}

	clean := strings.Split(link, "#")[0]
	return clean + "#" + label
}

// LabelWithExitIP rewrites a link's remark to
// "<flag> <Country> | <PROTOCOL> | <traits>", where the country is
// resolved from the exit IP observed through the proxy and traits
// describe the transport and encryption (see TraitTag). On any
// failure — missing or unknown exit IP, no labeler, no scheme — the
// link is returned unchanged, so a config is never mislabelled.
func LabelWithExitIP(link, exitIP string, g *GeoLabeler) string {
	countryLabel, ok := g.CountryLabel(exitIP)
	if !ok {
		return link
	}
	i := strings.Index(link, "://")
	if i <= 0 {
		return link
	}
	proto := strings.ToUpper(link[:i])
	label := fmt.Sprintf("%s | %s", countryLabel, proto)
	if tag := TraitTag(link); tag != "" {
		label += " | " + tag
	}
	return RewriteRemark(link, label)
}

// transportName normalizes a network/type value to its remark form.
// TCP is the default transport and is always reported, so two configs
// that differ only by transport never share a remark by accident.
func transportName(net string) string {
	switch strings.ToLower(strings.TrimSpace(net)) {
	case "", "tcp":
		return "TCP"
	case "ws":
		return "WS"
	case "grpc":
		return "gRPC"
	case "httpupgrade":
		return "HTTPup"
	case "xhttp", "splithttp":
		return "XHTTP"
	case "h2", "http":
		return "H2"
	case "kcp":
		return "KCP"
	case "quic":
		return "QUIC"
	default:
		return strings.ToUpper(net)
	}
}

// shortSSMethod shortens a Shadowsocks cipher name for remarks,
// mirroring main.go's getShortMethod.
func shortSSMethod(method string) string {
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
		return method
	}
}

// ssMethod extracts the cipher method from a Shadowsocks link, in both
// the classic ss://base64(method:password)@host form and the plain
// ss://method:password@host form. "" when it cannot be determined.
func ssMethod(link string) string {
	rest := link[strings.Index(link, "://")+3:]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return ""
	}
	userinfo := rest[:at]
	if dec, err := base64.RawURLEncoding.DecodeString(userinfo); err == nil {
		userinfo = string(dec)
	} else if dec, err := base64.URLEncoding.DecodeString(userinfo); err == nil {
		userinfo = string(dec)
	} else if dec, err := base64.RawStdEncoding.DecodeString(userinfo); err == nil {
		userinfo = string(dec)
	} else if dec, err := base64.StdEncoding.DecodeString(userinfo); err == nil {
		userinfo = string(dec)
	}
	if i := strings.Index(userinfo, ":"); i > 0 {
		return userinfo[:i]
	}
	return ""
}

// TraitTag describes a link's transport and encryption for its remark,
// e.g. "TCP • Reality • Vision", "WS • TLS", "TCP • ChaCha" or
// "QUIC • TLS • Salamander". Traits are joined with " • ". The
// transport is always present; "" is returned only for links whose
// scheme is not one of the supported protocols.
func TraitTag(link string) string {
	lower := strings.ToLower(link)
	scheme, _, _ := strings.Cut(lower, "://")
	var traits []string

	query := func() url.Values {
		u, err := url.Parse(link)
		if err != nil {
			return url.Values{}
		}
		return u.Query()
	}

	switch scheme {
	case "vless":
		q := query()
		traits = append(traits, transportName(q.Get("type")))
		switch sec := strings.ToLower(q.Get("security")); sec {
		case "tls":
			traits = append(traits, "TLS")
		case "reality":
			traits = append(traits, "Reality")
		case "", "none":
		default:
			traits = append(traits, strings.ToUpper(sec))
		}
		if strings.HasPrefix(strings.ToLower(q.Get("flow")), "xtls-rprx-vision") {
			traits = append(traits, "Vision")
		}
	case "vmess":
		payload := link[strings.Index(link, "://")+3:]
		if i := len(payload) % 4; i != 0 {
			payload += strings.Repeat("=", 4-i)
		}
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(payload)
		}
		if err != nil {
			return ""
		}
		var v map[string]any
		if json.Unmarshal(decoded, &v) != nil {
			return ""
		}
		net, _ := v["net"].(string)
		traits = append(traits, transportName(net))
		if tls, _ := v["tls"].(string); strings.ToLower(tls) == "tls" {
			traits = append(traits, "TLS")
		}
	case "trojan":
		q := query()
		traits = append(traits, transportName(q.Get("type")), "TLS")
	case "ss":
		q := query()
		traits = append(traits, transportName(q.Get("type")))
		if strings.ToLower(q.Get("security")) == "tls" {
			traits = append(traits, "TLS")
		}
		if m := ssMethod(link); m != "" {
			traits = append(traits, shortSSMethod(m))
		}
	case "hysteria2", "hy2":
		q := query()
		traits = append(traits, "QUIC", "TLS")
		if strings.ToLower(q.Get("obfs")) == "salamander" {
			traits = append(traits, "Salamander")
		}
	default:
		return ""
	}
	return strings.Join(traits, " • ")
}

// remarkOf returns a link's current display remark: the "ps" field for
// VMess links, the #fragment for everything else. "" when the link has
// no remark or a VMess payload cannot be decoded.
func remarkOf(link string) string {
	if strings.HasPrefix(strings.ToLower(link), "vmess://") {
		payload := link[len("vmess://"):]
		if i := strings.IndexAny(payload, "#?"); i >= 0 {
			payload = payload[:i]
		}
		if i := len(payload) % 4; i != 0 {
			payload += strings.Repeat("=", 4-i)
		}
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(payload)
			if err != nil {
				return ""
			}
		}
		var v map[string]any
		if json.Unmarshal(decoded, &v) != nil {
			return ""
		}
		ps, _ := v["ps"].(string)
		return ps
	}
	if i := strings.Index(link, "#"); i >= 0 {
		return link[i+1:]
	}
	return ""
}

// NumberDuplicateRemarks makes every remark in links unique: links
// whose remark appears more than once get a sequence number appended
// in order — " 01", " 02", ..., " 10", " 11" — while remarks that are
// already unique are left untouched. Link order is preserved. Links
// without a remark are left as they are.
func NumberDuplicateRemarks(links []string) []string {
	remarks := make([]string, len(links))
	counts := make(map[string]int)
	for i, link := range links {
		remarks[i] = remarkOf(link)
		if remarks[i] != "" {
			counts[remarks[i]]++
		}
	}
	out := make([]string, len(links))
	seen := make(map[string]int)
	for i, link := range links {
		r := remarks[i]
		if r == "" || counts[r] < 2 {
			out[i] = link
			continue
		}
		seen[r]++
		out[i] = RewriteRemark(link, fmt.Sprintf("%s %02d", r, seen[r]))
	}
	return out
}
