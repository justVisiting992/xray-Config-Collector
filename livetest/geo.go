package livetest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
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
// "<flag> <Country> | <PROTOCOL>", where the country is resolved from
// the exit IP observed through the proxy. On any failure — missing or
// unknown exit IP, no labeler, no scheme — the link is returned
// unchanged, so a config is never mislabelled.
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
	return RewriteRemark(link, label)
}
