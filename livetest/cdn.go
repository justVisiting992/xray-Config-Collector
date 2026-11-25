package livetest

import (
	_ "embed"
	"net/netip"
	"sort"
	"strings"
)

// cdnRanges is the embedded CDN egress table; see cdn_ranges.txt
// for its sources and for the rules on what may be added to it.
//
//go:embed cdn_ranges.txt
var cdnRanges string

// cdnEntry holds one CDN's egress prefixes, sorted by network
// address. Prefixes within one CDN are disjoint (the source lists
// are aggregated), so a binary search finds the only prefix that
// could contain a given IP.
type cdnEntry struct {
	name string
	v4   []netip.Prefix
	v6   []netip.Prefix
}

// cdnTable is in lookup-priority order: the order in which CDNs
// first appear in cdn_ranges.txt.
var cdnTable []cdnEntry

func init() {
	byName := map[string]*cdnEntry{}
	var order []string
	for _, line := range strings.Split(cdnRanges, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, cidr, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		p = p.Masked()
		e := byName[name]
		if e == nil {
			e = &cdnEntry{name: name}
			byName[name] = e
			order = append(order, name)
		}
		if p.Addr().Is4() {
			e.v4 = append(e.v4, p)
		} else {
			e.v6 = append(e.v6, p)
		}
	}
	for _, name := range order {
		e := byName[name]
		sortPrefixes(e.v4)
		sortPrefixes(e.v6)
		cdnTable = append(cdnTable, *e)
	}
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].Addr().Compare(ps[j].Addr()) < 0 })
}

// prefixesContain reports whether any prefix in the sorted, disjoint
// list ps contains ip.
func prefixesContain(ps []netip.Prefix, ip netip.Addr) bool {
	// The prefix with the largest network address <= ip is the only
	// possible container, because the prefixes are disjoint.
	i := sort.Search(len(ps), func(i int) bool { return ps[i].Addr().Compare(ip) > 0 }) - 1
	if i < 0 {
		return false
	}
	return ps[i].Contains(ip)
}

// CDNName returns the name of the CDN whose egress ranges contain
// ipStr ("Cloudflare", "CloudFront", "Fastly" or "Akamai"). ok is
// false when the IP is unparseable or belongs to no known CDN — in
// particular, ordinary hosting and cloud VPS addresses never match,
// so a config exiting from a real server keeps its country label.
func CDNName(ipStr string) (string, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return "", false
	}
	ip = ip.Unmap()
	for _, e := range cdnTable {
		if ip.Is4() {
			if prefixesContain(e.v4, ip) {
				return e.name, true
			}
		} else if prefixesContain(e.v6, ip) {
			return e.name, true
		}
	}
	return "", false
}
