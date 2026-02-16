package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Proxy represents a generic structure for Clash
type Proxy struct {
	Name     string
	Type     string
	Server   string
	Port     string
	UDP      bool
	Password string
	SNI      string
	// Add other fields as we expand (UUID, Path, etc.)
}

func main() {
	// 1. Read the harvested configs
	file, err := os.Open("mixed_iran.txt")
	if err != nil {
		fmt.Println("❌ Error: Could not find mixed_iran.txt")
		return
	}
	defer file.Close()

	var proxies []Proxy
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 2. Parse the link into a Proxy struct
		p := parseLink(line)
		if p.Server != "" {
			proxies = append(proxies, p)
		}
	}

	fmt.Printf("✅ Parsed %d proxies for Clash generation.\n", len(proxies))
	
	// Next step will be generating the YAML template...
}

func parseLink(link string) Proxy {
	u, err := url.Parse(link)
	if err != nil {
		return Proxy{}
	}

	p := Proxy{
		Type:   u.Scheme,
		Server: u.Hostname(),
		Port:   u.Port(),
		Name:   u.Fragment, // This is the label like "Node-1"
	}

	if p.Name == "" {
		p.Name = fmt.Sprintf("Node-%s", p.Server)
	}

	return p
}