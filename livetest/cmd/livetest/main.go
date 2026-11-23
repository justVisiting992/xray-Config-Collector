// Command livetest live-tests proxy share links from files through an
// embedded xray-core: a config only passes if it actually carries an
// HTTP request through the proxy.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/justVisiting992/xray-Config-Collector/livetest"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "livetest:", err)
		os.Exit(1)
	}
}

func run() error {
	filesFlag := flag.String("files", "mixed_iran.txt", "comma-separated files of proxy links to test")
	concurrency := flag.Int("concurrency", 50, "number of configs tested in parallel")
	timeout := flag.Duration("timeout", 5*time.Second, "per-config test timeout")
	probe := flag.String("probe", livetest.DefaultProbeURL, "URL fetched through each proxy")
	out := flag.String("out", "", "if set, write passing links to this file, one per line")
	exitIP := flag.Bool("exit-ip", false, "also fetch each passing config's exit IP")
	geoDB := flag.String("geo-db", "Country.mmdb", "path to the GeoIP country database used to label passing links by exit IP (only with -out)")
	flag.Parse()

	var links []string
	for _, name := range strings.Split(*filesFlag, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		ls, err := readLinks(name)
		if err != nil {
			return err
		}
		links = append(links, ls...)
	}
	if len(links) == 0 {
		return fmt.Errorf("no links found in %q", *filesFlag)
	}

	// Writing labelled output needs each passing config's exit IP, so
	// requesting -out enables the exit-IP fetch automatically.
	wantExitIP := *exitIP || *out != ""

	start := time.Now()
	results := livetest.TestAll(context.Background(), links, livetest.Options{
		ProbeURL:    *probe,
		Timeout:     *timeout,
		Concurrency: *concurrency,
		ExitIP:      wantExitIP,
	})
	elapsed := time.Since(start)

	// The geo labeler is only needed to label links written to -out.
	var labeler *livetest.GeoLabeler
	if *out != "" {
		gl, err := livetest.OpenGeoLabeler(*geoDB)
		if err != nil {
			fmt.Fprintf(os.Stderr, "livetest: warning: cannot open geo database %q: %v; passing links will be written unlabelled\n", *geoDB, err)
		} else {
			labeler = gl
			defer labeler.Close()
		}
	}

	type stat struct{ total, passed int }
	byProto := map[string]*stat{}
	var protos []string
	passedLinks := make([]string, 0, len(results))
	totalPassed := 0
	for _, r := range results {
		s, ok := byProto[r.Protocol]
		if !ok {
			s = &stat{}
			byProto[r.Protocol] = s
			protos = append(protos, r.Protocol)
		}
		s.total++
		if r.OK {
			s.passed++
			totalPassed++
			link := r.Link
			if labeler != nil {
				link = livetest.LabelWithExitIP(link, r.ExitIP, labeler)
			}
			passedLinks = append(passedLinks, link)
		}
	}
	sort.Strings(protos)
	for _, p := range protos {
		s := byProto[p]
		fmt.Printf("%s: %d total, %d passed\n", p, s.total, s.passed)
	}
	fmt.Printf("total: %d tested, %d passed in %s\n", len(results), totalPassed, elapsed.Round(time.Millisecond))

	if *out != "" {
		content := strings.Join(passedLinks, "\n")
		if content != "" {
			content += "\n"
		}
		if err := os.WriteFile(*out, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func readLinks(name string) ([]string, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var links []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		links = append(links, line)
	}
	return links, sc.Err()
}
