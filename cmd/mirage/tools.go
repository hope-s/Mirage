package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"mirage/internal/node"
)

func postStatus(cfgPath, path string, timeout time.Duration, out any) error {
	u, err := statusURL(cfgPath)
	if err != nil {
		return err
	}
	cl := http.Client{Timeout: timeout}
	resp, err := cl.Post(u+path, "application/json", nil)
	if err != nil {
		return fmt.Errorf("service not reachable - is it running? %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return errors.New(string(body))
	}
	return json.Unmarshal(body, out)
}

func cmdLinktest(args []string) error {
	fs := flag.NewFlagSet("linktest", flag.ExitOnError)
	cfgPath := configFlag(fs)
	tunnel := fs.String("tunnel", "", "tunnel to test (default: main)")
	_ = fs.Parse(args)
	var r node.LinkTestResult
	err := spin("testing each link: fresh connections, latency, jitter and a short upload (about 10s per link)", func() error {
		return postStatus(*cfgPath, "/linktest?tunnel="+url.QueryEscape(*tunnel), 10*time.Minute, &r)
	})
	if err != nil {
		return err
	}
	fmt.Println(renderLinkTest(r))
	return nil
}

func cmdCFScan(args []string) error {
	fs := flag.NewFlagSet("cfscan", flag.ExitOnError)
	cfgPath := configFlag(fs)
	link := fs.String("link", "", "CDN link name (default: the first one)")
	tunnel := fs.String("tunnel", "", "tunnel (default: main)")
	port := fs.Int("port", 0, "edge port: 443, 2053, 2083, 2087, 2096 or 8443 (default: the link's port)")
	n := fs.Int("n", 400, "how many random Cloudflare IPs to probe")
	apply := fs.Bool("apply", false, "switch the link to the best IPs found (saved in the config)")
	_ = fs.Parse(args)
	q := url.Values{}
	q.Set("link", *link)
	q.Set("tunnel", *tunnel)
	q.Set("port", strconv.Itoa(*port))
	q.Set("n", strconv.Itoa(*n))
	if *apply {
		q.Set("apply", "1")
	}
	var r node.ScanReport
	err := spin(fmt.Sprintf("probing %d Cloudflare IPs, then testing the fastest with real tunnel handshakes (about a minute)", *n), func() error {
		return postStatus(*cfgPath, "/cfscan?"+q.Encode(), 5*time.Minute, &r)
	})
	if err != nil {
		return err
	}
	fmt.Println(renderScan(r, *apply))
	return nil
}
