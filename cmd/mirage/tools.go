package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"text/tabwriter"
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
	fmt.Println("testing each link: fresh connections, latency, jitter and a short upload (about 10s per link)...")
	var r node.LinkTestResult
	if err := postStatus(*cfgPath, "/linktest?tunnel="+url.QueryEscape(*tunnel), 10*time.Minute, &r); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nLINK\tTRANSPORT\tOK\tCONNECT\tJITTER\tPING\tUPLOAD\tRETRANS")
	for _, l := range r.Links {
		ping, retrans := "-", "-"
		if l.RTTms > 0 {
			ping = fmt.Sprintf("%.0fms", l.RTTms)
		}
		if l.Retrans > 0 || l.Transport == "kcp" || l.Transport == "ftcp" {
			retrans = fmt.Sprintf("%.1f%%", l.Retrans*100)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d/%d\t%.0fms\t%.0fms\t%s\t%.1f Mbps\t%s\n", l.Name, l.Transport, l.OK, l.Tries,
			l.HandshakeMs, l.JitterMs, ping, l.UpMbps, retrans)
	}
	tw.Flush()
	fmt.Println("\nadvice:")
	for _, a := range r.Advice {
		fmt.Println("  -", a)
	}
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
	fmt.Printf("probing %d Cloudflare IPs, then testing the fastest with real tunnel handshakes (about a minute)...\n", *n)
	var r node.ScanReport
	if err := postStatus(*cfgPath, "/cfscan?"+q.Encode(), 5*time.Minute, &r); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nADDRESS\tTCP\tTUNNEL\tJITTER\tFAILED\tNOTE")
	shown := 0
	for _, x := range r.Results {
		if shown >= 15 {
			break
		}
		shown++
		note := ""
		if !x.OK() {
			note = x.Err
			if len(note) > 60 {
				note = note[:60] + "..."
			}
		}
		fmt.Fprintf(tw, "%s\t%.0fms\t%.0fms\t%.0fms\t%.0f%%\t%s\n", x.Addr, x.ConnMs, x.RTTms, x.JitterMs, x.Loss*100, note)
	}
	tw.Flush()
	if r.Err != "" {
		fmt.Println("\nnote:", r.Err)
	}
	if len(r.Applied) > 0 {
		fmt.Printf("\nlink %s now uses: %v (saved)\n", r.Link, r.Applied)
	} else if !*apply {
		fmt.Println("\nrun with -apply to switch the link to the best IPs")
	}
	return nil
}
