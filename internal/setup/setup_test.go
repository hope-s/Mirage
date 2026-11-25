package setup

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"mirage/internal/node"
)

func TestTokenRoundTripAndForwardParsing(t *testing.T) {
	tk := Token{V: 1, Key: strings.Repeat("ab", 32), Links: []Link{{Name: "tls", T: "tls", Mode: "d", Addrs: []string{"1.2.3.4:443"}}}}
	s, err := EncodeToken(tk)
	if err != nil {
		t.Fatal(err)
	}
	// pasted with line breaks / spaces
	broken := s[:20] + "\n  " + s[20:]
	got, err := DecodeToken(broken)
	if err != nil || got.Links[0].Addrs[0] != "1.2.3.4:443" {
		t.Fatalf("decode: %v", err)
	}
	if _, err := DecodeToken("garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
	f := ParseForwards("443=2096, 8443 ,9000=10.0.0.2:80", "tcp")
	want := []node.ForwardConf{{Proto: "tcp", Listen: ":443", Target: "127.0.0.1:2096"}, {Proto: "tcp", Listen: ":8443", Target: "127.0.0.1:8443"}, {Proto: "tcp", Listen: ":9000", Target: "10.0.0.2:80"}}
	if fmt.Sprint(f) != fmt.Sprint(want) {
		t.Fatalf("forwards: %v", f)
	}
}

func TestForwardsRoundTrip(t *testing.T) {
	fs := Forwards("443=2096,8443,9000=10.0.0.2:80", "8443,5353=53")
	if len(fs) != 4 || fs[1].Proto != "both" || fs[3].Proto != "udp" {
		t.Fatalf("merge: %+v", fs)
	}
	tcp, udp := FormatForwards(fs)
	if tcp != "443=2096,8443,9000=10.0.0.2:80" || udp != "8443,5353=53" {
		t.Fatalf("format: %q %q", tcp, udp)
	}
	if fmt.Sprint(Forwards(tcp, udp)) != fmt.Sprint(fs) {
		t.Fatal("round trip changed the forwards")
	}
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestCDNAutoOrigin: without an origin port the CDN origin listens with ws
// on 80 and wss on 443 so both Flexible and Full SSL work.
func TestCDNAutoOrigin(t *testing.T) {
	o := KharejDefaults()
	o.IP, o.TLS, o.TCP, o.CDN, o.CheckPorts, o.Panel, o.Status = "1.2.3.4", "", strconv.Itoa(freePort(t)), "cdn.example.com", false, nil, ""
	res, err := Kharej(o)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, l := range res.Config.Listen {
		got[l.Name] = l.Transport
	}
	if got["cdn-80"] != "ws" || got["cdn-443"] != "wss" {
		t.Fatalf("listeners: %v", got)
	}
	tk, _ := DecodeToken(res.Token)
	last := tk.Links[len(tk.Links)-1]
	if !last.CDN || last.T != "wss" || last.Addrs[0] != "cdn.example.com:443" {
		t.Fatalf("cdn link: %+v", last)
	}

	// a TLS link on 443 leaves only the Flexible origin
	o.TLS = "443"
	res, err = Kharej(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range res.Config.Listen {
		if l.Name == "cdn-443" {
			t.Fatal("cdn should not take 443 from the tls link")
		}
	}

	// reverse: iran gets optional listeners and skips busy ones
	o.TLS, o.IP, o.Reverse = "", "", "5.6.7.8"
	res, err = Kharej(o)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Iran(IranOptions{Token: res.Token, Forward: strconv.Itoa(freePort(t)), CheckPorts: false})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, l := range ir.Config.Listen {
		if strings.HasPrefix(l.Name, "cdn-") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("iran cdn listeners: %+v", ir.Config.Listen)
	}
}
