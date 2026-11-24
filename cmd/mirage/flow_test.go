package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mirage/internal/app"
	"mirage/internal/node"
)

func freeP(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func echoSrv(t *testing.T) int {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func quietStdout(t *testing.T) {
	old := os.Stdout
	f, _ := os.Open(os.DevNull)
	os.Stdout = f
	t.Cleanup(func() { os.Stdout = old; f.Close() })
}

// TestFullFlow runs both setup commands exactly as a user would, starts
// both apps, pushes data through a forward, then drives the web panel.
func TestFullFlow(t *testing.T) {
	quietStdout(t)
	dir := t.TempDir()
	khCfg := filepath.Join(dir, "kh", "config.json")
	irCfg := filepath.Join(dir, "ir", "config.json")
	echo := echoSrv(t)
	pTLS, pTCP, pWS := freeP(t), freeP(t), freeP(t)
	err := cmdSetupKharej([]string{"-c", khCfg, "-ip", "127.0.0.1",
		"-tls", strconv.Itoa(pTLS), "-tcp", strconv.Itoa(pTCP), "-ws", strconv.Itoa(pWS), "-backup", "ws",
		"-allow-local", strconv.Itoa(echo), "-status", "127.0.0.1:" + strconv.Itoa(freeP(t)), "-profile", "speed"})
	if err != nil {
		t.Fatal(err)
	}
	kc, err := node.LoadConfig(khCfg)
	if err != nil {
		t.Fatal(err)
	}
	fwd := freeP(t)
	err = cmdSetupIran([]string{"-c", irCfg, "-token", kc.Token,
		"-forward", fmt.Sprintf("%d=%d", fwd, echo), "-socks", strconv.Itoa(freeP(t)),
		"-status", "127.0.0.1:" + strconv.Itoa(freeP(t))})
	if err != nil {
		t.Fatal(err)
	}
	ic, _ := node.LoadConfig(irCfg)
	if ic.Profile != "speed" || len(ic.Dial) != 3 {
		t.Fatalf("token not applied: %+v", ic)
	}

	ka := app.New(khCfg)
	if err := ka.Start(); err != nil {
		t.Fatal(err)
	}
	defer ka.Close()
	ia := app.New(irCfg)
	if err := ia.Start(); err != nil {
		t.Fatal(err)
	}
	defer ia.Close()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && len(ia.StatusData().Sessions) < 4 {
		time.Sleep(100 * time.Millisecond)
	}
	if n := len(ia.StatusData().Sessions); n < 4 {
		t.Fatalf("expected tls+tcp+ws sessions, got %d", n)
	}
	roundTrip(t, "127.0.0.1:"+strconv.Itoa(fwd))

	// ---- web panel ----
	pc := ic.Panel
	_, port, _ := net.SplitHostPort(pc.Listen)
	base := "https://127.0.0.1:" + port + pc.Path
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar, Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	call := func(method, p string, body any) (int, []byte) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, base+p, rd)
		req.Header.Set("X-Mirage", "1")
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	// wrong secret path looks like nginx 404
	resp, err := cl.Get("https://127.0.0.1:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("panel visible without secret path: %d", resp.StatusCode)
	}
	if code, _ := call("GET", "/api/status", nil); code != 401 {
		t.Fatalf("status without login: %d", code)
	}
	if code, _ := call("POST", "/api/login", map[string]string{"User": "admin", "Pass": "wrong"}); code != 401 {
		t.Fatalf("bad login accepted: %d", code)
	}
	if code, b := call("POST", "/api/login", map[string]string{"User": pc.User, "Pass": pc.Pass}); code != 200 {
		t.Fatalf("login failed: %d %s", code, b)
	}
	// CSRF guard
	r2, _ := http.NewRequest("GET", base+"/api/status", nil)
	if resp, err := cl.Do(r2); err == nil {
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("missing X-Mirage header accepted: %d", resp.StatusCode)
		}
	}
	code, b := call("GET", "/api/status", nil)
	if code != 200 || !strings.Contains(string(b), `"role":"iran"`) {
		t.Fatalf("status: %d %s", code, b)
	}
	// edit forwards from the panel: add a second forward, reload applies it
	fwd2 := freeP(t)
	code, b = call("PUT", "/api/forwards", map[string]any{
		"Forward": []node.ForwardConf{{Proto: "tcp", Listen: "127.0.0.1:" + strconv.Itoa(fwd), Target: "127.0.0.1:" + strconv.Itoa(echo)},
			{Proto: "tcp", Listen: "127.0.0.1:" + strconv.Itoa(fwd2), Target: "127.0.0.1:" + strconv.Itoa(echo)}},
		"Socks": []node.SocksConf{}})
	if code != 200 {
		t.Fatalf("edit forwards: %d %s", code, b)
	}
	time.Sleep(300 * time.Millisecond)
	waitUp(t, ia)
	roundTrip(t, "127.0.0.1:"+strconv.Itoa(fwd2))
	// invalid config is rejected and the old one keeps running
	code, _ = call("PUT", "/api/forwards", map[string]any{"Forward": []node.ForwardConf{{Proto: "tcp", Listen: "bad", Target: "x"}}})
	if code != 400 {
		t.Fatalf("invalid forward accepted: %d", code)
	}
	roundTrip(t, "127.0.0.1:"+strconv.Itoa(fwd2))
	// disable the tcp link from the panel
	off := true
	if code, b := call("POST", "/api/link", map[string]any{"Name": "tcp", "Disabled": &off}); code != 200 {
		t.Fatalf("link toggle: %d %s", code, b)
	}
	time.Sleep(300 * time.Millisecond)
	waitUp(t, ia)
	for _, s := range ia.StatusData().Sessions {
		if s.Link == "tcp" {
			t.Fatal("disabled link still has sessions")
		}
	}
	roundTrip(t, "127.0.0.1:"+strconv.Itoa(fwd2))
	// profile switch + speed test through the panel
	if code, b := call("POST", "/api/profile", map[string]string{"Profile": "stealth"}); code != 200 {
		t.Fatalf("profile: %d %s", code, b)
	}
	time.Sleep(300 * time.Millisecond)
	waitUp(t, ia)
	code, b = call("POST", "/api/speedtest", nil)
	if code != 200 || !strings.Contains(string(b), "down_mbps") {
		t.Fatalf("speedtest: %d %s", code, b)
	}
	// the saved file reflects the edits
	saved, _ := node.LoadConfig(irCfg)
	if saved.Profile != "stealth" || len(saved.Forward) != 2 {
		t.Fatalf("edits not saved: %+v", saved)
	}
	if code, _ := call("GET", "/api/logs", nil); code != 200 {
		t.Fatal("logs")
	}
	// kharej token is available in its panel config
	if kc.Token == "" || kc.Panel == nil {
		t.Fatal("kharej token/panel missing")
	}
}

func waitUp(t *testing.T, a *app.App) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if len(a.StatusData().Sessions) > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("tunnel did not come back after reload")
}

func roundTrip(t *testing.T, a string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", a, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	data := make([]byte, 1<<20)
	rand.Read(data)
	go func() { c.Write(data); c.(*net.TCPConn).CloseWrite() }()
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("round trip through %s failed: %v (%d bytes)", a, err, len(got))
	}
}

func TestTokenRoundTripAndForwardParsing(t *testing.T) {
	tk := token{V: 1, Key: strings.Repeat("ab", 32), Links: []tokenLink{{Name: "tls", T: "tls", Mode: "d", Addrs: []string{"1.2.3.4:443"}}}}
	s, err := encodeToken(tk)
	if err != nil {
		t.Fatal(err)
	}
	// pasted with line breaks / spaces
	broken := s[:20] + "\n  " + s[20:]
	got, err := decodeToken(broken)
	if err != nil || got.Links[0].Addrs[0] != "1.2.3.4:443" {
		t.Fatalf("decode: %v", err)
	}
	if _, err := decodeToken("garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
	f := parseForwards("443=2096, 8443 ,9000=10.0.0.2:80", "tcp")
	want := []node.ForwardConf{{Proto: "tcp", Listen: ":443", Target: "127.0.0.1:2096"}, {Proto: "tcp", Listen: ":8443", Target: "127.0.0.1:8443"}, {Proto: "tcp", Listen: ":9000", Target: "10.0.0.2:80"}}
	if fmt.Sprint(f) != fmt.Sprint(want) {
		t.Fatalf("forwards: %v", f)
	}
}
