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
	pTLS, pTCP, pWS, pKCP := freeP(t), freeP(t), freeP(t), freeP(t)
	err := cmdSetupKharej([]string{"-c", khCfg, "-ip", "127.0.0.1",
		"-tls", strconv.Itoa(pTLS), "-tcp", strconv.Itoa(pTCP), "-ws", strconv.Itoa(pWS), "-backup", "ws",
		"-kcp", strconv.Itoa(pKCP), "-kcp-mode", "fast3", "-fec", "10:4",
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
	if ic.Profile != "speed" || len(ic.Dial) != 4 {
		t.Fatalf("token not applied: %+v", ic)
	}
	for _, d := range ic.Dial {
		if d.Transport == "kcp" && (d.KCP == nil || d.KCP.Mode != "fast3" || d.KCP.Data != 10 || d.KCP.Parity != 4) {
			t.Fatalf("kcp options not carried by the token: %+v", d.KCP)
		}
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
	for time.Now().Before(deadline) && len(ia.StatusData().Sessions) < 6 {
		time.Sleep(100 * time.Millisecond)
	}
	if n := len(ia.StatusData().Sessions); n < 6 {
		t.Fatalf("expected tls+tcp+kcp+ws sessions, got %d", n)
	}
	roundTrip(t, "127.0.0.1:"+strconv.Itoa(fwd))

	// ---- web panel ----
	pc := ic.Panel
	_, port, _ := net.SplitHostPort(pc.Listen)
	if pc.TLS {
		t.Fatal("panel should default to plain HTTP")
	}
	base := "http://127.0.0.1:" + port + pc.Path
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
	resp, err := cl.Get("http://127.0.0.1:" + port + "/")
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

	// ---- panel: fonts, settings, kcp edit, link test ----
	get := func(p string) (int, string) {
		resp, err := cl.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Content-Type")
	}
	if code, ct := get("/font/vazirmatn.woff2"); code != 200 || ct != "font/woff2" {
		t.Fatalf("built-in font: %d %s", code, ct)
	}
	if code, _ := get("/font/yekan-400"); code != 404 {
		t.Fatalf("yekan without files should 404, got %d", code)
	}
	fontDir := filepath.Join(filepath.Dir(irCfg), "fonts")
	os.MkdirAll(fontDir, 0o755)
	os.WriteFile(filepath.Join(fontDir, "IRANYekanX-Regular.woff2"), []byte("wOF2r"), 0o644)
	os.WriteFile(filepath.Join(fontDir, "IRANYekanX-Bold.woff2"), []byte("wOF2b"), 0o644)
	os.WriteFile(filepath.Join(fontDir, "IRANYekanX-ExtraBold.woff2"), []byte("wOF2x"), 0o644)
	for w, want := range map[string]string{"400": "wOF2r", "700": "wOF2b"} {
		resp, err := cl.Get(base + "/font/yekan-" + w)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != want {
			t.Fatalf("yekan %s served %q", w, body)
		}
	}
	if code, b := call("POST", "/api/settings", map[string]any{"Cipher": "chacha20-poly1305", "Fingerprint": "firefox",
		"RefreshHours": 12, "WindowMB": 4, "KeepaliveS": 5}); code != 200 {
		t.Fatalf("settings: %d %s", code, b)
	}
	if code, _ := call("POST", "/api/settings", map[string]any{"Fingerprint": "netscape"}); code != 400 {
		t.Fatal("bad fingerprint accepted")
	}
	time.Sleep(300 * time.Millisecond)
	waitUp(t, ia)
	mode, fec := "turbo", "8:8"
	if code, b := call("POST", "/api/link", map[string]any{"Name": "kcp", "KCPMode": &mode, "FEC": &fec}); code != 200 {
		t.Fatalf("kcp edit: %d %s", code, b)
	}
	if code, _ := call("POST", "/api/link", map[string]any{"Name": "tls", "KCPMode": &mode}); code != 400 {
		t.Fatal("kcp mode on a tls link accepted")
	}
	saved, _ = node.LoadConfig(irCfg)
	var kd *node.DialConf
	for i := range saved.Dial {
		if saved.Dial[i].Name == "kcp" {
			kd = &saved.Dial[i]
		}
	}
	if saved.Cipher != "chacha20-poly1305" || saved.Fingerprint != "firefox" || saved.RefreshHours != 12 ||
		kd == nil || kd.KCP.Mode != "turbo" || kd.KCP.Data != 8 || kd.KCP.Parity != 8 {
		t.Fatalf("panel edits not saved: %+v kcp=%+v", saved, kd)
	}
	if code, b := call("GET", "/api/cdnlinks", nil); code != 200 || string(bytes.TrimSpace(b)) != "[]" {
		t.Fatalf("cdnlinks: %d %s", code, b)
	}
	if code, _ := call("GET", "/api/config?tunnel=nope", nil); code != 404 {
		t.Fatal("unknown tunnel should 404")
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

// TestReverseCDNSetup: in reverse mode the CDN domain points at iran, so
// kharej dials the CDN and iran listens on the origin port.
func TestReverseCDNSetup(t *testing.T) {
	quietStdout(t)
	dir := t.TempDir()
	khCfg := filepath.Join(dir, "kh.json")
	irCfg := filepath.Join(dir, "ir.json")
	origin := freeP(t)
	err := cmdSetupKharej([]string{"-c", khCfg, "-reverse", "127.0.0.1", "-tls", "", "-tcp", strconv.Itoa(freeP(t)),
		"-cdn", "t.example.com", "-cdn-origin-port", strconv.Itoa(origin), "-refresh", "6", "-status", "", "-panel=false"})
	if err != nil {
		t.Fatal(err)
	}
	kc, err := node.LoadConfig(khCfg)
	if err != nil {
		t.Fatal(err)
	}
	var cdn *node.DialConf
	for i := range kc.Dial {
		if kc.Dial[i].Name == "cdn" {
			cdn = &kc.Dial[i]
		}
	}
	if cdn == nil || cdn.CDN != "t.example.com" || cdn.Transport != "wss" || !cdn.Backup || kc.RefreshHours != 6 {
		t.Fatalf("kharej cdn dial wrong: %+v refresh=%d", cdn, kc.RefreshHours)
	}
	err = cmdSetupIran([]string{"-c", irCfg, "-token", kc.Token, "-forward", strconv.Itoa(freeP(t)), "-status", "", "-panel=false"})
	if err != nil {
		t.Fatal(err)
	}
	ic, _ := node.LoadConfig(irCfg)
	found := false
	for _, l := range ic.Listen {
		if l.Name == "cdn-"+strconv.Itoa(origin) && l.Transport == "ws" && l.Backup {
			found = true
		}
	}
	if !found || ic.RefreshHours != 6 {
		t.Fatalf("iran should listen ws on the origin port: %+v refresh=%d", ic.Listen, ic.RefreshHours)
	}
}

// TestMultiTunnel runs a main tunnel and an extra one in the same process
// on each side, then removes the extra one with a reload.
func TestMultiTunnel(t *testing.T) {
	quietStdout(t)
	dir := t.TempDir()
	kh := filepath.Join(dir, "kh", "config.json")
	ir := filepath.Join(dir, "ir", "config.json")
	khX := filepath.Join(app.TunnelsDir(kh), "second.json")
	irX := filepath.Join(app.TunnelsDir(ir), "second.json")
	echo := echoSrv(t)
	setup := func(khPath, irPath string, extra bool, fwd int) {
		t.Helper()
		opt := func() []string {
			if extra {
				return []string{"-panel=false", "-status", ""}
			}
			return []string{"-status", "127.0.0.1:" + strconv.Itoa(freeP(t))}
		}
		if err := cmdSetupKharej(append([]string{"-c", khPath, "-ip", "127.0.0.1", "-tls", "", "-tcp", strconv.Itoa(freeP(t)),
			"-allow-local", strconv.Itoa(echo)}, opt()...)); err != nil {
			t.Fatal(err)
		}
		kc, _ := node.LoadConfig(khPath)
		if err := cmdSetupIran(append([]string{"-c", irPath, "-token", kc.Token, "-forward", fmt.Sprintf("%d=%d", fwd, echo)}, opt()...)); err != nil {
			t.Fatal(err)
		}
	}
	fwdMain, fwdX := freeP(t), freeP(t)
	setup(kh, ir, false, fwdMain)
	setup(khX, irX, true, fwdX)

	ka, ia := app.New(kh), app.New(ir)
	for _, a := range []*app.App{ka, ia} {
		if err := a.Start(); err != nil {
			t.Fatal(err)
		}
		defer a.Close()
	}
	deadline := time.Now().Add(15 * time.Second)
	up := func() bool {
		ts := ia.StatusData().Tunnels
		return len(ts) == 2 && len(ts[0].Sessions) > 0 && len(ts[1].Sessions) > 0
	}
	for time.Now().Before(deadline) && !up() {
		time.Sleep(100 * time.Millisecond)
	}
	if !up() {
		t.Fatalf("both tunnels should be up: %+v", ia.StatusData().Tunnels)
	}
	if names := ia.TunnelNames(); len(names) != 2 || names[0] != "main" || names[1] != "second" {
		t.Fatalf("names %v", names)
	}
	roundTrip(t, "127.0.0.1:"+strconv.Itoa(fwdMain))
	roundTrip(t, "127.0.0.1:"+strconv.Itoa(fwdX))

	if err := os.Remove(irX); err != nil {
		t.Fatal(err)
	}
	if err := ia.Reload(); err != nil {
		t.Fatal(err)
	}
	if n := len(ia.StatusData().Tunnels); n != 1 {
		t.Fatalf("extra tunnel should be gone, have %d", n)
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(fwdX), time.Second); err == nil {
		c.Close()
		t.Fatal("removed tunnel's forward still listening")
	}
	roundTrip(t, "127.0.0.1:"+strconv.Itoa(fwdMain))
}

// TestPanelSetupTunnels creates a kharej and an iran tunnel the way the
// panel wizard does, sends data through them, then removes them.
func TestPanelSetupTunnels(t *testing.T) {
	quietStdout(t)
	dir := t.TempDir()
	main := filepath.Join(dir, "config.json")
	echo := echoSrv(t)
	if err := cmdSetupKharej([]string{"-c", main, "-ip", "127.0.0.1", "-tls", "", "-tcp", strconv.Itoa(freeP(t)),
		"-status", "127.0.0.1:" + strconv.Itoa(freeP(t))}); err != nil {
		t.Fatal(err)
	}
	a := app.New(main)
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	kres, err := a.SetupKharej(app.KharejRequest{Name: "kx", IP: "127.0.0.1", TCP: strconv.Itoa(freeP(t)),
		AllowLocal: strconv.Itoa(echo), Profile: "speed", Cipher: "auto", Fingerprint: "chrome"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SetupKharej(app.KharejRequest{Name: "kx", IP: "127.0.0.1", TCP: strconv.Itoa(freeP(t))}); err == nil {
		t.Fatal("an existing tunnel was replaced without Replace")
	}
	fwd := freeP(t)
	if _, err := a.SetupIran(app.IranRequest{Name: "ix", Token: kres.Token, Forward: fmt.Sprintf("%d=%d", fwd, echo)}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(app.TunnelsDir(main), "ix.json")); err != nil {
		t.Fatal("iran tunnel file not saved:", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	up := func() bool {
		for _, ts := range a.StatusData().Tunnels {
			if ts.Name == "ix" && len(ts.Sessions) > 0 {
				return true
			}
		}
		return false
	}
	for time.Now().Before(deadline) && !up() {
		time.Sleep(100 * time.Millisecond)
	}
	if !up() {
		t.Fatalf("panel-made tunnel did not connect: %+v", a.StatusData().Tunnels)
	}
	roundTrip(t, "127.0.0.1:"+strconv.Itoa(fwd))

	if err := a.RemoveTunnel(app.MainTunnel); err == nil {
		t.Fatal("main tunnel removed")
	}
	for _, n := range []string{"ix", "kx"} {
		if err := a.RemoveTunnel(n); err != nil {
			t.Fatal(err)
		}
	}
	if names := a.TunnelNames(); len(names) != 1 {
		t.Fatalf("tunnels left: %v", names)
	}
}
