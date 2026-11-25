// Package transport provides the carriers a Mirage session can ride on:
//
//	tcp  - raw TCP; the stream is already indistinguishable from random
//	tls  - TLS 1.2/1.3 that looks like an HTTPS server to probes
//	ws   - WebSocket over plain HTTP (CDN origin / port 80 / 8080)
//	wss  - WebSocket over TLS (direct, or through a CDN such as Cloudflare)
//	kcp  - KCP over UDP, for lossy links (see kcp.go)
//	ftcp - KCP over fake TCP packets (see kcp.go)
//
// Listeners hand back connections that have not been authenticated yet; the
// caller runs the secure handshake and, on failure, calls Reject so that
// probes see an ordinary website (or the configured fallback server).
package transport

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Kinds of transport.
const (
	TCP = "tcp"
	TLS = "tls"
	WS  = "ws"
	WSS = "wss"
)

// Valid reports whether kind is a known transport.
func Valid(kind string) bool {
	switch kind {
	case TCP, TLS, WS, WSS, KCP, FTCP:
		return true
	}
	return false
}

// DialOptions describes how to reach the other side.
type DialOptions struct {
	Kind  string
	Addrs []string   // host:port, one picked at random per connection
	SNI   string     // TLS server name (tls/wss)
	Host  string     // HTTP Host header (ws/wss); defaults to SNI or addr host
	Path  string     // WebSocket path
	KCP   KCPOptions // kcp/ftcp tuning
	Key   []byte     // packet obfuscation key (kcp/ftcp)
}

// Dial opens one transport connection.
func Dial(ctx context.Context, o DialOptions) (net.Conn, error) {
	if len(o.Addrs) == 0 {
		return nil, errors.New("transport: no address")
	}
	addr := o.Addrs[mrand.IntN(len(o.Addrs))]
	if IsPacket(o.Kind) {
		return dialKCP(ctx, o, addr)
	}
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	host, _, _ := net.SplitHostPort(addr)
	sni := o.SNI
	if sni == "" && net.ParseIP(host) == nil {
		sni = host
	}
	switch o.Kind {
	case TCP:
		return raw, nil
	case TLS, WSS:
		alpn := []string{"h2", "http/1.1"}
		if o.Kind == WSS {
			alpn = []string{"http/1.1"}
		}
		tc := tls.Client(raw, &tls.Config{
			ServerName: sni,
			// The TLS layer is camouflage only. Authentication and
			// confidentiality come from the inner PSK handshake, which a
			// man-in-the-middle cannot complete, so certificate checks
			// are not needed (and would break self-signed setups).
			InsecureSkipVerify: true,
			NextProtos:         alpn,
			MinVersion:         tls.VersionTLS12,
		})
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			raw.Close()
			return nil, err
		}
		if o.Kind == TLS {
			return tc, nil
		}
		return wsUpgrade(tc, o, host, sni)
	case WS:
		return wsUpgrade(raw, o, host, sni)
	}
	raw.Close()
	return nil, fmt.Errorf("transport: unknown kind %q", o.Kind)
}

func wsUpgrade(c net.Conn, o DialOptions, host, sni string) (net.Conn, error) {
	h := o.Host
	if h == "" {
		h = sni
	}
	if h == "" {
		h = host
	}
	wc, err := wsClientHandshake(c, h, o.Path, 10*time.Second)
	if err != nil {
		c.Close()
		return nil, err
	}
	return wc, nil
}

// ListenOptions describes a tunnel listener.
type ListenOptions struct {
	Kind     string
	Addr     string // :443
	CertFile string
	KeyFile  string
	SNI      string     // used as CN for an auto-generated certificate
	Path     string     // WebSocket path (ws/wss)
	Fallback string     // host:port of a real web server for probes; optional
	KCP      KCPOptions // kcp/ftcp tuning
	Key      []byte     // packet obfuscation key (kcp/ftcp)
}

// Listener yields unauthenticated transport connections.
type Listener struct {
	opts   ListenOptions
	ln     net.Listener
	conns  chan net.Conn
	srv    *http.Server
	closed chan struct{}
	once   sync.Once
}

// Listen starts a listener.
func Listen(o ListenOptions) (*Listener, error) {
	if !Valid(o.Kind) {
		return nil, fmt.Errorf("transport: unknown kind %q", o.Kind)
	}
	var ln net.Listener
	var err error
	if IsPacket(o.Kind) {
		ln, err = listenKCP(o)
	} else {
		ln, err = net.Listen("tcp", o.Addr)
	}
	if err != nil {
		return nil, err
	}
	l := &Listener{opts: o, ln: ln, conns: make(chan net.Conn, 128), closed: make(chan struct{})}
	if o.Kind == TLS || o.Kind == WSS {
		cert, err := loadOrGenerateCert(o.CertFile, o.KeyFile, o.SNI)
		if err != nil {
			ln.Close()
			return nil, err
		}
		alpn := []string{"http/1.1"}
		l.ln = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   alpn,
			MinVersion:   tls.VersionTLS12,
		})
	}
	if o.Kind == WS || o.Kind == WSS {
		path := o.Path
		if path == "" {
			path = "/"
		}
		l.srv = &http.Server{
			Handler:           l.wsHandler(path),
			ReadHeaderTimeout: 15 * time.Second,
			ErrorLog:          log.New(io.Discard, "", 0),
		}
		go func() { _ = l.srv.Serve(l.ln) }()
	} else {
		go l.acceptLoop()
	}
	return l, nil
}

func (l *Listener) acceptLoop() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			select {
			case <-l.closed:
				return
			default:
			}
			if strings.Contains(err.Error(), "too many open files") {
				time.Sleep(time.Second)
				continue
			}
			l.Close()
			return
		}
		select {
		case l.conns <- c:
		case <-l.closed:
			c.Close()
			return
		}
	}
}

func (l *Listener) wsHandler(path string) http.Handler {
	var proxy http.Handler
	if l.opts.Fallback != "" {
		u := &url.URL{Scheme: "http", Host: l.opts.Fallback}
		rp := httputil.NewSingleHostReverseProxy(u)
		rp.ErrorLog = log.New(io.Discard, "", 0)
		proxy = rp
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path && isWSUpgrade(r) {
			c, err := wsServerUpgrade(w, r)
			if err != nil {
				return
			}
			select {
			case l.conns <- c:
			case <-l.closed:
				c.Close()
			}
			return
		}
		if proxy != nil {
			proxy.ServeHTTP(w, r)
			return
		}
		serveDecoy(w, r)
	})
}

// Accept returns the next raw connection.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Addr returns the bound address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Kind returns the transport kind.
func (l *Listener) Kind() string { return l.opts.Kind }

// Close stops the listener.
func (l *Listener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		if l.srv != nil {
			_ = l.srv.Close()
		}
		_ = l.ln.Close()
	})
	return nil
}

// Reject handles a connection that failed authentication so that it looks
// like an ordinary server. br holds any bytes already read. isHTTP tells
// whether the bytes looked like an HTTP request.
func (l *Listener) Reject(c net.Conn, br *bufio.Reader, isHTTP bool) {
	defer c.Close()
	if l.opts.Kind == WS || l.opts.Kind == WSS {
		// Already upgraded to WebSocket: behave like an app that
		// silently ignores messages it does not understand.
		drain(c, br)
		return
	}
	if l.opts.Fallback != "" {
		splice(c, br, l.opts.Fallback)
		return
	}
	if isHTTP {
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, 1<<20))
		writeDecoyRaw(c, req)
		return
	}
	drain(c, br)
}

// drain swallows input for a random time, like a server waiting for a
// protocol message it never receives, then closes.
func drain(c net.Conn, br *bufio.Reader) {
	_ = c.SetDeadline(time.Now().Add(time.Duration(10+mrand.IntN(50)) * time.Second))
	_, _ = io.Copy(io.Discard, io.LimitReader(br, 64<<20))
}

func splice(c net.Conn, br *bufio.Reader, addr string) {
	up, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		drain(c, br)
		return
	}
	defer up.Close()
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		if _, err := up.Write(b); err != nil {
			return
		}
		_, _ = br.Discard(n)
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

const decoyHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title><style>body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f6f7f9;color:#222}
main{max-width:640px;margin:12vh auto;padding:32px;background:#fff;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:22px;margin:0 0 12px}p{line-height:1.6;color:#555}</style></head>
<body><main><h1>Site under maintenance</h1><p>We are performing scheduled maintenance. Please check back soon.</p></main></body></html>
`

func serveDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx")
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, decoyHTML)
}

type rawRW struct {
	h    http.Header
	code int
	buf  strings.Builder
}

func (r *rawRW) Header() http.Header         { return r.h }
func (r *rawRW) WriteHeader(c int)           { r.code = c }
func (r *rawRW) Write(b []byte) (int, error) { return r.buf.Write(b) }

func writeDecoyRaw(c net.Conn, req *http.Request) {
	rw := &rawRW{h: http.Header{}, code: 200}
	serveDecoy(rw, req)
	resp := &http.Response{
		StatusCode:    rw.code,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        rw.h,
		ContentLength: int64(rw.buf.Len()),
		Body:          io.NopCloser(strings.NewReader(rw.buf.String())),
		Close:         true,
	}
	resp.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	_ = resp.Write(c)
}

func loadOrGenerateCert(certFile, keyFile, cn string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		if _, err := os.Stat(certFile); err == nil {
			return tls.LoadX509KeyPair(certFile, keyFile)
		}
		certPEM, keyPEM, err := GenerateCert(cn)
		if err != nil {
			return tls.Certificate{}, err
		}
		if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
			return tls.Certificate{}, err
		}
		if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, err
		}
		return tls.X509KeyPair(certPEM, keyPEM)
	}
	certPEM, keyPEM, err := GenerateCert(cn)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// GenerateCert creates a self-signed ECDSA certificate.
func GenerateCert(cn string) (certPEM, keyPEM []byte, err error) {
	if cn == "" {
		cn = "localhost"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Duration(1+mrand.IntN(60)) * 24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(cn); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{cn}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return certPEM, keyPEM, nil
}
