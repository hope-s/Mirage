package secure

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func pair(t *testing.T) (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c, <-ch
}

func TestRoundTrip(t *testing.T) {
	psk, _ := NewPSK()
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	type res struct {
		c   *Conn
		err error
	}
	sch := make(chan res, 1)
	go func() {
		c, _, err := Server(b, psk, NewReplayCache(), 5*time.Second)
		sch <- res{c, err}
	}()
	cc, err := Client(a, psk, 5*time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	sr := <-sch
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	data := make([]byte, 3<<20)
	rand.Read(data)
	go func() { cc.Write(data); cc.Write([]byte("x")) }()
	got := make([]byte, len(data)+1)
	if _, err := io.ReadFull(sr.c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:len(data)], data) || got[len(data)] != 'x' {
		t.Fatal("mismatch")
	}
	// other direction
	go sr.c.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(cc, buf); err != nil || string(buf) != "hello" {
		t.Fatal("reverse direction failed", err)
	}
}

func TestWrongKey(t *testing.T) {
	k1, _ := NewPSK()
	k2, _ := NewPSK()
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	errc := make(chan error, 1)
	go func() { _, _, err := Server(b, k1, nil, 3*time.Second); errc <- err }()
	go Client(a, k2, 3*time.Second, "")
	if err := <-errc; !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth got %v", err)
	}
}

func TestHTTPProbe(t *testing.T) {
	k, _ := NewPSK()
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	go a.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	_, br, err := Server(b, k, nil, 3*time.Second)
	if !errors.Is(err, ErrHTTP) {
		t.Fatalf("want ErrHTTP got %v", err)
	}
	line, _ := br.ReadString('\n')
	if line != "GET / HTTP/1.1\r\n" {
		t.Fatalf("bytes not preserved: %q", line)
	}
}

// recorder captures what a client sends so it can be replayed.
type recorder struct {
	net.Conn
	buf bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) { r.buf.Write(p); return r.Conn.Write(p) }

func TestReplay(t *testing.T) {
	k, _ := NewPSK()
	rc := NewReplayCache()
	a, b := pair(t)
	rec := &recorder{Conn: a}
	go func() { Server(b, k, rc, 3*time.Second) }()
	if _, err := Client(rec, k, 3*time.Second, ""); err != nil {
		t.Fatal(err)
	}
	a.Close()
	b.Close()
	a2, b2 := pair(t)
	defer a2.Close()
	defer b2.Close()
	go a2.Write(rec.buf.Bytes())
	_, _, err := Server(b2, k, rc, 3*time.Second)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestGarbagePreservesBytes(t *testing.T) {
	k, _ := NewPSK()
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	junk := make([]byte, 100)
	rand.Read(junk)
	junk[0] |= 0x80
	go a.Write(junk)
	_, br, err := Server(b, k, nil, 3*time.Second)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth got %v", err)
	}
	got := make([]byte, 100)
	if _, err := io.ReadFull(br, got); err != nil || !bytes.Equal(got, junk) {
		t.Fatal("fallback bytes lost")
	}
}

func TestCipherNegotiation(t *testing.T) {
	psk, _ := NewPSK()
	cases := []struct {
		name string
		dial func(net.Conn) (*Conn, error)
		want string
	}{
		{"aes", func(c net.Conn) (*Conn, error) { return Client(c, psk, 3*time.Second, CipherAES) }, CipherAES},
		{"chacha", func(c net.Conn) (*Conn, error) { return Client(c, psk, 3*time.Second, CipherChaCha) }, CipherChaCha},
		// a Mirage 1.0/1.1 peer sends a v1 body and must get AES
		{"v1-peer", func(c net.Conn) (*Conn, error) { return client(c, psk, 3*time.Second, hsVersion, cipherIDAES) }, CipherAES},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			type res struct {
				c   *Conn
				err error
			}
			ch := make(chan res, 1)
			go func() { c, _, err := Server(b, psk, NewReplayCache(), 3*time.Second); ch <- res{c, err} }()
			cc, err := tc.dial(a)
			if err != nil {
				t.Fatal(err)
			}
			r := <-ch
			if r.err != nil {
				t.Fatal(r.err)
			}
			if cc.Cipher() != tc.want || r.c.Cipher() != tc.want {
				t.Fatalf("client %s server %s, want %s", cc.Cipher(), r.c.Cipher(), tc.want)
			}
			go cc.Write([]byte("hello mirage"))
			buf := make([]byte, 12)
			if _, err := io.ReadFull(r.c, buf); err != nil || string(buf) != "hello mirage" {
				t.Fatalf("data: %q %v", buf, err)
			}
		})
	}
}
