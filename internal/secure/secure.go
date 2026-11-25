// Package secure implements Mirage's authenticated key exchange and the
// encrypted, length-hidden, padded record layer that runs on top of every
// transport (raw TCP, TLS, WebSocket ...).
//
// Wire format (client = side that dialed the transport connection):
//
//	C->S  salt[16] | maskedEphPub[32] | sealedLen[2+16] | sealedBody[n+16]
//	S->C  maskedEphPub[32] | sealedLen[2+16] | sealedBody[n+16]
//
// Everything on the wire is indistinguishable from random bytes for anyone
// who does not know the pre-shared key (PSK): the X25519 public keys are
// XOR-masked with a PSK-derived pad, and lengths are AEAD-sealed. The first
// byte of the salt always has its high bit set so a connection can never be
// confused with a plaintext HTTP request (see IsHTTPPrefix).
//
// Session keys are derived from an ephemeral X25519 exchange mixed with the
// PSK, which gives forward secrecy: leaking the PSK later does not reveal
// previously recorded traffic.
package secure

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

const (
	saltLen  = 16
	pubLen   = 32
	tagLen   = 16
	lenField = 2 + tagLen

	// MaxPayload is the maximum plaintext carried in one record.
	MaxPayload = 32 * 1024

	clockSkew  = 120 * time.Second
	hsVersion  = 1 // AES-256-GCM only (Mirage 1.0/1.1)
	hsVersion2 = 2 // adds a cipher byte after the timestamp
	maxHsPad   = 256
	smallWrite = 512
)

var (
	// ErrAuth means the peer failed authentication (wrong key, garbage,
	// replay, or clock skew). Callers must not reveal this to the peer.
	ErrAuth = errors.New("secure: authentication failed")
	// ErrHTTP means the first bytes look like a plaintext HTTP request,
	// i.e. a browser or an active prober, not a Mirage client.
	ErrHTTP = errors.New("secure: plaintext http request")
)

// PSK is a 32-byte pre-shared key.
type PSK [32]byte

// NewPSK returns a fresh random key.
func NewPSK() (PSK, error) {
	var k PSK
	_, err := rand.Read(k[:])
	return k, err
}

// PacketKey derives the key that obfuscates packet carriers (kcp/ftcp). It
// is separate from the session keys, which come from the handshake.
func (k PSK) PacketKey() []byte { return derive(k[:], nil, "mirage packet obfuscation v1", 32) }

func derive(secret, salt []byte, info string, n int) []byte {
	out, err := hkdf.Key(sha256.New, secret, salt, info, n)
	if err != nil {
		panic(err) // only possible with absurd lengths
	}
	return out
}

// Session ciphers. The dialing side asks for one in its handshake and the
// listener follows; v1 peers always get AES-256-GCM.
const (
	CipherAES    = "aes-256-gcm"
	CipherChaCha = "chacha20-poly1305"
	CipherAuto   = "auto" // ChaCha20 when this CPU has no AES instructions
)

const (
	cipherIDAES    byte = 1
	cipherIDChaCha byte = 2
)

// ValidCipher reports whether name is a known cipher setting ("" = AES).
func ValidCipher(name string) bool {
	switch name {
	case "", CipherAES, CipherChaCha, CipherAuto:
		return true
	}
	return false
}

// HasAESHardware reports whether this CPU accelerates AES.
func HasAESHardware() bool {
	return cpu.X86.HasAES || cpu.ARM64.HasAES || cpu.S390X.HasAES
}

func cipherID(name string) byte {
	switch name {
	case CipherChaCha:
		return cipherIDChaCha
	case CipherAuto:
		if !HasAESHardware() {
			return cipherIDChaCha
		}
	}
	return cipherIDAES
}

// CipherName names a cipher id.
func CipherName(id byte) string {
	if id == cipherIDChaCha {
		return CipherChaCha
	}
	return CipherAES
}

func newSessionAEAD(id byte, key []byte) cipher.AEAD {
	if id == cipherIDChaCha {
		a, err := chacha20poly1305.New(key)
		if err != nil {
			panic(err)
		}
		return a
	}
	return newAEAD(key)
}

func newAEAD(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return a
}

func nonce(n uint64) []byte {
	var b [12]byte
	binary.BigEndian.PutUint64(b[4:], n)
	return b[:]
}

func xor(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n))
}

// sealFrame writes sealedLen|sealedBody using nonces n and n+1.
func sealFrame(a cipher.AEAD, n uint64, body, ad []byte) []byte {
	out := make([]byte, 0, lenField+len(body)+tagLen)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(body)))
	out = a.Seal(out, nonce(n), l[:], ad)
	out = a.Seal(out, nonce(n+1), body, ad)
	return out
}

func openFrame(r io.Reader, a cipher.AEAD, n uint64, ad []byte) ([]byte, error) {
	var lb [lenField]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return nil, err
	}
	l, err := a.Open(nil, nonce(n), lb[:], ad)
	if err != nil {
		return nil, ErrAuth
	}
	size := int(binary.BigEndian.Uint16(l))
	buf := make([]byte, size+tagLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	body, err := a.Open(buf[:0], nonce(n+1), buf, ad)
	if err != nil {
		return nil, ErrAuth
	}
	return body, nil
}

// hsBody builds a handshake body. ver 1 has no cipher byte (for v1 peers).
func hsBody(ver, cid byte) []byte {
	pad := randInt(maxHsPad)
	b := make([]byte, 1+8+1+pad)
	_, _ = rand.Read(b)
	b[0] = ver
	binary.BigEndian.PutUint64(b[1:9], uint64(time.Now().Unix()))
	if ver == hsVersion2 {
		b[9] = cid
	}
	return b
}

// checkHsBody validates a handshake body and returns its version and
// requested cipher.
func checkHsBody(b []byte) (ver, cid byte, err error) {
	if len(b) < 9 || (b[0] != hsVersion && b[0] != hsVersion2) {
		return 0, 0, ErrAuth
	}
	ts := time.Unix(int64(binary.BigEndian.Uint64(b[1:9])), 0)
	if d := time.Since(ts); d > clockSkew || d < -clockSkew {
		return 0, 0, ErrAuth
	}
	ver, cid = b[0], cipherIDAES
	if ver == hsVersion2 {
		if len(b) < 10 {
			return 0, 0, ErrAuth
		}
		cid = b[9]
		if cid != cipherIDAES && cid != cipherIDChaCha {
			cid = cipherIDAES
		}
	}
	return ver, cid, nil
}

func sessionKeys(cid byte, shared []byte, psk PSK, salt []byte) (c2s, s2c cipher.AEAD) {
	secret := append(append([]byte{}, shared...), psk[:]...)
	c2s = newSessionAEAD(cid, derive(secret, salt, "mirage c2s", 32))
	s2c = newSessionAEAD(cid, derive(secret, salt, "mirage s2c", 32))
	return
}

// Client performs the client side of the handshake over c, asking for the
// named session cipher (see CipherAES).
func Client(c net.Conn, psk PSK, timeout time.Duration, cipherName string) (*Conn, error) {
	return client(c, psk, timeout, hsVersion2, cipherID(cipherName))
}

func client(c net.Conn, psk PSK, timeout time.Duration, ver, cid byte) (*Conn, error) {
	if timeout > 0 {
		_ = c.SetDeadline(time.Now().Add(timeout))
		defer c.SetDeadline(time.Time{})
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	salt[0] |= 0x80

	k1 := derive(psk[:], salt, "mirage m1", 64)
	masked := make([]byte, pubLen)
	xor(masked, priv.PublicKey().Bytes(), k1[32:])
	ad1 := append(append([]byte{}, salt...), masked...)
	msg := append(ad1, sealFrame(newAEAD(k1[:32]), 0, hsBody(ver, cid), ad1)...)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}

	br := bufio.NewReaderSize(c, 64*1024)
	k2 := derive(psk[:], salt, "mirage m2", 64)
	sMasked := make([]byte, pubLen)
	if _, err := io.ReadFull(br, sMasked); err != nil {
		return nil, err
	}
	ad2 := append(append([]byte{}, sMasked...), salt...)
	body, err := openFrame(br, newAEAD(k2[:32]), 0, ad2)
	if err != nil {
		return nil, err
	}
	_, cid, err = checkHsBody(body) // the server's choice; a v1 server answers v1: AES
	if err != nil {
		return nil, err
	}
	sPubB := make([]byte, pubLen)
	xor(sPubB, sMasked, k2[32:])
	sPub, err := ecdh.X25519().NewPublicKey(sPubB)
	if err != nil {
		return nil, ErrAuth
	}
	shared, err := priv.ECDH(sPub)
	if err != nil {
		return nil, ErrAuth
	}
	c2s, s2c := sessionKeys(cid, shared, psk, salt)
	conn := newConn(c, br, s2c, c2s)
	conn.cipher = cid
	return conn, nil
}

// IsHTTPPrefix reports whether b starts like a plaintext HTTP/1 or HTTP/2
// request line.
func IsHTTPPrefix(b []byte) bool {
	for _, m := range []string{"GET ", "POST", "HEAD", "PUT ", "OPTI", "DELE", "PATC", "CONN", "TRAC", "PRI "} {
		if len(b) >= 4 && string(b[:4]) == m {
			return true
		}
	}
	return false
}

// Server performs the server side of the handshake. It always returns the
// buffered reader it used, so that on ErrHTTP/ErrAuth the caller can hand
// the already-consumed bytes to a decoy or fallback.
func Server(c net.Conn, psk PSK, rc *ReplayCache, timeout time.Duration) (*Conn, *bufio.Reader, error) {
	br := bufio.NewReaderSize(c, 64*1024)
	if timeout > 0 {
		_ = c.SetDeadline(time.Now().Add(timeout))
	}
	head, err := br.Peek(4)
	if err != nil {
		return nil, br, err
	}
	if IsHTTPPrefix(head) {
		return nil, br, ErrHTTP
	}
	hdr, err := br.Peek(saltLen + pubLen)
	if err != nil {
		return nil, br, err
	}
	salt := append([]byte{}, hdr[:saltLen]...)
	masked := append([]byte{}, hdr[saltLen:]...)
	if salt[0]&0x80 == 0 {
		return nil, br, ErrAuth
	}
	k1 := derive(psk[:], salt, "mirage m1", 64)
	ad1 := append(append([]byte{}, salt...), masked...)
	// Peek the sealed length before consuming anything so that a failed
	// authentication leaves the bytes available to a fallback server.
	lenHdr, err := br.Peek(saltLen + pubLen + lenField)
	if err != nil {
		return nil, br, err
	}
	a1 := newAEAD(k1[:32])
	if _, err := a1.Open(nil, nonce(0), lenHdr[saltLen+pubLen:], ad1); err != nil {
		return nil, br, ErrAuth
	}
	if _, err := br.Discard(saltLen + pubLen); err != nil {
		return nil, br, err
	}
	body, err := openFrame(br, a1, 0, ad1)
	if err != nil {
		return nil, br, err
	}
	ver, cid, err := checkHsBody(body)
	if err != nil {
		return nil, br, err
	}
	if rc != nil && !rc.Add(salt) {
		return nil, br, ErrAuth
	}
	cPubB := make([]byte, pubLen)
	xor(cPubB, masked, k1[32:])
	cPub, err := ecdh.X25519().NewPublicKey(cPubB)
	if err != nil {
		return nil, br, ErrAuth
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, br, err
	}
	shared, err := priv.ECDH(cPub)
	if err != nil {
		return nil, br, ErrAuth
	}
	k2 := derive(psk[:], salt, "mirage m2", 64)
	sMasked := make([]byte, pubLen)
	xor(sMasked, priv.PublicKey().Bytes(), k2[32:])
	ad2 := append(append([]byte{}, sMasked...), salt...)
	msg := append(sMasked, sealFrame(newAEAD(k2[:32]), 0, hsBody(ver, cid), ad2)...)
	if _, err := c.Write(msg); err != nil {
		return nil, br, err
	}
	if timeout > 0 {
		_ = c.SetDeadline(time.Time{})
	}
	c2s, s2c := sessionKeys(cid, shared, psk, salt)
	conn := newConn(c, br, c2s, s2c)
	conn.cipher = cid
	return conn, br, nil
}

// Conn is an encrypted record stream. It is safe for one concurrent reader
// and any number of concurrent writers.
type Conn struct {
	raw    net.Conn
	br     *bufio.Reader
	cipher byte

	rmu   sync.Mutex
	ra    cipher.AEAD
	rn    uint64
	rbuf  []byte
	rdErr error

	rstore []byte // reused record buffer (reader side)

	wmu   sync.Mutex
	wa    cipher.AEAD
	wn    uint64
	wrErr error
	wbuf  []byte // reused record buffer (writer side)
	pad   int    // padding level, see SetPadding
}

// Padding levels.
const (
	PadNone  = 0 // fastest: no padding at all
	PadLight = 1 // pad only small records (hides keystrokes / control frames)
	PadHeavy = 2 // pad every record
)

// SetPadding chooses how much random padding outgoing records carry.
func (c *Conn) SetPadding(level int) {
	c.wmu.Lock()
	c.pad = level
	c.wmu.Unlock()
}

func newConn(raw net.Conn, br *bufio.Reader, ra, wa cipher.AEAD) *Conn {
	return &Conn{raw: raw, br: br, ra: ra, wa: wa, pad: PadLight}
}

func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rbuf) == 0 {
		if c.rdErr != nil {
			return 0, c.rdErr
		}
		body, err := c.readRecord()
		c.rn += 2
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				err = io.EOF
			}
			c.rdErr = err
			return 0, err
		}
		if len(body) < 2 {
			c.rdErr = ErrAuth
			return 0, c.rdErr
		}
		n := int(binary.BigEndian.Uint16(body))
		if n > len(body)-2 {
			c.rdErr = ErrAuth
			return 0, c.rdErr
		}
		c.rbuf = body[2 : 2+n]
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// readRecord is openFrame without per-record allocations. The returned
// slice is valid until the next call (Read consumes it before that).
func (c *Conn) readRecord() ([]byte, error) {
	var lb [lenField]byte
	if _, err := io.ReadFull(c.br, lb[:]); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := c.ra.Open(l[:0], nonce(c.rn), lb[:], nil); err != nil {
		return nil, ErrAuth
	}
	size := int(binary.BigEndian.Uint16(l[:])) + tagLen
	if cap(c.rstore) < size {
		c.rstore = make([]byte, size)
	}
	buf := c.rstore[:size]
	if _, err := io.ReadFull(c.br, buf); err != nil {
		return nil, err
	}
	body, err := c.ra.Open(buf[:0], nonce(c.rn+1), buf, nil)
	if err != nil {
		return nil, ErrAuth
	}
	return body, nil
}

func padFor(level, n int) int {
	switch level {
	case PadNone:
		return 0
	case PadHeavy:
		if n < smallWrite {
			return randInt(256)
		}
		return randInt(128)
	default:
		if n < smallWrite {
			return randInt(128)
		}
		return 0
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wrErr != nil {
		return 0, c.wrErr
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > MaxPayload {
			n = MaxPayload
		}
		pad := padFor(c.pad, n)
		blen := 2 + n + pad
		total := lenField + blen + tagLen
		if cap(c.wbuf) < total {
			c.wbuf = make([]byte, total, MaxPayload+512)
		}
		rec := c.wbuf[:total]
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(blen))
		c.wa.Seal(rec[:0], nonce(c.wn), l[:], nil)
		body := rec[lenField : lenField+blen]
		binary.BigEndian.PutUint16(body, uint16(n))
		copy(body[2:], p[:n])
		if pad > 0 {
			_, _ = rand.Read(body[2+n:])
		}
		c.wa.Seal(body[:0], nonce(c.wn+1), body, nil)
		c.wn += 2
		if _, err := c.raw.Write(rec); err != nil {
			c.wrErr = err
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// Cipher names the negotiated session cipher.
func (c *Conn) Cipher() string { return CipherName(c.cipher) }

func (c *Conn) Close() error                       { return c.raw.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// ReplayCache remembers handshake salts for longer than the accepted clock
// skew so a captured handshake cannot be replayed.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[[saltLen]byte]time.Time
	max  int
}

func NewReplayCache() *ReplayCache {
	return &ReplayCache{seen: make(map[[saltLen]byte]time.Time), max: 200000}
}

// Add returns false if salt was already seen.
func (r *ReplayCache) Add(salt []byte) bool {
	var k [saltLen]byte
	copy(k[:], salt)
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[k]; ok {
		return false
	}
	if len(r.seen) >= r.max {
		for s, t := range r.seen {
			if now.Sub(t) > 2*clockSkew+time.Minute {
				delete(r.seen, s)
			}
		}
		if len(r.seen) >= r.max {
			return false // under flood: fail closed
		}
	}
	r.seen[k] = now
	return true
}

// Sweep drops expired entries; call periodically.
func (r *ReplayCache) Sweep() {
	now := time.Now()
	r.mu.Lock()
	for s, t := range r.seen {
		if now.Sub(t) > 2*clockSkew+time.Minute {
			delete(r.seen, s)
		}
	}
	r.mu.Unlock()
}

// KeyString/ParseKey helpers.
func (k PSK) String() string { return fmt.Sprintf("%x", k[:]) }
