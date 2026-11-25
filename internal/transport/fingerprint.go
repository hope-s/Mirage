package transport

import (
	"context"
	"fmt"
	mrand "math/rand/v2"
	"net"

	utls "github.com/refraction-networking/utls"
)

// Fingerprints are the TLS ClientHello shapes a dialer can present. A
// browser fingerprint makes tls/wss links look like that browser to DPI;
// "go" is Go's own TLS stack.
var Fingerprints = []string{"chrome", "firefox", "safari", "edge", "ios", "random", "go"}

var helloIDs = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"edge":    utls.HelloEdge_Auto,
	"ios":     utls.HelloIOS_Auto,
}

// ValidFingerprint reports whether fp is known ("" = chrome).
func ValidFingerprint(fp string) bool {
	if fp == "" || fp == "random" || fp == "go" {
		return true
	}
	_, ok := helloIDs[fp]
	return ok
}

// uclient runs a TLS handshake that mimics a browser. alpn replaces the
// browser's own list so the server negotiates what we can speak.
func uclient(ctx context.Context, raw net.Conn, sni string, alpn []string, fp string) (net.Conn, error) {
	if fp == "" {
		fp = "chrome"
	}
	if fp == "random" {
		fp = []string{"chrome", "firefox", "safari", "edge"}[mrand.IntN(4)]
	}
	id, ok := helloIDs[fp]
	if !ok {
		return nil, fmt.Errorf("transport: unknown fingerprint %q", fp)
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, err
	}
	for _, e := range spec.Extensions {
		if a, ok := e.(*utls.ALPNExtension); ok {
			a.AlpnProtocols = alpn
		}
	}
	uc := utls.UClient(raw, &utls.Config{
		ServerName: sni,
		// camouflage only; the inner PSK handshake authenticates
		InsecureSkipVerify: true,
	}, utls.HelloCustom)
	if err := uc.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uc, nil
}
