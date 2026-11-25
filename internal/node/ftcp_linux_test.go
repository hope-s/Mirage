//go:build linux

package node

import (
	"os"
	"strconv"
	"testing"

	"mirage/internal/transport"
)

// TestFakeTCP needs root (raw sockets + iptables); CI runs it with sudo.
func TestFakeTCP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("fake tcp needs root")
	}
	for _, reverse := range []bool{false, true} {
		t.Run("reverse="+strconv.FormatBool(reverse), func(t *testing.T) {
			kh, ir, fp := pair(t, reverse, []string{transport.FTCP})
			ko := &transport.KCPOptions{Mode: "fast3", Data: 10, Parity: 3}
			for i := range kh.Listen {
				kh.Listen[i].KCP = ko
			}
			for i := range kh.Dial {
				kh.Dial[i].KCP = ko
			}
			for i := range ir.Listen {
				ir.Listen[i].KCP = ko
			}
			for i := range ir.Dial {
				ir.Dial[i].KCP = ko
			}
			var in *Node
			if reverse {
				in = start(t, ir)
				start(t, kh)
			} else {
				start(t, kh)
				in = start(t, ir)
			}
			waitSessions(t, in, 2)
			echoCheck(t, addr(fp), 2<<20)
		})
	}
}
