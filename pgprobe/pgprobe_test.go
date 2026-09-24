package pgprobe

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// fakeServer answers the TLS request with sslAnswer and every login with
// reply (a whole message), or with raw bytes when sslAnswer is 0.
func fakeServer(t *testing.T, sslAnswer byte, reply []byte) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var n uint32
				if binary.Read(c, binary.BigEndian, &n) != nil || n < 8 || n > 10000 {
					return
				}
				body := make([]byte, n-4)
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				if binary.BigEndian.Uint32(body[:4]) == 80877103 {
					if sslAnswer == 0 {
						c.Write([]byte("HTTP/1.1 400 Bad Request\r\n"))
						return
					}
					c.Write([]byte{sslAnswer})
					if binary.Read(c, binary.BigEndian, &n) != nil || n < 8 || n > 10000 {
						return
					}
					body = make([]byte, n-4)
					if _, err := io.ReadFull(c, body); err != nil {
						return
					}
				}
				c.Write(reply)
			}(c)
		}
	}()
	return l.Addr().String()
}

func msg(typ byte, payload []byte) []byte {
	out := []byte{typ}
	out = binary.BigEndian.AppendUint32(out, uint32(len(payload)+4))
	return append(out, payload...)
}

func errMsg(code, text string) []byte {
	p := append([]byte("SFATAL\x00C"+code+"\x00M"), text...)
	return msg('E', append(p, 0, 0))
}

func TestProbe(t *testing.T) {
	ctx := context.Background()
	sasl := msg('R', append(binary.BigEndian.AppendUint32(nil, 10), []byte("SCRAM-SHA-256\x00\x00")...))
	for name, tc := range map[string]struct {
		ssl         byte
		reply       []byte
		state       string
		plainLogins bool
	}{
		"password":   {'N', sasl, protocol.OutsideAsksPassword, true},
		"cleartext":  {'N', msg('R', binary.BigEndian.AppendUint32(nil, 3)), protocol.OutsideAsksPassword, true},
		"trust":      {'N', msg('R', binary.BigEndian.AppendUint32(nil, 0)), protocol.OutsideNoPassword, true},
		"no role":    {'N', errMsg("28000", `role "rowsafe_outside_check" does not exist`), protocol.OutsideNoPassword, true},
		"hba reject": {'N', errMsg("28000", `no pg_hba.conf entry for host "203.0.113.9", user "rowsafe_outside_check", database "rowsafe_outside_check", no encryption`), protocol.OutsideRefusesLogins, false},
		"too many":   {'N', errMsg("53300", "sorry, too many clients already"), protocol.OutsideError, false},
		"http":       {0, nil, protocol.OutsideNotPostgres, false},
	} {
		r := Probe(ctx, fakeServer(t, tc.ssl, tc.reply), Options{})
		if !r.Reachable || r.State != tc.state || r.PlainLogins != tc.plainLogins || r.TLS {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestProbeFiltered(t *testing.T) {
	r := Probe(context.Background(), "192.0.2.1:5432", Options{DialTimeout: 200 * time.Millisecond,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}})
	if r.Reachable || r.State != protocol.OutsideFiltered {
		t.Errorf("%+v", r)
	}
}
