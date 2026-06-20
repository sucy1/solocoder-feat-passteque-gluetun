package dns

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/qdm12/dns/v2/pkg/server"
)

type fallbackDialer struct {
	dialers []server.Dialer
}

func newFallbackDialer(dialers ...server.Dialer) *fallbackDialer {
	return &fallbackDialer{
		dialers: dialers,
	}
}

func (d *fallbackDialer) String() string {
	names := make([]string, len(d.dialers))
	for i, dialer := range d.dialers {
		names[i] = dialer.String()
	}
	return "fallback(" + strings.Join(names, ", ") + ")"
}

func (d *fallbackDialer) ReusableConnsSupported() bool {
	return false
}

func (d *fallbackDialer) Addresses() []string {
	var addresses []string
	for _, dialer := range d.dialers {
		addresses = append(addresses, dialer.Addresses()...)
	}
	return addresses
}

func (d *fallbackDialer) Dial(ctx context.Context, network, address string) (
	conn net.Conn, err error,
) {
	return &fallbackConn{
		ctx:     ctx,
		dialers: d.dialers,
		network: network,
		address: address,
	}, nil
}

type fallbackConn struct {
	ctx        context.Context
	dialers    []server.Dialer
	network    string
	address    string
	writeBuf   bytes.Buffer
	readBuf    bytes.Buffer
	readOnce   sync.Once
	readErr    error
	deadline   time.Time
	closed     bool
	closeMutex sync.Mutex
}

func (c *fallbackConn) Read(b []byte) (n int, err error) {
	c.readOnce.Do(c.doFallbackRead)
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.readBuf.Read(b)
}

func (c *fallbackConn) Write(b []byte) (n int, err error) {
	return c.writeBuf.Write(b)
}

func (c *fallbackConn) Close() error {
	c.closeMutex.Lock()
	defer c.closeMutex.Unlock()
	c.closed = true
	return nil
}

func (c *fallbackConn) LocalAddr() net.Addr {
	return nil
}

func (c *fallbackConn) RemoteAddr() net.Addr {
	return nil
}

func (c *fallbackConn) SetDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

func (c *fallbackConn) SetReadDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

func (c *fallbackConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *fallbackConn) doFallbackRead() {
	ctx := c.ctx
	if !c.deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, c.deadline)
		defer cancel()
	}

	writeData := c.writeBuf.Bytes()

	var errs []error
	for i, dialer := range c.dialers {
		conn, err := dialer.Dial(ctx, c.network, c.address)
		if err != nil {
			errs = append(errs, fmt.Errorf("dialer %d (%s): dial: %w", i, dialer, err))
			continue
		}

		if !c.deadline.IsZero() {
			_ = conn.SetDeadline(c.deadline)
		}

		_, err = conn.Write(writeData)
		if err != nil {
			_ = conn.Close()
			errs = append(errs, fmt.Errorf("dialer %d (%s): write: %w", i, dialer, err))
			continue
		}

		_, err = c.readBuf.ReadFrom(conn)
		_ = conn.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("dialer %d (%s): read: %w", i, dialer, err))
			continue
		}

		return
	}

	if len(errs) > 0 {
		errStrs := make([]string, len(errs))
		for i, err := range errs {
			errStrs[i] = err.Error()
		}
		c.readErr = fmt.Errorf("all dialers failed: %s", strings.Join(errStrs, "; "))
	}
}
