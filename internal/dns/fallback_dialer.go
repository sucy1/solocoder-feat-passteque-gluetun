package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/qdm12/dns/v2/pkg/provider"
)

type dohFallbackDialer struct {
	urls     []string
	ipVersion string
	timeout  time.Duration
}

func newDoHFallbackDialer(urls []string, timeout time.Duration, ipVersion string) *dohFallbackDialer {
	return &dohFallbackDialer{
		urls:      urls,
		timeout:   timeout,
		ipVersion: ipVersion,
	}
}

func (d *dohFallbackDialer) String() string {
	return "doh-fallback(" + strings.Join(d.urls, ", ") + ")"
}

func (d *dohFallbackDialer) ReusableConnsSupported() bool {
	return false
}

func (d *dohFallbackDialer) Addresses() []string {
	return d.urls
}

func (d *dohFallbackDialer) Dial(ctx context.Context, network, address string) (
	conn net.Conn, err error,
) {
	transport := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: d.timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if d.ipVersion == "ipv6" {
				return (&net.Dialer{
					Timeout: d.timeout,
				}).DialContext(ctx, "tcp6", addr)
			}
			return (&net.Dialer{
				Timeout: d.timeout,
			}).DialContext(ctx, "tcp4", addr)
		},
	}
	httpClient := &http.Client{
		Timeout:   d.timeout,
		Transport: transport,
	}

	return &dohFallbackConn{
		ctx:        ctx,
		urls:       d.urls,
		httpClient: httpClient,
	}, nil
}

type dohFallbackConn struct {
	ctx        context.Context
	urls       []string
	httpClient *http.Client
	writeBuf   bytes.Buffer
	readBuf    bytes.Buffer
	readOnce   sync.Once
	readErr    error
	deadline   time.Time
	closed     bool
	closeMutex sync.Mutex
}

const dohDNSMessageContentType = "application/dns-message"

func (c *dohFallbackConn) Read(b []byte) (n int, err error) {
	c.readOnce.Do(c.doFallbackRead)
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.readBuf.Read(b)
}

func (c *dohFallbackConn) Write(b []byte) (n int, err error) {
	return c.writeBuf.Write(b)
}

func (c *dohFallbackConn) Close() error {
	c.closeMutex.Lock()
	defer c.closeMutex.Unlock()
	c.closed = true
	c.httpClient.CloseIdleConnections()
	return nil
}

func (c *dohFallbackConn) LocalAddr() net.Addr {
	return nil
}

func (c *dohFallbackConn) RemoteAddr() net.Addr {
	return nil
}

func (c *dohFallbackConn) SetDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

func (c *dohFallbackConn) SetReadDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

func (c *dohFallbackConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *dohFallbackConn) doFallbackRead() {
	ctx := c.ctx
	if !c.deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, c.deadline)
		defer cancel()
	}

	writeData := c.writeBuf.Bytes()
	const lengthPrefixSize = 2
	if len(writeData) < lengthPrefixSize {
		c.readErr = fmt.Errorf("DNS query too short: %d bytes", len(writeData))
		return
	}

	dnsMessage := writeData[lengthPrefixSize:]

	var errs []error
	for i, url := range c.urls {
		responseBody, err := c.doHTTPRequest(ctx, url, dnsMessage)
		if err != nil {
			errs = append(errs, fmt.Errorf("url %d (%s): %w", i, url, err))
			continue
		}

		responseLength := uint16(len(responseBody)) //nolint:gosec
		err = binary.Write(&c.readBuf, binary.BigEndian, responseLength)
		if err != nil {
			c.readErr = fmt.Errorf("writing response length prefix: %w", err)
			return
		}

		_, err = c.readBuf.Write(responseBody)
		if err != nil {
			c.readErr = fmt.Errorf("writing response body: %w", err)
			return
		}

		return
	}

	if len(errs) > 0 {
		errStrs := make([]string, len(errs))
		for i, err := range errs {
			errStrs[i] = err.Error()
		}
		c.readErr = fmt.Errorf("all DoH URLs failed: %s", strings.Join(errStrs, "; "))
	}
}

func (c *dohFallbackConn) doHTTPRequest(ctx context.Context, url string, dnsMessage []byte) (
	body []byte, err error,
) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(dnsMessage))
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	request.Header.Set("Content-Type", dohDNSMessageContentType)
	request.Header.Set("Accept", dohDNSMessageContentType)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("performing HTTP request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %s", response.Status)
	}

	body, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading HTTP response body: %w", err)
	}

	return body, nil
}

func providersToDoHURLs(providers []provider.Provider) (urls []string) {
	urls = make([]string, 0, len(providers))
	for _, p := range providers {
		if p.DoH.URL != "" {
			urls = append(urls, p.DoH.URL)
		}
	}
	return urls
}
