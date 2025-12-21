package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"time"
)

type Config struct {
	Timeout    time.Duration
	SNI        string
	HostHeader string
	Path       string
}

type Result struct {
	IP        netip.Addr        `json:"ip"`
	OK        bool              `json:"ok"`
	Status    int               `json:"status"`
	Error     string            `json:"error,omitempty"`
	ConnectMS int64             `json:"connect_ms"`
	TLSMS     int64             `json:"tls_ms"`
	TTFBMS    int64             `json:"ttfb_ms"`
	TotalMS   int64             `json:"total_ms"`
	Trace     map[string]string `json:"trace,omitempty"`
	When      time.Time         `json:"when"`
}

type Prober struct {
	cfg    Config
	client *http.Client
}

// NewProber creates a reusable, direct-connection (no proxy) prober.
func NewProber(cfg Config) *Prober {
	if cfg.Path == "" {
		cfg.Path = "/cdn-cgi/trace"
	}
	if !strings.HasPrefix(cfg.Path, "/") {
		cfg.Path = "/" + cfg.Path
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}

	transport := &http.Transport{
		Proxy: nil, // critical: ignore HTTP(S)_PROXY and NO_PROXY env vars
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			ServerName: cfg.SNI,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	return &Prober{cfg: cfg, client: client}
}

// ProbeHTTPTrace probes https://<ip>/<path> with SNI/HostHeader.
func (p *Prober) ProbeHTTPTrace(ctx context.Context, ip netip.Addr) Result {
	start := time.Now()
	res := Result{
		IP:   ip,
		When: start,
	}

	targetHost := ip.String()
	// URL host must wrap IPv6 in brackets.
	if ip.Is6() {
		targetHost = "[" + targetHost + "]"
	}

	url := "https://" + targetHost + p.cfg.Path

	var (
		connectStart time.Time
		tlsStart     time.Time
		gotFirstByte time.Time
		connectDur   time.Duration
		tlsDur       time.Duration
	)

	trace := &httptrace.ClientTrace{
		ConnectStart: func(network, addr string) {
			connectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			if !connectStart.IsZero() {
				connectDur = time.Since(connectStart)
			}
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if !tlsStart.IsZero() {
				tlsDur = time.Since(tlsStart)
			}
		},
		GotFirstResponseByte: func() {
			gotFirstByte = time.Now()
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, url, nil)
	if err != nil {
		res.Error = err.Error()
		res.TotalMS = time.Since(start).Milliseconds()
		return res
	}
	if p.cfg.HostHeader != "" {
		req.Host = p.cfg.HostHeader
	}
	req.Header.Set("User-Agent", "mcis/0.1")
	req.Header.Set("Accept", "text/plain")

	httpRes, err := p.client.Do(req)
	if err != nil {
		// Normalize common context timeout.
		if errors.Is(err, context.DeadlineExceeded) {
			res.Error = "timeout"
		} else {
			res.Error = err.Error()
		}
		res.TotalMS = time.Since(start).Milliseconds()
		res.ConnectMS = connectDur.Milliseconds()
		res.TLSMS = tlsDur.Milliseconds()
		if !gotFirstByte.IsZero() {
			res.TTFBMS = gotFirstByte.Sub(start).Milliseconds()
		}
		return res
	}
	defer func() { _ = httpRes.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(httpRes.Body, 64*1024))
	res.Status = httpRes.StatusCode
	res.ConnectMS = connectDur.Milliseconds()
	res.TLSMS = tlsDur.Milliseconds()
	if !gotFirstByte.IsZero() {
		res.TTFBMS = gotFirstByte.Sub(start).Milliseconds()
	}
	res.TotalMS = time.Since(start).Milliseconds()

	if httpRes.StatusCode >= 200 && httpRes.StatusCode < 300 {
		res.OK = true
		res.Trace = parseTrace(string(body))
	} else {
		res.OK = false
		res.Error = fmt.Sprintf("http_status_%d", httpRes.StatusCode)
	}
	return res
}

func parseTrace(s string) map[string]string {
	m := make(map[string]string)
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k != "" {
			m[k] = v
		}
	}
	return m
}
