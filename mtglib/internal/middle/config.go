// Package middle implements the client side of the Telegram middle-proxy
// (RPC) protocol. It is needed to promote a sponsored channel (ad_tag):
// Telegram only shows the channel when the proxy talks to its middle proxies
// and sends the tag with every RPC_PROXY_REQ.
//
// The protocol follows the reference implementations
// https://github.com/TelegramMessenger/MTProxy and
// https://github.com/alexbers/mtprotoproxy.
package middle

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	ProxySecretURL   = "https://core.telegram.org/getProxySecret"
	ProxyConfigURLv4 = "https://core.telegram.org/getProxyConfig"
	ProxyConfigURLv6 = "https://core.telegram.org/getProxyConfigV6"

	UpdateEach = time.Hour

	// Telegram's proxy secret is 128 bytes; anything shorter than the 4-byte
	// key selector is surely broken.
	minSecretLen = 32
)

var (
	proxyForRe = regexp.MustCompile(`^\s*proxy_for\s+(-?\d+)\s+(\S+?);\s*$`)
	defaultRe  = regexp.MustCompile(`^\s*default\s+(-?\d+);\s*$`)
)

type Logger interface {
	Info(msg string)
	WarningError(msg string, err error)
}

type addrList struct {
	byDC      map[int][]string
	defaultDC int
}

func (a addrList) get(dc int) []string {
	if addrs := a.byDC[dc]; len(addrs) > 0 {
		return addrs
	}

	return a.byDC[a.defaultDC]
}

// Config holds the middle-proxy secret and address lists published by
// Telegram. It is safe for concurrent use.
type Config struct {
	mtx    sync.RWMutex
	secret []byte
	v4     addrList
	v6     addrList

	http   *http.Client
	logger Logger
	wg     sync.WaitGroup
}

func NewConfig(client *http.Client, logger Logger) *Config {
	return &Config{http: client, logger: logger}
}

// Secret returns the current proxy secret, or nil if it is not fetched yet.
func (c *Config) Secret() []byte {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	return c.secret
}

// Addresses returns middle-proxy addresses for the given (signed) DC. The
// order follows the IP preference: v4 first unless preferV6 is set.
func (c *Config) Addresses(dc int, useV4, useV6, preferV6 bool) []string {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	var v4, v6 []string

	if useV4 {
		v4 = c.v4.get(dc)
	}

	if useV6 {
		v6 = c.v6.get(dc)
	}

	out := make([]string, 0, len(v4)+len(v6))
	if preferV6 {
		out = append(append(out, v6...), v4...)
	} else {
		out = append(append(out, v4...), v6...)
	}

	return out
}

// Update fetches the proxy secret and both address lists once.
func (c *Config) Update(ctx context.Context) error {
	secret, err := c.fetch(ctx, ProxySecretURL)
	if err != nil {
		return fmt.Errorf("cannot fetch proxy secret: %w", err)
	}

	if len(secret) < minSecretLen {
		return fmt.Errorf("proxy secret is too short: %d bytes", len(secret))
	}

	v4, errV4 := c.fetchAddrs(ctx, ProxyConfigURLv4)
	v6, errV6 := c.fetchAddrs(ctx, ProxyConfigURLv6)

	if errV4 != nil && errV6 != nil {
		return errors.Join(errV4, errV6)
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.secret = secret

	if errV4 == nil {
		c.v4 = v4
	}

	if errV6 == nil {
		c.v6 = v6
	}

	return nil
}

// Run updates the config right away and then every UpdateEach until ctx is
// done.
func (c *Config) Run(ctx context.Context) {
	c.wg.Go(func() {
		ticker := time.NewTicker(UpdateEach)
		defer ticker.Stop()

		for {
			if err := c.Update(ctx); err != nil {
				c.logger.WarningError("cannot update middle proxy config", err)
			} else {
				c.logger.Info("middle proxy config is updated")
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
}

// Wait blocks until the updater started by Run stops.
func (c *Config) Wait() {
	c.wg.Wait()
}

func (c *Config) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	defer resp.Body.Close() //nolint: errcheck

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) //nolint: errcheck
		return nil, fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, url)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) //nolint: wrapcheck, mnd
}

func (c *Config) fetchAddrs(ctx context.Context, url string) (addrList, error) {
	body, err := c.fetch(ctx, url)
	if err != nil {
		return addrList{}, fmt.Errorf("cannot fetch %s: %w", url, err)
	}

	list, err := parseProxyConfig(body)
	if err != nil {
		return addrList{}, fmt.Errorf("cannot parse %s: %w", url, err)
	}

	return list, nil
}

func parseProxyConfig(body []byte) (addrList, error) {
	list := addrList{byDC: map[int][]string{}, defaultDC: 2} //nolint: mnd

	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()

		if m := proxyForRe.FindStringSubmatch(line); m != nil {
			dc, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}

			if _, _, err := net.SplitHostPort(m[2]); err != nil {
				continue
			}

			list.byDC[dc] = append(list.byDC[dc], m[2])

			continue
		}

		if m := defaultRe.FindStringSubmatch(line); m != nil {
			if dc, err := strconv.Atoi(m[1]); err == nil {
				list.defaultDC = dc
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return addrList{}, err //nolint: wrapcheck
	}

	if len(list.byDC) == 0 {
		return addrList{}, errors.New("no proxy_for entries")
	}

	return list, nil
}
