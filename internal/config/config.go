// Package config reads and validates gateway settings.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Config struct {
	Port string
	// ListenHost is the IP address the server binds: loopback by default, 0.0.0.0 or :: in a container.
	ListenHost   string
	ServingURL   *url.URL
	WarehouseURL *url.URL
	// FeedbackURL is the private feedback service; the gateway sends it only POST /api/feedback.
	FeedbackURL     *url.URL
	UpstreamTimeout time.Duration
	Operator        Operator
}

// Cookie modes of the operator session.
const (
	CookieModeSecure   = "secure"
	CookieModeLoopback = "loopback-development"
)

// Operator holds the account settings. Authentication is mandatory, so the mode, origin and store
// path are required.
type Operator struct {
	CookieMode string
	// PublicOrigin is the exact Origin browsers send, such as https://example.org.
	PublicOrigin string
	StorePath    string
	// The bootstrap values create the account file only when it does not exist yet.
	BootstrapLogin        string
	BootstrapDisplayName  string
	BootstrapPasswordHash string
	IdleTimeout           time.Duration
	AbsoluteTimeout       time.Duration
}

// Load reads settings through getenv, so callers and tests choose the source.
func Load(getenv func(string) string) (Config, error) {
	value := func(key, fallback string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return fallback
	}
	var cfg Config
	var err error
	cfg.Port = value("PORT", "8080")
	if n, convErr := strconv.Atoi(cfg.Port); convErr != nil || n < 1 || n > 65535 {
		return Config{}, fmt.Errorf("PORT: expected TCP port number")
	}
	// The healthcheck dials 127.0.0.1, so only loopback or all interfaces are accepted.
	cfg.ListenHost = value("LISTEN_HOST", "127.0.0.1")
	if ip := net.ParseIP(cfg.ListenHost); ip == nil || !ip.IsLoopback() && !ip.IsUnspecified() {
		return Config{}, errors.New("LISTEN_HOST: expected a loopback address, or 0.0.0.0 or :: for all interfaces in a container")
	}
	if cfg.ServingURL, err = upstreamURL("SERVING_URL", value("SERVING_URL", "http://serving:8080")); err != nil {
		return Config{}, err
	}
	if cfg.WarehouseURL, err = upstreamURL("WAREHOUSE_URL", value("WAREHOUSE_URL", "http://warehouse:8080")); err != nil {
		return Config{}, err
	}
	if cfg.FeedbackURL, err = upstreamURL("FEEDBACK_URL", value("FEEDBACK_URL", "http://feedback:8084")); err != nil {
		return Config{}, err
	}
	cfg.UpstreamTimeout, err = time.ParseDuration(value("UPSTREAM_TIMEOUT", "15s"))
	if err != nil || cfg.UpstreamTimeout <= 0 {
		return Config{}, fmt.Errorf("UPSTREAM_TIMEOUT: expected positive duration such as 15s")
	}
	if cfg.Operator, err = loadOperator(getenv, value); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// upstreamURL never echoes the raw value: it may carry credentials.
func upstreamURL(key, raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" ||
		target.User != nil || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" {
		return nil, fmt.Errorf("%s: expected http(s) URL with host and without credentials, query or fragment", key)
	}
	return target, nil
}

// loadOperator never echoes a value: a misplaced secret must not reach the startup log.
func loadOperator(getenv func(string) string, value func(key, fallback string) string) (Operator, error) {
	op := Operator{
		CookieMode:            getenv("OPERATOR_COOKIE_MODE"),
		PublicOrigin:          getenv("OPERATOR_PUBLIC_ORIGIN"),
		StorePath:             getenv("OPERATOR_STORE_PATH"),
		BootstrapLogin:        getenv("OPERATOR_BOOTSTRAP_LOGIN"),
		BootstrapDisplayName:  getenv("OPERATOR_BOOTSTRAP_DISPLAY_NAME"),
		BootstrapPasswordHash: getenv("OPERATOR_BOOTSTRAP_PASSWORD_HASH"),
	}
	if op.CookieMode != CookieModeSecure && op.CookieMode != CookieModeLoopback {
		return Operator{}, fmt.Errorf("OPERATOR_COOKIE_MODE: expected %s or %s", CookieModeSecure, CookieModeLoopback)
	}
	if err := checkOrigin(op.CookieMode, op.PublicOrigin); err != nil {
		return Operator{}, err
	}
	if !filepath.IsAbs(op.StorePath) || filepath.Clean(op.StorePath) != op.StorePath {
		return Operator{}, errors.New("OPERATOR_STORE_PATH: expected a clean absolute path to the account file")
	}
	var err error
	if op.IdleTimeout, err = duration("OPERATOR_IDLE_TIMEOUT", value("OPERATOR_IDLE_TIMEOUT", "30m")); err != nil {
		return Operator{}, err
	}
	if op.AbsoluteTimeout, err = duration("OPERATOR_ABSOLUTE_TIMEOUT", value("OPERATOR_ABSOLUTE_TIMEOUT", "8h")); err != nil {
		return Operator{}, err
	}
	if op.IdleTimeout > op.AbsoluteTimeout {
		return Operator{}, errors.New("OPERATOR_IDLE_TIMEOUT: must not exceed OPERATOR_ABSOLUTE_TIMEOUT")
	}
	return op, nil
}

func duration(key, raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: expected positive duration such as 30m", key)
	}
	return d, nil
}

// checkOrigin requires the serialized origin a browser sends: lowercase ASCII scheme and host, a port
// only when it is not the scheme's default, and nothing else.
func checkOrigin(mode, raw string) error {
	const key = "OPERATOR_PUBLIC_ORIGIN"
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Scheme+"://"+u.Host != raw || strings.ToLower(raw) != raw ||
		strings.ContainsFunc(raw, func(r rune) bool { return r > unicode.MaxASCII }) {
		return fmt.Errorf("%s: expected an ASCII origin such as https://example.org, without path, query or credentials", key)
	}
	if port := u.Port(); strings.HasSuffix(u.Host, ":") || port != "" && !validPort(u.Scheme, port) {
		return fmt.Errorf("%s: expected a port from 1 to 65535 without leading zeros, omitted when it is the default", key)
	}
	if mode == CookieModeSecure {
		if u.Scheme != "https" {
			return fmt.Errorf("%s: secure OPERATOR_COOKIE_MODE requires an https origin", key)
		}
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s: loopback-development OPERATOR_COOKIE_MODE requires an http origin with a loopback IP address", key)
	}
	return nil
}

func validPort(scheme, port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == port &&
		(scheme != "https" || n != 443) && (scheme != "http" || n != 80)
}
