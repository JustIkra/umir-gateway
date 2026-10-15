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
	AuthURL               *url.URL
	AuthServiceKey        string
	AuthRuntimeServiceKey string
	PrivateListenHost     string
	PrivatePort           string
	AuthTimeout           time.Duration
	ServingServiceKey     string
	WarehouseServiceKey   string
	FeedbackServiceKey    string
	Port                  string
	// ListenHost is the IP address the server binds: loopback by default, 0.0.0.0 or :: in a container.
	ListenHost   string
	ServingURL   *url.URL
	WarehouseURL *url.URL
	// FeedbackURL is the private feedback service; the gateway sends it only POST /api/feedback.
	FeedbackURL     *url.URL
	UpstreamTimeout time.Duration
	// JournalCapacity is how many latest entries the change journal keeps.
	JournalCapacity int
	// ExpirationRunInterval paces the expiration runs the gateway starts on the warehouse.
	ExpirationRunInterval time.Duration
	Operator              Operator
	// RegistryRefreshInterval paces the Auth registry refresh; RegistryMaxAge bounds how old the last
	// successful snapshot may be for runtime readiness. Both belong to the Auth mode.
	RegistryRefreshInterval time.Duration
	RegistryMaxAge          time.Duration
	// InstanceID names this replica in /readyz; empty means the process generates one.
	InstanceID string
}

// maxJournalCapacity keeps the journal buffer, allocated at start, within a few megabytes.
const maxJournalCapacity = 100_000

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
	cfg.JournalCapacity, err = strconv.Atoi(value("JOURNAL_CAPACITY", "1000"))
	if err != nil || cfg.JournalCapacity < 1 || cfg.JournalCapacity > maxJournalCapacity {
		return Config{}, fmt.Errorf("JOURNAL_CAPACITY: expected an integer from 1 to %d", maxJournalCapacity)
	}
	cfg.ExpirationRunInterval, err = time.ParseDuration(value("EXPIRATION_RUN_INTERVAL", "1s"))
	if err != nil || cfg.ExpirationRunInterval <= 0 {
		return Config{}, fmt.Errorf("EXPIRATION_RUN_INTERVAL: expected positive duration such as 1s")
	}
	if raw := getenv("AUTH_URL"); raw != "" {
		if cfg.AuthURL, err = upstreamURL("AUTH_URL", raw); err != nil {
			return Config{}, err
		}
		if cfg.AuthURL.Path != "" && cfg.AuthURL.Path != "/" {
			return Config{}, errors.New("AUTH_URL: expected an origin without a path")
		}
		cfg.AuthServiceKey = getenv("AUTH_SERVICE_KEY")
		if cfg.AuthServiceKey == "" || strings.ContainsAny(cfg.AuthServiceKey, " \t\r\n") {
			return Config{}, errors.New("AUTH_SERVICE_KEY: private transport credential is required")
		}
		isolated := getenv("AUTH_ISOLATED_TEST_NETWORK")
		if isolated != "" && isolated != "true" && isolated != "false" {
			return Config{}, errors.New("AUTH_ISOLATED_TEST_NETWORK: expected true or false")
		}
		ip := net.ParseIP(cfg.AuthURL.Hostname())
		if cfg.AuthURL.Scheme == "http" && (ip == nil || !ip.IsLoopback()) && isolated != "true" {
			return Config{}, errors.New("AUTH_URL: HTTPS is required outside loopback or AUTH_ISOLATED_TEST_NETWORK=true")
		}
		for key, destination := range map[string]*string{"SERVING_SERVICE_KEY": &cfg.ServingServiceKey, "WAREHOUSE_SERVICE_KEY": &cfg.WarehouseServiceKey, "FEEDBACK_SERVICE_KEY": &cfg.FeedbackServiceKey} {
			*destination = getenv(key)
			if *destination == "" || strings.ContainsAny(*destination, " \t\r\n") {
				return Config{}, fmt.Errorf("%s: private transport credential is required", key)
			}
		}
		for key, target := range map[string]*url.URL{"SERVING_URL": cfg.ServingURL, "WAREHOUSE_URL": cfg.WarehouseURL, "FEEDBACK_URL": cfg.FeedbackURL} {
			ip := net.ParseIP(target.Hostname())
			if (target.Path != "" && target.Path != "/") || target.Scheme == "http" && (ip == nil || !ip.IsLoopback()) && isolated != "true" {
				return Config{}, fmt.Errorf("%s: scoped transport requires an origin and HTTPS outside isolated tests", key)
			}
		}
		cfg.AuthRuntimeServiceKey = getenv("AUTH_RUNTIME_SERVICE_KEY")
		if cfg.AuthRuntimeServiceKey == "" || strings.ContainsAny(cfg.AuthRuntimeServiceKey, " \t\r\n") || cfg.AuthRuntimeServiceKey == cfg.AuthServiceKey {
			return Config{}, errors.New("AUTH_RUNTIME_SERVICE_KEY: a separate Auth-to-Gateway transport credential is required")
		}
		cfg.PrivateListenHost = value("PRIVATE_LISTEN_HOST", "127.0.0.1")
		if ip := net.ParseIP(cfg.PrivateListenHost); ip == nil || !ip.IsLoopback() && !ip.IsUnspecified() {
			return Config{}, errors.New("PRIVATE_LISTEN_HOST: expected loopback or unspecified IP")
		}
		cfg.PrivatePort = value("PRIVATE_PORT", "8086")
		if n, err := strconv.Atoi(cfg.PrivatePort); err != nil || n < 1 || n > 65535 || cfg.PrivatePort == cfg.Port {
			return Config{}, errors.New("PRIVATE_PORT: expected a separate TCP port")
		}
		cfg.AuthTimeout, err = duration("AUTH_TIMEOUT", value("AUTH_TIMEOUT", "5s"))
		if err != nil {
			return Config{}, err
		}
		if err := loadRegistrySettings(&cfg, getenv, value); err != nil {
			return Config{}, err
		}
	} else if getenv("AUTH_SERVICE_KEY") != "" || getenv("AUTH_TIMEOUT") != "" || getenv("AUTH_ISOLATED_TEST_NETWORK") != "" {
		return Config{}, errors.New("AUTH_URL: required with Auth settings")
	}
	if cfg.Operator, err = loadOperator(getenv, value, cfg.AuthURL != nil); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Bounds of the Auth registry refresh. The snapshot must survive a few missed refreshes, so its
// maximum age is at least registryMinAgeIntervals refresh intervals.
const (
	minRegistryRefreshInterval = time.Second
	maxRegistryRefreshInterval = 30 * time.Second
	registryMinAgeIntervals    = 3
	maxInstanceIDLength        = 128
)

// loadRegistrySettings reads the Auth-mode readiness settings. It never echoes a value.
func loadRegistrySettings(cfg *Config, getenv func(string) string, value func(key, fallback string) string) error {
	var err error
	cfg.RegistryRefreshInterval, err = duration("GATEWAY_REGISTRY_REFRESH_INTERVAL", value("GATEWAY_REGISTRY_REFRESH_INTERVAL", "2s"))
	if err != nil || cfg.RegistryRefreshInterval < minRegistryRefreshInterval || cfg.RegistryRefreshInterval > maxRegistryRefreshInterval {
		return errors.New("GATEWAY_REGISTRY_REFRESH_INTERVAL: expected a duration from 1s to 30s")
	}
	cfg.RegistryMaxAge, err = duration("GATEWAY_REGISTRY_MAX_AGE", value("GATEWAY_REGISTRY_MAX_AGE", "30s"))
	if err != nil {
		return err
	}
	if cfg.RegistryMaxAge < registryMinAgeIntervals*cfg.RegistryRefreshInterval {
		return errors.New("GATEWAY_REGISTRY_MAX_AGE: must be at least three GATEWAY_REGISTRY_REFRESH_INTERVAL periods")
	}
	cfg.InstanceID = getenv("GATEWAY_INSTANCE_ID")
	if cfg.InstanceID != "" && !validInstanceID(cfg.InstanceID) {
		return errors.New("GATEWAY_INSTANCE_ID: expected 1 to 128 ASCII letters, digits, '.', '_', ':' or '-'")
	}
	return nil
}

func validInstanceID(id string) bool {
	if len(id) > maxInstanceIDLength {
		return false
	}
	for _, r := range id {
		letterOrDigit := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !letterOrDigit && !strings.ContainsRune("._:-", r) {
			return false
		}
	}
	return true
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
func loadOperator(getenv func(string) string, value func(key, fallback string) string, remote bool) (Operator, error) {
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
	if remote {
		op.StorePath, op.BootstrapLogin, op.BootstrapDisplayName, op.BootstrapPasswordHash = "", "", "", ""
		return op, nil
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
