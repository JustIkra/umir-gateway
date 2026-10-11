// Package config reads and validates gateway settings.
package config

import (
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// writeAllowance is the default time left after the upstream budget to deliver a response,
// including the gateway's own timeout error.
const writeAllowance = 5 * time.Second

type Config struct {
	Port            string
	ServingURL      *url.URL
	WarehouseURL    *url.URL
	UpstreamTimeout time.Duration
	// WriteTimeout bounds writing a response to the client, counted from the request headers.
	WriteTimeout time.Duration
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
	if cfg.ServingURL, err = upstreamURL("SERVING_URL", value("SERVING_URL", "http://serving:8080")); err != nil {
		return Config{}, err
	}
	if cfg.WarehouseURL, err = upstreamURL("WAREHOUSE_URL", value("WAREHOUSE_URL", "http://warehouse:8080")); err != nil {
		return Config{}, err
	}
	cfg.UpstreamTimeout, err = time.ParseDuration(value("UPSTREAM_TIMEOUT", "15s"))
	if err != nil || cfg.UpstreamTimeout <= 0 {
		return Config{}, fmt.Errorf("UPSTREAM_TIMEOUT: expected positive duration such as 15s")
	}
	cfg.WriteTimeout = cfg.UpstreamTimeout + writeAllowance
	if cfg.WriteTimeout <= cfg.UpstreamTimeout {
		return Config{}, fmt.Errorf("UPSTREAM_TIMEOUT: too long to leave time for writing the response")
	}
	if raw := getenv("WRITE_TIMEOUT"); raw != "" {
		cfg.WriteTimeout, err = time.ParseDuration(raw)
		if err != nil || cfg.WriteTimeout <= cfg.UpstreamTimeout {
			return Config{}, fmt.Errorf("WRITE_TIMEOUT: expected duration longer than UPSTREAM_TIMEOUT")
		}
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
