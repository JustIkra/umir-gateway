// Package config reads and validates gateway settings.
package config

import (
	"fmt"
	"net/url"
	"strconv"
	"time"
)

type Config struct {
	Port            string
	ServingURL      *url.URL
	WarehouseURL    *url.URL
	UpstreamTimeout time.Duration
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
