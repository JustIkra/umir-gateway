package main

import (
	"testing"

	"github.com/JustIkra/umir-gateway/internal/config"
)

func TestListenAddressDefaultsToLoopback(t *testing.T) {
	values := operatorEnv(t)
	for host, want := range map[string]string{"": "127.0.0.1:8080", "0.0.0.0": "0.0.0.0:8080", "::": "[::]:8080"} {
		values["LISTEN_HOST"] = host
		cfg, err := config.Load(func(key string) string { return values[key] })
		if err != nil {
			t.Fatal(err)
		}
		if got := listenAddress(cfg); got != want {
			t.Errorf("LISTEN_HOST=%q: address %q, want %q", host, got, want)
		}
	}
}
