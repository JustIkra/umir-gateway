//go:build integration

package itest

import (
	"context"
	"testing"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
)

// TestVHostIsUsableAndRemoved opens a temporary virtual host, declares a queue in it and leaves the
// removal to the cleanup.
func TestVHostIsUsableAndRemoved(t *testing.T) {
	conn, err := amqp.Dial(NewVHost(t))
	if err != nil {
		t.Fatalf("dial the temporary virtual host: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()
	ch, err := conn.Channel()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ch.QueueDeclare("probe", false, true, true, false, nil); err != nil {
		t.Fatalf("declare: %v", err)
	}
}

// TestRedisPrefixIsolatesKeys writes under a prefix and expects the key to be gone after the cleanup of
// a sibling prefix test run; here only the write and read are checked.
func TestRedisPrefixIsolatesKeys(t *testing.T) {
	opts, err := redis.ParseURL(RedisLimiterURL(t))
	if err != nil {
		t.Fatal("invalid Redis URL")
	}
	client := redis.NewClient(opts)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	prefix := RedisPrefix(t)
	if err := client.Set(context.Background(), prefix+"probe", "1", 0).Err(); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got, err := client.Get(context.Background(), prefix+"probe").Result(); err != nil || got != "1" {
		t.Fatalf("get: %q %v", got, err)
	}
}
