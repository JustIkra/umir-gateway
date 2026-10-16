// Source: umir-factory reference/durable/itest@26166c8ba197 (adapted: repository name gateway, no PostgreSQL and no cache Redis helpers)

// Package itest provides the shared integration-test infrastructure of the
// durable stack: RabbitMQ virtual hosts, Redis
// key prefixes and a fault-injecting TCP proxy. It compiles without any build
// tag, so integration tests of other packages can import it.
package itest
