package httpapi

import (
	"encoding/json"
	"net/http"
)

// Capability states reported by readiness.
const (
	CapabilityOK = "ok"
)

// NewReadyz serves the capability state of this process. HTTP is "ok" whenever the process answers;
// scheduler reports the state of the expiration scheduler. Neither changes the status code: the
// body names the replica and its capabilities and carries no address, secret or timing detail.
func NewReadyz(instance string, scheduler func() string, onWriteFailure func()) http.Handler {
	type body struct {
		Instance     string            `json:"instance"`
		Capabilities map[string]string `json:"capabilities"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(body{Instance: instance, Capabilities: map[string]string{"http": CapabilityOK, "scheduler": scheduler()}}); err != nil && onWriteFailure != nil {
			onWriteFailure()
		}
	})
}
