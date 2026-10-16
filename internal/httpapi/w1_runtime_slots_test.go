package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/expiration"
	"github.com/JustIkra/umir-gateway/internal/journal"
)

const (
	slotsEpoch = "11111111-1111-4111-8111-111111111111"
	slotsOrg   = "22222222-2222-4222-8222-222222222222"
	slotsKey   = "w1-slots-key"
)

// slotsAuth is an Auth whose registry always holds the restaurant of the current call.
type slotsAuth struct {
	tenant, operation string
}

func (a *slotsAuth) ControlToken(context.Context, string) (ServiceClaims, error) {
	return ServiceClaims{Kind: "service", Subject: "service:auth", Caller: "umir-auth", Audience: []string{"umir-gateway"}, Permissions: []string{a.operation}, Operation: a.operation, TenantID: a.tenant, OrgID: slotsOrg, Epoch: slotsEpoch, LifecycleVersion: "1"}, nil
}

func (a *slotsAuth) Registry(context.Context) (expiration.Registry, error) {
	var entry expiration.RegistryEntry
	entry.Restaurant = expiration.Restaurant{RestaurantID: a.tenant, OrgID: slotsOrg, Lifecycle: "registering", LifecycleVersion: "1"}
	entry.Settings.TimeZone, entry.Settings.Version = "Europe/Moscow", "1"
	return expiration.Registry{Complete: true, Entries: []expiration.RegistryEntry{entry}}, nil
}
func (a *slotsAuth) ReadMark() uint64 { return 0 }
func (a *slotsAuth) SharedRegistry(ctx context.Context) (expiration.Registry, uint64, error) {
	registry, err := a.Registry(ctx)
	return registry, 1, err
}
func (a *slotsAuth) RegistryAfter(ctx context.Context, _ uint64) (expiration.Registry, error) {
	return a.Registry(ctx)
}
func (a *slotsAuth) RegistrySnapshot() (expiration.Registry, bool) {
	return expiration.Registry{}, false
}
func (a *slotsAuth) RegistrySnapshotWithin(time.Duration) (expiration.Registry, bool) {
	return expiration.Registry{}, false
}

func slotsTenant(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }

func (a *slotsAuth) call(g *GatewayRuntime, method string, i int) int {
	a.tenant = slotsTenant(i)
	a.operation = "runtime.register"
	body := `{"operationID":"55555555-5555-4555-8555-555555555555","expectedEpoch":"` + slotsEpoch + `","lifecycleVersion":"1","settings":{"timeZone":"Europe/Moscow","settingsVersion":"1"}}`
	if method == http.MethodDelete {
		a.operation = "runtime.close"
		body = `{"operationID":"55555555-5555-4555-8555-555555555555","expectedEpoch":"` + slotsEpoch + `","lifecycleVersion":"1"}`
	}
	r := httptest.NewRequest(method, "/internal/gateway/v2/r/"+a.tenant+"/registry", strings.NewReader(body))
	r.Header.Set("X-Umir-Service-Key", slotsKey)
	r.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w.Code
}

func TestW1RuntimeAcceptsTenThousandLiveAndTenThousandClosed(t *testing.T) {
	changes, err := journal.NewScoped(slotsEpoch, 16, 10000, 16, time.Now, func() string { return "cursor" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth := &slotsAuth{}
	g, err := NewGatewayRuntime(RuntimeOptions{Auth: auth, ServiceKey: slotsKey, Epoch: slotsEpoch, TZDataVersion: "test", Changes: changes})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10000 {
		if code := auth.call(g, http.MethodPut, i); code != http.StatusOK {
			t.Fatalf("live registration %d: %d", i, code)
		}
	}
	for i := 10000; i < 20000; i++ {
		if code := auth.call(g, http.MethodDelete, i); code != http.StatusOK {
			t.Fatalf("closed registration %d: %d", i, code)
		}
	}
	if code := auth.call(g, http.MethodPut, 20000); code != http.StatusServiceUnavailable {
		t.Fatalf("the 10 001st live registration: %d, want 503", code)
	}
	if code := auth.call(g, http.MethodDelete, 20001); code != http.StatusServiceUnavailable {
		t.Fatalf("the 10 001st closed registration: %d, want 503", code)
	}
	// Closing a live restaurant moves it to the other class; with that class full the close is refused
	// and the restaurant stays live.
	if code := auth.call(g, http.MethodDelete, 0); code != http.StatusServiceUnavailable {
		t.Fatalf("closing a live restaurant while the closed class is full: %d, want 503", code)
	}
}
