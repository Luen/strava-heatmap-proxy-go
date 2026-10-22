package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testCookies() []*http.Cookie {
	return []*http.Cookie{
		{Name: "CloudFront-Signature", Value: "sig"},
		{Name: "CloudFront-Policy", Value: "policy"},
		{Name: "CloudFront-Key-Pair-Id", Value: "key-pair"},
		{Name: "_strava_idcf", Value: "idcf"},
	}
}

func healthyClient() *StravaSessionClient {
	return &StravaSessionClient{
		sessionIdentifier:           "test-session",
		cloudFrontCookies:           testCookies(),
		cloudFrontCookiesExpiration: time.Now().Add(time.Hour),
	}
}

func stubProxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Proxied", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	})
}

func decodeHealth(t *testing.T, rec *httptest.ResponseRecorder) healthResponse {
	t.Helper()
	var resp healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode health response: %v (body: %q)", err, rec.Body.String())
	}
	return resp
}

func TestHealthHealthy(t *testing.T) {
	client := healthyClient()
	handler := rootHandler(client, stubProxy(), nil, false)

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
	resp := decodeHealth(t, rec)
	if resp.Status != "ok" {
		t.Fatalf("expected status ok, got %q", resp.Status)
	}
	if resp.Error != "" {
		t.Fatalf("expected no error, got %q", resp.Error)
	}
	want := client.cloudFrontCookiesExpiration.UTC().Format(time.RFC3339)
	if resp.ExpiresAt != want {
		t.Fatalf("expected expires_at %q, got %q", want, resp.ExpiresAt)
	}
}

func TestHealthExpired(t *testing.T) {
	client := healthyClient()
	client.cloudFrontCookiesExpiration = time.Now().Add(-time.Hour)
	handler := rootHandler(client, stubProxy(), nil, false)

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	resp := decodeHealth(t, rec)
	if resp.Status != "error" || resp.Error == "" {
		t.Fatalf("expected error status with message, got %+v", resp)
	}
	if resp.ExpiresAt == "" {
		t.Fatalf("expected expires_at to be set for expired cookies, got %+v", resp)
	}
}

func TestHealthNoCookies(t *testing.T) {
	handler := rootHandler(&StravaSessionClient{}, stubProxy(), nil, false)

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	resp := decodeHealth(t, rec)
	if resp.Status != "error" || resp.Error == "" {
		t.Fatalf("expected error status with message, got %+v", resp)
	}
}

func TestHealthZeroExpiry(t *testing.T) {
	client := healthyClient()
	client.cloudFrontCookiesExpiration = time.Time{}
	handler := rootHandler(client, stubProxy(), nil, false)

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	if resp := decodeHealth(t, rec); resp.Status != "error" {
		t.Fatalf("expected error status, got %+v", resp)
	}
}

func TestHealthHead(t *testing.T) {
	handler := rootHandler(healthyClient(), stubProxy(), nil, false)

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodHead, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected empty body for HEAD, got %q", rec.Body.String())
	}
}

func TestHealthBypassesCORS(t *testing.T) {
	allowed, err := parseAllowedOrigins(`["https://gpx.studio"]`)
	if err != nil {
		t.Fatalf("parseAllowedOrigins: %v", err)
	}
	handler := rootHandler(healthyClient(), stubProxy(), allowed, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://unlisted.example")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected health check to bypass CORS and return 200, got %d", rec.Code)
	}
}

func TestNonRootFallsThroughToProxy(t *testing.T) {
	handler := rootHandler(healthyClient(), stubProxy(), nil, false)

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/identified/globalheat/all/bluered/1/2/3.png", nil))

	if rec.Header().Get("X-Proxied") != "true" || rec.Body.String() != "proxied" {
		t.Fatalf("expected non-root request to reach proxy, got code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestNonGetRootFallsThroughToProxy(t *testing.T) {
	handler := rootHandler(healthyClient(), stubProxy(), nil, false)

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	if rec.Header().Get("X-Proxied") != "true" {
		t.Fatalf("expected POST / to reach proxy, got code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestHealthMethod(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		client  *StravaSessionClient
		wantErr bool
	}{
		{"healthy", &StravaSessionClient{sessionIdentifier: "s", cloudFrontCookies: testCookies(), cloudFrontCookiesExpiration: now.Add(time.Hour)}, false},
		{"no session", &StravaSessionClient{cloudFrontCookies: testCookies(), cloudFrontCookiesExpiration: now.Add(time.Hour)}, true},
		{"too few cookies", &StravaSessionClient{sessionIdentifier: "s", cloudFrontCookies: testCookies()[:3], cloudFrontCookiesExpiration: now.Add(time.Hour)}, true},
		{"zero expiry", &StravaSessionClient{sessionIdentifier: "s", cloudFrontCookies: testCookies()}, true},
		{"expired", &StravaSessionClient{sessionIdentifier: "s", cloudFrontCookies: testCookies(), cloudFrontCookiesExpiration: now.Add(-time.Minute)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.client.health(now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("health() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOriginAllowlist(t *testing.T) {
	allowlist, err := parseAllowedOrigins(`["https://gpx.studio","https://*.wanderstories.space"]`)
	if err != nil {
		t.Fatalf("parseAllowedOrigins: %v", err)
	}
	tests := []struct {
		origin string
		want   bool
	}{
		{"https://gpx.studio", true},
		{"https://wanderstories.space", true},        // apex included
		{"https://studio.wanderstories.space", true}, // subdomain
		{"https://maps.wanderstories.space", true},
		{"https://deep.maps.wanderstories.space", true},
		{"https://evilwanderstories.space", false},      // lookalike, no dot boundary
		{"https://wanderstories.space.evil.com", false}, // domain as subdomain of attacker
		{"http://studio.wanderstories.space", false},    // wrong scheme
		{"https://example.com", false},                  // unrelated
		{"https://gpx.studio.evil.com", false},          // exact entry is not a suffix
		{"", false},
		{"not a url", false},
	}
	for _, tt := range tests {
		if got := allowlist.allows(tt.origin); got != tt.want {
			t.Errorf("allows(%q) = %v, want %v", tt.origin, got, tt.want)
		}
	}
}

func TestOriginAllowlistWithoutDot(t *testing.T) {
	// "https://*wanderstories.space" (no dot) is equivalent to "https://*.wanderstories.space".
	allowlist, err := parseAllowedOrigins(`["https://*wanderstories.space"]`)
	if err != nil {
		t.Fatalf("parseAllowedOrigins: %v", err)
	}
	if !allowlist.allows("https://studio.wanderstories.space") {
		t.Error("expected subdomain to be allowed")
	}
	if allowlist.allows("https://evilwanderstories.space") {
		t.Error("expected lookalike domain to be rejected")
	}
}

func TestParseAllowedOriginsInvalidWildcard(t *testing.T) {
	for _, input := range []string{
		`["https://*"]`,
		`["https://foo.*.example.com"]`,
		`["*"]`,
	} {
		if _, err := parseAllowedOrigins(input); err == nil {
			t.Errorf("parseAllowedOrigins(%s): expected error, got nil", input)
		}
	}
}

func TestWildcardOriginThroughHandler(t *testing.T) {
	allowlist, err := parseAllowedOrigins(`["https://gpx.studio","https://*.wanderstories.space"]`)
	if err != nil {
		t.Fatalf("parseAllowedOrigins: %v", err)
	}
	handler := rootHandler(healthyClient(), stubProxy(), allowlist, false)

	for _, origin := range []string{"https://maps.wanderstories.space", "https://wanderstories.space", "https://gpx.studio"} {
		req := httptest.NewRequest(http.MethodGet, "/identified/globalheat/all/bluered/1/2/3.png", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Header().Get("X-Proxied") != "true" {
			t.Errorf("origin %q: expected proxy, got code=%d", origin, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/identified/globalheat/all/bluered/1/2/3.png", nil)
	req.Header.Set("Origin", "https://evilwanderstories.space")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("lookalike origin: expected 403, got %d", rec.Code)
	}
}
