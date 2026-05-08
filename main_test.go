package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func testConfig() Config {
	return Config{
		Port:          "8080",
		AuthURL:       "https://example.com/auth",
		TokenURL:      "https://example.com/token",
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
		RedirectURL:   "http://localhost:8080/auth/callback",
		Scopes:        "openid profile email",
		RoleClaim:     "roles",
		AdminRole:     "admin",
		SessionSecret: "0123456789abcdef",
	}
}

func TestSessionRoundTrip(t *testing.T) {
	manager := NewSessionManager("0123456789abcdef")
	source := Session{Subject: "123", Name: "alice", Roles: []string{"admin"}, Expires: time.Now().Add(time.Minute).Unix()}
	encoded, err := manager.Encode(source)
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	decoded, err := manager.Decode(encoded)
	if err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if decoded.Subject != source.Subject || decoded.Name != source.Name || decoded.Roles[0] != "admin" {
		t.Fatalf("unexpected decoded session: %+v", decoded)
	}
}

func TestAdminRequiresRole(t *testing.T) {
	app := NewApp(testConfig(), http.DefaultClient)

	session, err := app.session.Encode(Session{Subject: "abc", Name: "bob", Expires: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	rr := httptest.NewRecorder()

	app.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", rr.Code)
	}
}

func TestAdminAllowsRequiredRole(t *testing.T) {
	app := NewApp(testConfig(), http.DefaultClient)

	session, err := app.session.Encode(Session{
		Subject: "abc",
		Name:    "bob",
		Roles:   []string{"admin"},
		Expires: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	rr := httptest.NewRecorder()

	app.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d", rr.Code)
	}
}

func TestHomeShowsLoginWhenLoggedOut(t *testing.T) {
	app := NewApp(testConfig(), http.DefaultClient)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	app.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Login with SSO") {
		t.Fatalf("expected login link in response")
	}
}

func TestCallbackDoesNotLeakTokenExchangeErrorDetails(t *testing.T) {
	cfg := testConfig()
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_grant","detail":"provider-internal-secret"}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	app := NewApp(cfg, client)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=ok", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "ok"})
	rr := httptest.NewRecorder()

	app.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "token exchange failed") {
		t.Fatalf("expected generic token exchange error, got %q", body)
	}
	if strings.Contains(body, "provider-internal-secret") || strings.Contains(body, "invalid_grant") {
		t.Fatalf("response leaked provider details: %q", body)
	}
}

func TestLoginSetsSecureCookieWhenTrustingForwardedProto(t *testing.T) {
	cfg := testConfig()
	cfg.TrustProxy = true
	app := NewApp(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()

	app.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected state cookie")
	}
	if !cookies[0].Secure {
		t.Fatal("expected secure state cookie when trusted forwarded proto is https")
	}
}
