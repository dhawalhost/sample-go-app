package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
