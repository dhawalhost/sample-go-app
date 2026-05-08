package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const sessionCookieName = "sample_session"
const stateCookieName = "sample_oauth_state"

type sessionContextKey struct{}

type Config struct {
	Port          string
	IssuerURL     string
	AuthURL       string
	TokenURL      string
	UserInfoURL   string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        string
	RoleClaim     string
	AdminRole     string
	SessionSecret string
}

type Session struct {
	Subject string   `json:"sub"`
	Name    string   `json:"name,omitempty"`
	Email   string   `json:"email,omitempty"`
	Roles   []string `json:"roles,omitempty"`
	Expires int64    `json:"exp"`
}

type SessionManager struct {
	secret []byte
}

func NewSessionManager(secret string) *SessionManager {
	return &SessionManager{secret: []byte(secret)}
}

func (s *SessionManager) Encode(session Session) (string, error) {
	payload, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	sig := s.sign(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *SessionManager) Decode(raw string) (*Session, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid session format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	expected := s.sign(payload)
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(expected, got) != 1 {
		return nil, errors.New("invalid session signature")
	}
	var session Session
	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, err
	}
	if time.Now().Unix() > session.Expires {
		return nil, errors.New("session expired")
	}
	return &session, nil
}

func (s *SessionManager) sign(payload []byte) []byte {
	h := hmac.New(sha256.New, s.secret)
	h.Write(payload)
	return h.Sum(nil)
}

type App struct {
	cfg     Config
	client  *http.Client
	session *SessionManager
	mux     *http.ServeMux
}

func main() {
	oidcHTTPClient := &http.Client{Timeout: 10 * time.Second}

	cfg, err := loadConfig(context.Background(), oidcHTTPClient)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	app := NewApp(cfg, oidcHTTPClient)
	log.Printf("sample app listening on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, app); err != nil {
		log.Fatal(err)
	}
}

func NewApp(cfg Config, client *http.Client) *App {
	app := &App{
		cfg:     cfg,
		client:  client,
		session: NewSessionManager(cfg.SessionSecret),
		mux:     http.NewServeMux(),
	}
	app.routes()
	return app
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *App) routes() {
	a.mux.HandleFunc("/", a.home)
	a.mux.HandleFunc("/login", a.login)
	a.mux.HandleFunc("/auth/callback", a.callback)
	a.mux.HandleFunc("/logout", a.logout)
	a.mux.Handle("/profile", a.requireAuth(http.HandlerFunc(a.profile)))
	a.mux.Handle("/admin", a.requireRole(a.cfg.AdminRole, http.HandlerFunc(a.admin)))
}

func (a *App) home(w http.ResponseWriter, r *http.Request) {
	session, _ := a.readSession(r)
	a.renderPage(w, map[string]any{
		"Title":   "Sample SSO App",
		"Session": session,
	})
}

func (a *App) profile(w http.ResponseWriter, r *http.Request) {
	session, ok := sessionFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	a.renderPage(w, map[string]any{
		"Title":   "Profile",
		"Session": session,
		"Profile": true,
	})
}

func (a *App) admin(w http.ResponseWriter, r *http.Request) {
	session, ok := sessionFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	a.renderPage(w, map[string]any{
		"Title":     "Admin",
		"Session":   session,
		"Admin":     true,
		"AdminRole": a.cfg.AdminRole,
	})
}

func (a *App) renderPage(w http.ResponseWriter, data map[string]any) {
	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, data); err != nil {
		log.Printf("template render error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Printf("response write error: %v", err)
	}
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	state, err := randomString(24)
	if err != nil {
		http.Error(w, "unable to generate state", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	u, err := url.Parse(a.cfg.AuthURL)
	if err != nil {
		http.Error(w, "invalid auth URL", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", a.cfg.ClientID)
	q.Set("redirect_uri", a.cfg.RedirectURL)
	q.Set("scope", a.cfg.Scopes)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (a *App) callback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	if errText := r.URL.Query().Get("error"); errText != "" {
		http.Error(w, "login failed: "+errText, http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	claims, err := a.exchangeCode(r.Context(), code)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	session := Session{
		Subject: stringClaim(claims, "sub"),
		Name:    userDisplayName(claims),
		Email:   stringClaim(claims, "email"),
		Roles:   roleClaims(claims, a.cfg.RoleClaim),
		Expires: time.Now().Add(1 * time.Hour).Unix(),
	}
	if session.Subject == "" {
		http.Error(w, "identity claims missing sub", http.StatusBadGateway)
		return
	}
	encoded, err := a.session.Encode(session)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})
	http.Redirect(w, r, "/profile", http.StatusFound)
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := a.readSession(r)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *App) requireRole(role string, next http.Handler) http.Handler {
	return a.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := sessionFromContext(r.Context())
		if !ok {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		for _, candidate := range session.Roles {
			if candidate == role {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
}

func sessionFromContext(ctx context.Context) (*Session, bool) {
	session, ok := ctx.Value(sessionContextKey{}).(*Session)
	return session, ok && session != nil
}

func (a *App) readSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}
	return a.session.Decode(cookie.Value)
}

func (a *App) exchangeCode(ctx context.Context, code string) (map[string]any, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", a.cfg.ClientID)
	form.Set("client_secret", a.cfg.ClientSecret)
	form.Set("redirect_uri", a.cfg.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}
	if a.cfg.UserInfoURL == "" {
		return nil, errors.New("userinfo endpoint must be configured; refusing to trust unverified id_token claims")
	}
	claims, err := a.userInfo(ctx, tokenResp)
	if err != nil {
		return nil, err
	}
	if stringClaim(claims, "sub") == "" {
		return nil, errors.New("userinfo response missing sub")
	}
	return claims, nil
}

func (a *App) userInfo(ctx context.Context, tokenResp map[string]any) (map[string]any, error) {
	accessToken := stringClaim(tokenResp, "access_token")
	if accessToken == "" {
		return nil, errors.New("missing access_token")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("userinfo status %d", resp.StatusCode)
	}
	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func loadConfig(ctx context.Context, client *http.Client) (Config, error) {
	cfg := Config{
		Port:          defaultEnv("PORT", "8080"),
		IssuerURL:     os.Getenv("SSO_ISSUER_URL"),
		AuthURL:       os.Getenv("SSO_AUTH_URL"),
		TokenURL:      os.Getenv("SSO_TOKEN_URL"),
		UserInfoURL:   os.Getenv("SSO_USERINFO_URL"),
		ClientID:      os.Getenv("SSO_CLIENT_ID"),
		ClientSecret:  os.Getenv("SSO_CLIENT_SECRET"),
		RedirectURL:   defaultEnv("SSO_REDIRECT_URL", "http://localhost:8080/auth/callback"),
		Scopes:        defaultEnv("SSO_SCOPES", "openid profile email"),
		RoleClaim:     defaultEnv("SSO_ROLE_CLAIM", "roles"),
		AdminRole:     defaultEnv("SSO_ADMIN_ROLE", "admin"),
		SessionSecret: strings.TrimSpace(os.Getenv("SESSION_SECRET")),
	}
	if cfg.IssuerURL != "" && (cfg.AuthURL == "" || cfg.TokenURL == "") {
		if err := applyDiscovery(ctx, client, &cfg); err != nil {
			return cfg, err
		}
	}
	if cfg.AuthURL == "" || cfg.TokenURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return cfg, errors.New("set SSO_CLIENT_ID, SSO_CLIENT_SECRET, and either SSO_ISSUER_URL or SSO_AUTH_URL+SSO_TOKEN_URL")
	}
	if len(cfg.SessionSecret) < 16 {
		return cfg, errors.New("SESSION_SECRET must be at least 16 chars")
	}
	return cfg, nil
}

func applyDiscovery(ctx context.Context, client *http.Client, cfg *Config) error {
	issuer := strings.TrimRight(cfg.IssuerURL, "/")
	discoveryURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("oidc discovery failed: %d", resp.StatusCode)
	}
	var metadata map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return err
	}
	if cfg.AuthURL == "" {
		cfg.AuthURL = stringClaim(metadata, "authorization_endpoint")
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = stringClaim(metadata, "token_endpoint")
	}
	if cfg.UserInfoURL == "" {
		cfg.UserInfoURL = stringClaim(metadata, "userinfo_endpoint")
	}
	return nil
}

func userDisplayName(claims map[string]any) string {
	name := stringClaim(claims, "name")
	username := stringClaim(claims, "preferred_username")
	return firstNonEmpty(name, username)
}

func randomString(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func parseJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid jwt")
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func stringClaim(claims map[string]any, key string) string {
	value, ok := claims[key]
	if !ok {
		return ""
	}
	str, _ := value.(string)
	return strings.TrimSpace(str)
}

func roleClaims(claims map[string]any, claimKey string) []string {
	value, ok := claims[claimKey]
	if !ok {
		return nil
	}
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return nil
		}
		parts := strings.Split(typed, ",")
		roles := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				roles = append(roles, part)
			}
		}
		return roles
	case []any:
		roles := make([]string, 0, len(typed))
		for _, item := range typed {
			if role, ok := item.(string); ok {
				role = strings.TrimSpace(role)
				if role != "" {
					roles = append(roles, role)
				}
			}
		}
		return roles
	default:
		return nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func defaultEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{ .Title }}</title>
  <style>
    body { font-family: sans-serif; max-width: 840px; margin: 2rem auto; padding: 0 1rem; line-height: 1.4; }
    .card { border: 1px solid #ddd; border-radius: 6px; padding: 1rem; margin-top: 1rem; }
    .muted { color: #666; }
    .danger { color: #a00; }
    a.button { display: inline-block; text-decoration: none; padding: .5rem .85rem; border: 1px solid #333; border-radius: 4px; margin-right: .5rem; }
    code { background: #f5f5f5; padding: 0 .25rem; }
  </style>
</head>
<body>
  <h1>{{ .Title }}</h1>
  {{ if .Session }}
    <p>Logged in as <strong>{{ .Session.Name }}</strong> ({{ .Session.Email }})</p>
    <p>
      <a class="button" href="/profile">Profile</a>
      <a class="button" href="/admin">Admin page</a>
      <a class="button" href="/logout">Logout</a>
    </p>
  {{ else }}
    <p class="muted">Use your identity provider to sign in via OIDC/OAuth2.</p>
    <p><a class="button" href="/login">Login with SSO</a></p>
  {{ end }}

  {{ if .Profile }}
    <div class="card">
      <h2>Profile claims</h2>
      <p><strong>sub:</strong> <code>{{ .Session.Subject }}</code></p>
      <p><strong>roles:</strong> <code>{{ range $i, $r := .Session.Roles }}{{ if $i }}, {{ end }}{{ $r }}{{ end }}</code></p>
    </div>
  {{ end }}

  {{ if .Admin }}
    <div class="card">
      <h2>Admin-only area</h2>
      <p>Authorization works. Required role: <code>{{ .AdminRole }}</code>.</p>
    </div>
  {{ end }}
</body>
</html>`))
