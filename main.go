package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

const (
	authPath     = "/auth"
	loginPath    = "/login"
	logoutPath   = "/logout"
	callbackPath = "/callback"

	groupKey    = "group"
	redirectKey = "redirect"

	codeKey  = "code"
	stateKey = "state"

	idTokenKey = "id_token"
)

var (
	httpAddress = flag.String("http-address", ":80", "The address on which to listen for requests")

	issuerURL    = flag.String("issuer-url", "https://accounts.google.com", "The OpenID Connect issuer URL")
	externalURL  = flag.String("external-url", "", "The external URL of this server")
	clientID     = flag.String("client-id", "", "The OAuth2 client ID")
	clientSecret = flag.String("client-secret", "", "The OAuth2 client secret")

	tokenKey        = flag.String("token-key", "", "The JWT signing key")
	tokenExpiration = flag.Duration("token-expiration", 7*24*time.Hour, "The JWT expiration duration")

	cookieName   = flag.String("cookie-name", "_token", "The cookie name")
	cookieDomain = flag.String("cookie-domain", "", "The cookie Domain attribute")
	cookiePath   = flag.String("cookie-path", "/", "The cookie Path attribute")

	configFile = flag.String("config-file", "", "The configuration file")
)

func main() {
	flag.Parse()

	if *externalURL == "" {
		log.Fatalf("External URL is not configured")
	}
	if *clientID == "" {
		log.Fatalf("Client ID is not configured")
	}
	if *clientSecret == "" {
		log.Fatalf("Client secret is not configured")
	}
	if *tokenKey == "" {
		log.Fatalf("Token key is not configured")
	}

	config, err := newConfig()
	if err != nil {
		log.Fatalf("Error creating config: %v", err)
	}

	store, err := newStore()
	if err != nil {
		log.Fatalf("Error creating store: %v", err)
	}

	provider, err := newProvider()
	if err != nil {
		log.Fatalf("Error creating provider: %v", err)
	}

	server := &Server{
		config,
		store,
		provider,
	}

	http.HandleFunc(authPath, server.handleAuth)
	http.HandleFunc(loginPath, server.handleLogin)
	http.HandleFunc(logoutPath, server.handleLogout)
	http.HandleFunc(callbackPath, server.handleCallback)

	log.Fatal(http.ListenAndServe(*httpAddress, nil))
}

type Server struct {
	config   *Config
	store    *Store
	provider *Provider
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	group := r.URL.Query().Get(groupKey)

	claims, err := s.store.getSession(r)
	if err != nil || !claims.isAuthenticated() {
		if r.URL.Query().Has(redirectKey) {
			s.handleLogin(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
		return
	}

	if !s.config.isAuthorized(group, claims.Subject) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.Header().Set("X-Subject", claims.Subject)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get(redirectKey)

	err := s.verifyRedirect(redirect)
	if err != nil {
		log.Printf("Error verifying redirect URL: %v", err)
		s.handleError(w, http.StatusBadRequest)
		return
	}

	state, err := randomString(12)
	if err != nil {
		log.Printf("Error creating state: %v", err)
		s.handleError(w, http.StatusInternalServerError)
		return
	}

	nonce, err := randomString(12)
	if err != nil {
		log.Printf("Error creating nonce: %v", err)
		s.handleError(w, http.StatusInternalServerError)
		return
	}

	claims := newLoginClaims(state, nonce, redirect)

	err = s.store.setSession(w, claims)
	if err != nil {
		log.Printf("Error setting session: %v", err)
		s.handleError(w, http.StatusInternalServerError)
		return
	}

	authCodeURL := s.provider.authCodeURL(state, nonce)
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	claims, err := s.store.getSession(r)

	if err == nil {
		log.Printf("Logout for '%v'", claims.Subject)
	}

	s.store.clearSession(w)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get(codeKey)
	state := r.URL.Query().Get(stateKey)

	claims, err := s.store.getSession(r)
	if err != nil {
		log.Printf("Invalid session: %v", err)
		s.handleError(w, http.StatusBadRequest)
		return
	}

	if claims.isAuthenticated() {
		w.WriteHeader(http.StatusOK)
		return
	}

	if state != claims.State {
		log.Printf("Invalid state")
		s.handleError(w, http.StatusBadRequest)
		return
	}

	redirect := claims.Redirect

	subject, err := s.provider.exchangeCode(r.Context(), code, claims.Nonce)
	if err != nil {
		log.Printf("Error exchanging code: %v", err)
		s.handleError(w, http.StatusBadRequest)
		return
	}

	claims = newAuthenticatedClaims(subject)

	err = s.store.setSession(w, claims)
	if err != nil {
		log.Printf("Error setting session: %v", err)
		s.handleError(w, http.StatusInternalServerError)
		return
	}

	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) handleError(w http.ResponseWriter, code int) {
	s.store.clearSession(w)
	w.WriteHeader(code)
}

func (s *Server) verifyRedirect(redirect string) error {
	if redirect == "" {
		return nil
	}

	redirectURL, err := url.Parse(redirect)
	if err != nil {
		return fmt.Errorf("error parsing redirect URL '%v'", redirect)
	}

	if !s.isValidRedirectHost(redirectURL) {
		return fmt.Errorf("invalid host in redirect URL '%v'", redirect)
	}

	return nil
}

func (s *Server) isValidRedirectHost(redirect *url.URL) bool {
	if *cookieDomain == "" {
		return redirect.Host == ""
	} else {
		return redirect.Host == *cookieDomain || strings.HasSuffix(redirect.Host, "."+*cookieDomain)
	}
}

type Config struct {
	Groups map[string][]string `json:"groups"`
}

func newConfig() (*Config, error) {
	config := Config{}

	if *configFile == "" {
		return &config, nil
	}

	data, err := os.ReadFile(*configFile)
	if err != nil {
		return nil, fmt.Errorf("error reading configuration file '%v': %v", *configFile, err)
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing configuration file '%v': %v", *configFile, err)
	}

	return &config, nil
}

func (c *Config) isAuthorized(group string, user string) bool {
	if group == "" {
		return true
	}

	for _, groupUser := range c.Groups[group] {
		if user == groupUser {
			return true
		}
	}

	return false
}

type Store struct {
	key []byte
}

func newStore() (*Store, error) {
	return &Store{
		key: []byte(*tokenKey),
	}, nil
}

func (s *Store) getKey(token *jwt.Token) (interface{}, error) {
	return s.key, nil
}

func (s *Store) getSession(r *http.Request) (Claims, error) {
	cookie, err := r.Cookie(*cookieName)
	if err != nil {
		return Claims{}, err
	}

	var claims Claims
	_, err = jwt.ParseWithClaims(cookie.Value, &claims, s.getKey)
	if err != nil {
		return Claims{}, fmt.Errorf("error parsing JWT: %v", err)
	}

	return claims, nil
}

func (s *Store) setSession(w http.ResponseWriter, claims Claims) error {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	value, err := token.SignedString(s.key)
	if err != nil {
		return fmt.Errorf("error creating JWT: %v", err)
	}

	maxAge := time.Until(claims.ExpiresAt.Time) / time.Second

	s.setCookie(w, value, int(maxAge))

	return nil
}

func (s *Store) clearSession(w http.ResponseWriter) {
	s.setCookie(w, "", -1)
}

func (s *Store) setCookie(w http.ResponseWriter, value string, maxAge int) {
	cookie := &http.Cookie{
		Name:     *cookieName,
		Value:    value,
		Domain:   *cookieDomain,
		Path:     *cookiePath,
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}

type Provider struct {
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func newProvider() (*Provider, error) {
	provider, err := oidc.NewProvider(context.Background(), *issuerURL)
	if err != nil {
		return nil, fmt.Errorf("error creating provider: %v", err)
	}

	config := &oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		RedirectURL:  strings.TrimSuffix(*externalURL, "/") + callbackPath,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: *clientID,
	})

	return &Provider{
		config:   config,
		verifier: verifier,
	}, nil
}

func (p *Provider) authCodeURL(state string, nonce string) string {
	return p.config.AuthCodeURL(
		state,
		oidc.Nonce(nonce))
}

func (p *Provider) exchangeCode(ctx context.Context, code string, nonce string) (string, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("error exchanging code: %v", err)
	}

	idTokenValue, ok := token.Extra(idTokenKey).(string)
	if !ok {
		return "", fmt.Errorf("ID token is not present")
	}

	idToken, err := p.verifier.Verify(ctx, idTokenValue)
	if err != nil {
		return "", fmt.Errorf("error verifying token: %v", err)
	}

	if idToken.Nonce != nonce {
		return "", fmt.Errorf("invalid nonce")
	}

	var userInfo oidc.UserInfo
	err = idToken.Claims(&userInfo)
	if err != nil {
		return "", fmt.Errorf("error reading claims from token: %v", err)
	}

	if !userInfo.EmailVerified {
		return "", fmt.Errorf("email '%v' is not verified", userInfo.Email)
	}

	log.Printf("Created session for '%v'", userInfo.Email)

	return userInfo.Email, nil
}

type Claims struct {
	jwt.RegisteredClaims
	State    string `json:"state,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	Redirect string `json:"redirect,omitempty"`
}

func newLoginClaims(state, nonce, redirect string) Claims {
	now := time.Now()
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
		Redirect: redirect,
		State:    state,
		Nonce:    nonce,
	}
}

func newAuthenticatedClaims(subject string) Claims {
	now := time.Now()
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(now.Add(*tokenExpiration)),
		},
	}
}

func (c Claims) isAuthenticated() bool {
	return c.Subject != ""
}

func randomString(size int) (string, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
