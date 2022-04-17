package main

import (
	"bytes"
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
	"gopkg.in/yaml.v2"
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
	tokenRefresh    = flag.Duration("token-refresh", time.Hour, "The JWT refresh duration")
	tokenExpiration = flag.Duration("token-expiration", 30*24*time.Hour, "The JWT expiration duration")

	cookieName   = flag.String("cookie-name", "_oidc", "The cookie name")
	cookieDomain = flag.String("cookie-domain", "", "The cookie Domain attribute")
	cookiePath   = flag.String("cookie-path", "/", "The cookie Path attribute")

	usersFile = flag.String("users-file", "", "The users configuration file")
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

	s := newServer()

	http.HandleFunc(authPath, s.handleAuth)
	http.HandleFunc(loginPath, s.handleLogin)
	http.HandleFunc(logoutPath, s.handleLogout)
	http.HandleFunc(callbackPath, s.handleCallback)

	log.Fatal(http.ListenAndServe(*httpAddress, nil))
}

// Server is the authentication and authorization server.
type Server struct {
	provider *Provider
	store    *Store
	users    *Users
}

func newServer() *Server {
	provider, err := newProvider()
	if err != nil {
		log.Fatalf("Error creating token service: %v", err)
	}

	store, err := newStore()
	if err != nil {
		log.Fatalf("Error creating store: %v", err)
	}

	users, err := newUsers()
	if err != nil {
		log.Fatalf("Error reading users files: %v", err)
	}

	return &Server{
		provider: provider,
		store:    store,
		users:    users,
	}
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	group := r.URL.Query().Get(groupKey)

	claims, err := s.store.getSession(r)
	if err != nil || !claims.isAuthenticated() {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !claims.isFresh() {
		claims = newAuthenticatedClaims(claims.Subject)

		err = s.store.setSession(w, claims)
		if err != nil {
			s.handleError(w, err, http.StatusInternalServerError)
			return
		}

		log.Printf("Refreshed session for %v", claims.Subject)
	}

	if !s.users.isAllowed(group, claims.Subject) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.Header().Set("X-Subject", claims.Subject)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get(redirectKey)

	err := verifyRedirect(redirect)
	if err != nil {
		err = fmt.Errorf("Error verifying redirect URL: %v", err)
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	state, err := randomString(12)
	if err != nil {
		err = fmt.Errorf("Error creating state: %v", err)
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}

	nonce, err := randomString(12)
	if err != nil {
		err = fmt.Errorf("Error creating nonce: %v", err)
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}

	claims := newLoginClaims(state, nonce, redirect)

	err = s.store.setSession(w, claims)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
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
		err = fmt.Errorf("Invalid session: %v", err)
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	if claims.isAuthenticated() {
		w.WriteHeader(http.StatusOK)
		return
	}

	if state != claims.State {
		err = fmt.Errorf("Invalid state")
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	redirect := claims.Redirect

	subject, err := s.provider.exchangeCode(r.Context(), code, claims.Nonce)
	if err != nil {
		err = fmt.Errorf("Error exchanging code: %v", err)
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	claims = newAuthenticatedClaims(subject)

	err = s.store.setSession(w, claims)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}

	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) handleError(w http.ResponseWriter, err error, code int) {
	log.Print(err)
	s.store.clearSession(w)
	http.Error(w, err.Error(), code)
}

// Provider is the token provider.
type Provider struct {
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func newProvider() (*Provider, error) {
	provider, err := oidc.NewProvider(context.Background(), *issuerURL)
	if err != nil {
		return nil, fmt.Errorf("Error creating provider: %v", err)
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
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "select_account"))
}

func (p *Provider) exchangeCode(ctx context.Context, code string, nonce string) (string, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("Error exchanging code: %v", err)
	}

	idTokenValue, ok := token.Extra(idTokenKey).(string)
	if !ok {
		return "", fmt.Errorf("ID token is not present")
	}

	idToken, err := p.verifier.Verify(ctx, idTokenValue)
	if err != nil {
		return "", fmt.Errorf("Error verifying token: %v", err)
	}

	if idToken.Nonce != nonce {
		return "", fmt.Errorf("Invalid nonce")
	}

	var userInfo oidc.UserInfo
	err = idToken.Claims(&userInfo)
	if err != nil {
		return "", fmt.Errorf("Error reading claims from token: %v", err)
	}

	if !userInfo.EmailVerified {
		return "", fmt.Errorf("Email '%v' is not verified", userInfo.Email)
	}

	log.Printf("Created session for '%v'", userInfo.Email)

	return userInfo.Email, nil
}

// Store is the session store.
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
		return Claims{}, fmt.Errorf("Error parsing JWT: %v", err)
	}

	return claims, nil
}

func (s *Store) setSession(w http.ResponseWriter, claims Claims) error {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	value, err := token.SignedString(s.key)
	if err != nil {
		return fmt.Errorf("Error creating JWT: %v", err)
	}

	maxAge := time.Until(claims.ExpiresAt.Time) / time.Second

	setCookie(w, value, int(maxAge))

	return nil
}

func (s *Store) clearSession(w http.ResponseWriter) {
	setCookie(w, "", -1)
}

// Users is the users.
type Users struct {
	users map[string][]string
}

func newUsers() (*Users, error) {
	if *usersFile == "" {
		return &Users{}, nil
	}

	file, err := os.ReadFile(*usersFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading users file '%v': %v", *usersFile, err)
	}

	file = bytes.ToLower(file)

	var users map[string][]string
	err = yaml.Unmarshal(file, &users)
	if err != nil {
		return nil, fmt.Errorf("Error parsing users file '%v': %v", *usersFile, err)
	}

	return &Users{
		users,
	}, nil
}

func (u *Users) isAllowed(group string, user string) bool {
	if u.users == nil {
		return true
	}

	group = strings.ToLower(group)
	user = strings.ToLower(user)

	for _, groupUser := range u.users[group] {
		if user == groupUser {
			return true
		}
	}

	return false
}

// Claims is the session JWT claims.
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
			IssuedAt:  jwt.NewNumericDate(now),
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
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(*tokenExpiration)),
		},
	}
}

func (c Claims) isAuthenticated() bool {
	return c.Subject != ""
}

func (c Claims) isFresh() bool {
	if c.IssuedAt == nil {
		return false
	}

	return time.Now().Before(c.IssuedAt.Time.Add(*tokenRefresh))
}

func verifyRedirect(redirect string) error {
	redirectURL, err := url.Parse(redirect)
	if err != nil {
		return fmt.Errorf("Error parsing redirect URL '%v'", redirect)
	}

	if !isValidRedirectHost(redirectURL) {
		return fmt.Errorf("Invalid host in redirect URL '%v'", redirect)
	}

	return nil
}

func isValidRedirectHost(redirect *url.URL) bool {
	if *cookieDomain == "" {
		return redirect.Host == ""
	} else {
		return redirect.Host == *cookieDomain || strings.HasSuffix(redirect.Host, "."+*cookieDomain)
	}
}

func setCookie(w http.ResponseWriter, value string, maxAge int) {
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

func randomString(size int) (string, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
