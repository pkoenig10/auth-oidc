package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

const (
	// IssuerURLGoogle is the issuer URL for Google.
	IssuerURLGoogle = "https://accounts.google.com"

	// ScopeEmail is the scope to request access to the email and email_verified claims.
	ScopeEmail = "email"

	// HeaderXAuthRequestEmail is the response header containing the user's email address.
	HeaderXAuthRequestEmail = "X-Auth-Request-Email"
)

const (
	authPath     = "/auth"
	loginPath    = "/login"
	logoutPath   = "/logout"
	callbackPath = "/callback"
)

const (
	groupKey    = "g"
	redirectKey = "rd"

	codeKey  = "code"
	stateKey = "state"

	idTokenKey = "id_token"
)

// Session is the session information.
type Session struct {
	Redirect     string    `json:"redirect,omitempty"`
	State        string    `json:"state,omitempty"`
	Nonce        string    `json:"nonce,omitempty"`
	Email        string    `json:"email,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
}

var (
	httpAddress = flag.String("http-address", ":4180", "")

	issuerURL    = flag.String("issuer-url", IssuerURLGoogle, "")
	clientID     = flag.String("client-id", "", "")
	clientSecret = flag.String("client-secret", "", "")

	cookieSecret   = flag.String("cookie-secret", "", "")
	cookieName     = flag.String("cookie-name", "_oidc", "")
	cookieDomain   = flag.String("cookie-domain", "", "")
	cookiePath     = flag.String("cookie-path", "/", "")
	cookieExpire   = flag.Duration("cookie-expire", 672*time.Hour, "")
	cookieSecure   = flag.Bool("cookie-secure", true, "")
	cookieHTTPOnly = flag.Bool("cookie-http-only", true, "")

	redirectURL = flag.String("redirect-url", "", "")

	usersFile = flag.String("users-file", "", "")
)

func main() {
	flag.Parse()

	s := newServer()

	http.HandleFunc(authPath, s.HandleAuth)
	http.HandleFunc(loginPath, s.HandleLogin)
	http.HandleFunc(logoutPath, s.HandleLogout)
	http.HandleFunc(callbackPath, s.HandleCallback)

	log.Fatal(http.ListenAndServe(*httpAddress, nil))
}

// Server is the authentication and authorization server.
type Server struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	secureCookie *securecookie.SecureCookie
	users        map[string]map[string]bool
}

// NewServer creates a new server.
func newServer() *Server {
	provider, err := oidc.NewProvider(context.Background(), *issuerURL)
	if err != nil {
		log.Fatalf("Error creating provider: %v", err)
	}

	oidcCondig := oidc.Config{
		ClientID: *clientID,
	}
	verifier := provider.Verifier(&oidcCondig)

	oauth2Config := oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		RedirectURL:  *redirectURL + callbackPath,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes(),
	}

	key := []byte(*cookieSecret)
	secureCookie := securecookie.New(key, key)
	secureCookie.SetSerializer(&securecookie.JSONEncoder{})

	users, err := readUsers()
	if err != nil {
		log.Fatalf("Error reading users files: %v", err)
	}

	return &Server{
		provider:     provider,
		verifier:     verifier,
		oauth2Config: oauth2Config,
		secureCookie: secureCookie,
		users:        users,
	}
}

// HandleAuth handles authentication.
func (s *Server) HandleAuth(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)

	if !time.Now().Before(session.Expiry) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	group := strings.ToLower(r.URL.Query().Get(groupKey))
	email := strings.ToLower(session.Email)
	if !s.users[group][email] {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.Header().Set(HeaderXAuthRequestEmail, session.Email)
	w.WriteHeader(http.StatusOK)
}

// HandleLogin handles login.
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)

	group := r.URL.Query().Get(groupKey)
	redirect := r.URL.Query().Get(redirectKey)

	err := s.refreshToken(r.Context(), w, group, session.RefreshToken)
	if err == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	state, err := generateRandomString()
	if err != nil {
		err = fmt.Errorf("Error generating state: %v", err)
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}

	nonce, err := generateRandomString()
	if err != nil {
		err = fmt.Errorf("Error generating nonce: %v", err)
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}

	session = &Session{
		Redirect: redirect,
		State:    state,
		Nonce:    nonce,
	}
	err = s.setSession(w, session)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}

	authCodeURL := s.oauth2Config.AuthCodeURL(
		state,
		authCodeOptions(nonce)...)
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

// HandleLogout handles logout.
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)

	log.Printf("Logout for %v", session.Email)

	s.clearSession(w)
	w.WriteHeader(http.StatusOK)
}

// HandleCallback handles the callback.
func (s *Server) HandleCallback(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)

	redirect := session.Redirect

	state := r.URL.Query().Get(stateKey)
	if state != session.State {
		err := fmt.Errorf("Invalid state")
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get(codeKey)
	token, err := s.exchangeToken(r.Context(), code)
	if err != nil {
		err := fmt.Errorf("Error exchanging token: %v", err)
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	idToken, err := s.verifyToken(r.Context(), token)
	if err != nil {
		err := fmt.Errorf("Error verifying token: %v", err)
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	if idToken.Nonce != session.Nonce {
		err := fmt.Errorf("Invalid nonce")
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	email, err := getEmail(idToken)
	if err != nil {
		err := fmt.Errorf("Error reading email from token: %v", err)
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	session = &Session{
		Email:        email,
		Expiry:       idToken.Expiry,
		RefreshToken: token.RefreshToken,
	}
	err = s.setSession(w, session)
	if err != nil {
		s.handleError(w, err, http.StatusForbidden)
		return
	}

	log.Printf("Created session for %v", email)

	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) exchangeToken(ctx context.Context, code string) (*oauth2.Token, error) {
	return s.oauth2Config.Exchange(ctx, code)
}

func (s *Server) verifyToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	idToken, ok := token.Extra(idTokenKey).(string)
	if !ok {
		return nil, fmt.Errorf("ID token is not present")
	}

	return s.verifier.Verify(ctx, idToken)
}

func (s *Server) refreshToken(ctx context.Context, w http.ResponseWriter, group string, refreshToken string) error {
	tokenSource := s.oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	})

	token, err := tokenSource.Token()
	if err != nil {
		return fmt.Errorf("Error refreshing token: %v", err)
	}

	idToken, err := s.verifyToken(ctx, token)
	if err != nil {
		return fmt.Errorf("Error verifying refreshed token: %v", err)
	}

	email, err := getEmail(idToken)
	if err != nil {
		return fmt.Errorf("Error reading email from refreshed token: %v", err)
	}

	session := &Session{
		Email:        email,
		Expiry:       idToken.Expiry,
		RefreshToken: token.RefreshToken,
	}
	err = s.setSession(w, session)
	if err != nil {
		return err
	}

	log.Printf("Refreshed session for %v", email)

	return nil
}

func (s *Server) handleError(w http.ResponseWriter, err error, code int) {
	log.Println(err)
	s.clearSession(w)
	http.Error(w, err.Error(), code)
}

func (s *Server) getSession(r *http.Request) *Session {
	cookie, err := r.Cookie(*cookieName)
	if err != nil {
		return &Session{}
	}

	var session Session
	err = s.secureCookie.Decode(*cookieName, cookie.Value, &session)
	if err != nil {
		log.Printf("Error decoding session cookie: %v", err)
		return &Session{}
	}

	return &session
}

func (s *Server) setSession(w http.ResponseWriter, session *Session) error {
	value, err := s.secureCookie.Encode(*cookieName, session)
	if err != nil {
		return fmt.Errorf("Error encoding session cookie: %v", err)
	}

	cookie := &http.Cookie{
		Name:     *cookieName,
		Domain:   *cookieDomain,
		Path:     *cookiePath,
		Secure:   *cookieSecure,
		HttpOnly: *cookieHTTPOnly,
		Expires:  time.Now().Add(*cookieExpire),
		Value:    value,
	}
	http.SetCookie(w, cookie)

	return nil
}

func (s *Server) clearSession(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     *cookieName,
		Domain:   *cookieDomain,
		Path:     *cookiePath,
		Secure:   *cookieSecure,
		HttpOnly: *cookieHTTPOnly,
		Expires:  time.Unix(0, 0),
	}
	http.SetCookie(w, cookie)
}

func getEmail(idToken *oidc.IDToken) (string, error) {
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	err := idToken.Claims(&claims)
	if err != nil {
		return "", fmt.Errorf("Error reading claims from token: %v", err)
	}

	if !claims.Verified {
		return "", fmt.Errorf("Email is not verified: %v", claims.Email)
	}

	return claims.Email, nil
}

func generateRandomString() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

func scopes() []string {
	if *issuerURL == IssuerURLGoogle {
		return []string{oidc.ScopeOpenID, ScopeEmail}
	}

	return []string{oidc.ScopeOpenID, ScopeEmail, oidc.ScopeOfflineAccess}
}

func authCodeOptions(nonce string) []oauth2.AuthCodeOption {
	if *issuerURL == IssuerURLGoogle {
		return []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.ApprovalForce, oauth2.AccessTypeOffline}
	}

	return []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.ApprovalForce}
}

func readUsers() (map[string]map[string]bool, error) {
	file, err := ioutil.ReadFile(*usersFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading users file %v: %v", *usersFile, err)
	}

	file = bytes.ToLower(file)

	var data map[string][]string
	err = yaml.Unmarshal(file, &data)
	if err != nil {
		return nil, fmt.Errorf("Error parsing users file %v: %v", *usersFile, err)
	}

	users := make(map[string]map[string]bool)
	for group, emails := range data {
		users[group] = make(map[string]bool)
		for _, email := range emails {
			users[group][email] = true
		}
	}

	return users, nil
}