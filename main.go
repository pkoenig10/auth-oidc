package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

const (
	// IssuerURLGoogle is the issuer URL for Google.
	IssuerURLGoogle = "https://accounts.google.com"

	// ScopeEmail is the scope to request access to the email and email_verified claims.
	ScopeEmail = "email"

	// HeaderXEmail is the response header containing the user's email address.
	HeaderXEmail = "X-Email"
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

var (
	httpAddress = flag.String("http-address", ":80", "The address on which to listen for requests")

	issuerURL    = flag.String("issuer-url", IssuerURLGoogle, "The OpenID Connect issuer URL")
	externalURL  = flag.String("external-url", "", "The external URL of this server")
	clientID     = flag.String("client-id", "", "The OAuth2 client ID")
	clientSecret = flag.String("client-secret", "", "The OAuth2 client secret")

	cookieKey      = flag.String("cookie-key", "", "The cookie encryption key")
	cookieName     = flag.String("cookie-name", "_oidc", "The cookie name")
	cookieDomain   = flag.String("cookie-domain", "", "The cookie Domain attribute")
	cookiePath     = flag.String("cookie-path", "/", "The cookie Path attribute")
	cookieMaxAge   = flag.Duration("cookie-max-age", 0, "The cookie Max-Age attribute")
	cookieSecure   = flag.Bool("cookie-secure", true, "The cookie Secure attribute")
	cookieHTTPOnly = flag.Bool("cookie-http-only", true, "The cookie HttpOnly attribute")

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

// LoginSession is the login session information.
type LoginSession struct {
	Redirect string `json:"r,omitempty"`
	State    string `json:"s,omitempty"`
	Nonce    string `json:"n,omitempty"`
}

// Session is the session information.
type Session struct {
	Email        string `json:"e,omitempty"`
	Expiry       int64  `json:"x,omitempty"`
	RefreshToken string `json:"r,omitempty"`
}

func (s *Session) isValid() bool {
	return time.Now().Unix() < s.Expiry
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

	var session Session
	err := s.store.getSession(r, &session)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !session.isValid() {
		session, err := s.provider.refreshToken(r.Context(), session.RefreshToken)
		if err != nil {
			err = fmt.Errorf("Error refreshing token: %v", err)
			s.handleError(w, err, http.StatusUnauthorized)
			return
		}

		err = s.store.setSession(w, &session)
		if err != nil {
			s.handleError(w, err, http.StatusInternalServerError)
			return
		}
	}

	if !s.users.isAllowed(group, session.Email) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.Header().Set(HeaderXEmail, session.Email)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get(redirectKey)

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

	loginSession := LoginSession{
		Redirect: redirect,
		State:    state,
		Nonce:    nonce,
	}
	err = s.store.setSession(w, &loginSession)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}

	authCodeURL := s.provider.authCodeURL(state, nonce)
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var session Session
	err := s.store.getSession(r, &session)

	if err == nil {
		log.Printf("Logout for %v", session.Email)
	}

	s.store.clearSession(w)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get(codeKey)
	state := r.URL.Query().Get(stateKey)

	var loginSession LoginSession
	err := s.store.getSession(r, &loginSession)
	if err != nil {
		err = fmt.Errorf("Invalid session: %v", err)
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	if state != loginSession.State {
		err = fmt.Errorf("Invalid state")
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	session, err := s.provider.exchangeCode(r.Context(), code, loginSession.Nonce)
	if err != nil {
		err = fmt.Errorf("Error exchanging code: %v", err)
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	err = s.store.setSession(w, &session)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}

	if loginSession.Redirect != "" {
		http.Redirect(w, r, loginSession.Redirect, http.StatusFound)
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
	cache    map[string]func() (Session, error)
	mutex    sync.Mutex
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
		Scopes:       scopes(),
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: *clientID,
	})

	return &Provider{
		config:   config,
		verifier: verifier,
		cache:    make(map[string]func() (Session, error)),
	}, nil
}

func (p *Provider) authCodeURL(state string, nonce string) string {
	return p.config.AuthCodeURL(
		state,
		authCodeOptions(nonce)...)
}

func (p *Provider) exchangeCode(ctx context.Context, code string, nonce string) (Session, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return Session{}, fmt.Errorf("Error exchanging code: %v", err)
	}

	idTokenValue, ok := token.Extra(idTokenKey).(string)
	if !ok {
		return Session{}, fmt.Errorf("ID token is not present")
	}

	idToken, err := p.verifier.Verify(ctx, idTokenValue)
	if err != nil {
		return Session{}, fmt.Errorf("Error verifying token: %v", err)
	}

	if idToken.Nonce != nonce {
		return Session{}, fmt.Errorf("Invalid nonce")
	}

	email, err := getEmail(idToken)
	if err != nil {
		return Session{}, fmt.Errorf("Error reading email from token: %v", err)
	}

	log.Printf("Created session for %v", email)

	return Session{
		Email:        email,
		Expiry:       idToken.Expiry.Unix(),
		RefreshToken: token.RefreshToken,
	}, nil
}

func (p *Provider) refreshToken(ctx context.Context, refreshToken string) (Session, error) {
	p.mutex.Lock()

	future, ok := p.cache[refreshToken]
	if !ok {
		var session Session
		var err error
		done := make(chan struct{})

		future = func() (Session, error) {
			<-done
			return session, err
		}
		p.cache[refreshToken] = future

		go func() {
			session, err = p.exchangeRefreshToken(ctx, refreshToken)
			close(done)

			time.Sleep(time.Minute)

			p.mutex.Lock()
			delete(p.cache, refreshToken)
			p.mutex.Unlock()
		}()
	}

	p.mutex.Unlock()

	return future()
}

func (p *Provider) exchangeRefreshToken(ctx context.Context, refreshToken string) (Session, error) {
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}
	tokenSource := p.config.TokenSource(ctx, token)

	token, err := tokenSource.Token()
	if err != nil {
		return Session{}, fmt.Errorf("Error refreshing token: %v", err)
	}

	idTokenValue, ok := token.Extra(idTokenKey).(string)
	if !ok {
		return Session{}, fmt.Errorf("ID token is not present")
	}

	idToken, err := p.verifier.Verify(ctx, idTokenValue)
	if err != nil {
		return Session{}, fmt.Errorf("Error verifying token: %v", err)
	}

	email, err := getEmail(idToken)
	if err != nil {
		return Session{}, fmt.Errorf("Error reading email from ID token: %v", err)
	}

	log.Printf("Refreshed session for %v", email)

	return Session{
		Email:        email,
		Expiry:       idToken.Expiry.Unix(),
		RefreshToken: token.RefreshToken,
	}, nil
}

// Store is the session store.
type Store struct {
	aead cipher.AEAD
}

func newStore() (*Store, error) {
	key := []byte(*cookieKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error creating cipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Error creating AEAD: %v", err)
	}

	return &Store{
		aead: aead,
	}, nil
}

func (s *Store) getSession(r *http.Request, dst interface{}) error {
	cookie, err := r.Cookie(*cookieName)
	if err != nil {
		return err
	}

	err = s.fromCookieValue(cookie.Value, &dst)
	if err != nil {
		return fmt.Errorf("Error reading session cookie: %v", err)
	}

	return nil
}

func (s *Store) setSession(w http.ResponseWriter, src interface{}) error {
	value, err := s.toCookieValue(src)
	if err != nil {
		return fmt.Errorf("Error writing session cookie: %v", err)
	}

	cookie := &http.Cookie{
		Name:     *cookieName,
		Domain:   *cookieDomain,
		Path:     *cookiePath,
		Secure:   *cookieSecure,
		HttpOnly: *cookieHTTPOnly,
		MaxAge:   int(*cookieMaxAge / time.Second),
		Value:    value,
	}
	http.SetCookie(w, cookie)

	return nil
}

func (s *Store) clearSession(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     *cookieName,
		Domain:   *cookieDomain,
		Path:     *cookiePath,
		Secure:   *cookieSecure,
		HttpOnly: *cookieHTTPOnly,
		MaxAge:   -1,
	}
	http.SetCookie(w, cookie)
}

func (s *Store) toCookieValue(src interface{}) (string, error) {
	serialized, err := serialize(src)
	if err != nil {
		return "", err
	}

	encrypted, err := s.encrypt(serialized)
	if err != nil {
		return "", err
	}

	encoded := encode(encrypted)

	return string(encoded), nil
}

func (s *Store) fromCookieValue(src string, dst interface{}) error {
	decoded, err := decode([]byte(src))
	if err != nil {
		return err
	}

	decrypted, err := s.decrypt(decoded)
	if err != nil {
		return err
	}

	err = deserialize(decrypted, dst)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) encrypt(value []byte) ([]byte, error) {
	nonce, err := randomBytes(s.aead.NonceSize())
	if err != nil {
		return nil, err
	}

	encrypted := s.aead.Seal(nil, nonce, value, nil)

	return append(nonce, encrypted...), nil
}

func (s *Store) decrypt(value []byte) ([]byte, error) {
	nonce := value[:s.aead.NonceSize()]
	encrypted := value[s.aead.NonceSize():]

	decrypted, err := s.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

// Users is the users.
type Users struct {
	users map[string][]string
}

func newUsers() (*Users, error) {
	if *usersFile == "" {
		return &Users{}, nil
	}

	file, err := ioutil.ReadFile(*usersFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading users file %v: %v", *usersFile, err)
	}

	file = bytes.ToLower(file)

	var users map[string][]string
	err = yaml.Unmarshal(file, &users)
	if err != nil {
		return nil, fmt.Errorf("Error parsing users file %v: %v", *usersFile, err)
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

func serialize(src interface{}) ([]byte, error) {
	return json.Marshal(src)
}

func deserialize(src []byte, dst interface{}) error {
	return json.Unmarshal(src, dst)
}

func encode(value []byte) []byte {
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(value)))
	base64.RawURLEncoding.Encode(encoded, value)
	return encoded
}

func decode(value []byte) ([]byte, error) {
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(value)))
	n, err := base64.RawURLEncoding.Decode(decoded, value)
	if err != nil {
		return nil, err
	}

	return decoded[:n], nil
}

func randomString(size int) (string, error) {
	bytes, err := randomBytes(size)
	if err != nil {
		return "", err
	}

	return string(encode(bytes)), nil
}

func randomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
