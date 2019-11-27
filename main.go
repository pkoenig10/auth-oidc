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
	"time"

	"github.com/coreos/go-oidc"
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

var (
	httpAddress = flag.String("http-address", ":4180", "")

	issuerURL    = flag.String("issuer-url", IssuerURLGoogle, "")
	clientID     = flag.String("client-id", "", "")
	clientSecret = flag.String("client-secret", "", "")

	cookieKey      = flag.String("cookie-key", "", "")
	cookieName     = flag.String("cookie-name", "_oidc", "")
	cookieDomain   = flag.String("cookie-domain", "", "")
	cookiePath     = flag.String("cookie-path", "/", "")
	cookieMaxAge   = flag.Duration("cookie-max-age", 0, "")
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
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
	store        *Store
	users        map[string]map[string]bool
}

func newServer() *Server {
	provider, err := oidc.NewProvider(context.Background(), *issuerURL)
	if err != nil {
		log.Fatalf("Error creating provider: %v", err)
	}

	oidcCondig := oidc.Config{
		ClientID: *clientID,
	}
	verifier := provider.Verifier(&oidcCondig)

	oauth2Config := &oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		RedirectURL:  *redirectURL + callbackPath,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes(),
	}

	store, err := newStore()
	if err != nil {
		log.Fatalf("Error creating store: %v", err)
	}

	users, err := readUsers()
	if err != nil {
		log.Fatalf("Error reading users files: %v", err)
	}

	return &Server{
		provider:     provider,
		verifier:     verifier,
		oauth2Config: oauth2Config,
		store:        store,
		users:        users,
	}
}

// HandleAuth handles authentication.
func (s *Server) HandleAuth(w http.ResponseWriter, r *http.Request) {
	var session Session
	err := s.store.getSession(r, &session)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !session.isValid() {
		err := s.refreshToken(r.Context(), w, &session)
		if err != nil {
			err = fmt.Errorf("Error refreshing token: %v", err)
			s.handleError(w, err, http.StatusUnauthorized)
			return
		}
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

	authCodeURL := s.oauth2Config.AuthCodeURL(
		state,
		authCodeOptions(nonce)...)
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

// HandleLogout handles logout.
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	var session Session
	err := s.store.getSession(r, &session)

	if err == nil {
		log.Printf("Logout for %v", session.Email)
	}

	s.store.clearSession(w)
	w.WriteHeader(http.StatusOK)
}

// HandleCallback handles the callback.
func (s *Server) HandleCallback(w http.ResponseWriter, r *http.Request) {
	var loginSession LoginSession
	err := s.store.getSession(r, &loginSession)
	if err != nil {
		err := fmt.Errorf("Invalid session: %v", err)
		s.handleError(w, err, http.StatusBadRequest)
		return
	}

	redirect := loginSession.Redirect

	state := r.URL.Query().Get(stateKey)
	if state != loginSession.State {
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

	if idToken.Nonce != loginSession.Nonce {
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

	session := Session{
		Email:        email,
		Expiry:       idToken.Expiry.Unix(),
		RefreshToken: token.RefreshToken,
	}
	err = s.store.setSession(w, &session)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
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

func (s *Server) refreshToken(ctx context.Context, w http.ResponseWriter, session *Session) error {
	token := &oauth2.Token{
		RefreshToken: session.RefreshToken,
	}
	tokenSource := s.oauth2Config.TokenSource(ctx, token)

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

	*session = Session{
		Email:        email,
		Expiry:       idToken.Expiry.Unix(),
		RefreshToken: token.RefreshToken,
	}
	err = s.store.setSession(w, session)
	if err != nil {
		return err
	}

	log.Printf("Refreshed session for %v", email)

	return nil
}

func (s *Server) handleError(w http.ResponseWriter, err error, code int) {
	log.Println(err)
	s.store.clearSession(w)
	http.Error(w, err.Error(), code)
}

// Store is the session store.
type Store struct {
	block cipher.Block
}

func newStore() (*Store, error) {
	key := []byte(*cookieKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error creating cipher: %v", err)
	}

	return &Store{
		block: block,
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
	aead, err := cipher.NewGCM(s.block)
	if err != nil {
		return nil, err
	}

	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}

	encrypted := aead.Seal(nil, nonce, value, nil)

	return append(nonce, encrypted...), nil
}

func (s *Store) decrypt(value []byte) ([]byte, error) {
	aead, err := cipher.NewGCM(s.block)
	if err != nil {
		return nil, err
	}

	nonce := value[:aead.NonceSize()]
	encrypted := value[aead.NonceSize():]

	decrypted, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
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
