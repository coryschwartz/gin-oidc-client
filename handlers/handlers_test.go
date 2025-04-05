package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

// Verify that a given state, once encoded for transmission,
// can be decoded back to the original state.
func TestOauthStateMarshaling(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	pkce, challenge, _ := generatePKCE()
	secret := "abc"
	sessionId := "def"
	csrf := "abc-123"
	password := oauthStatePassword(secret, sessionId, csrf)
	state := &oauthState{
		NextUrl:   u,
		PKCEPlain: pkce,
	}
	marshaled, err := marshalOauthState(state, password)
	assert.Nil(t, err, "marshaling the state should not produce an error")
	// it's encrypted; don't leak information through the state string
	importantStrings := []string{
		string(pkce),
		challenge,
		secret,
		sessionId,
		csrf,
		password,
	}
	for _, leak := range importantStrings {
		assert.False(t, strings.Contains(marshaled, leak), "the marshalled state should not contain leaks.")
	}
	unmarshaled, err := unmarshalOauthState(marshaled, password)
	assert.Nil(t, err, "unmarshalling the state should not produce an error")
	assert.True(t, assert.ObjectsAreEqualValues(state, unmarshaled), "unmarshalled state should be the same as the original")

}

// Test that the PKCE challenge and validator are correct.
// RFC 7636 4.2 says code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier))
func TestPKCEChallenge(t *testing.T) {
	plain, challenge, err := generatePKCE()
	assert.Nil(t, err, "generatePKCE should never err")
	validator := base64.RawURLEncoding.EncodeToString(plain)
	sum := sha256.Sum256([]byte(validator))
	encoded := base64.RawURLEncoding.EncodeToString(sum[:])
	assert.Equal(t, challenge, encoded, "verifier should verify challenge")
}

// tokenJSON is the struct representing the HTTP response from OAuth2
// providers returning a token or error in JSON form.
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type tokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	// error fields
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
	// ID Token
	// IDToken *oidc.IDToken `json:"id_token"`
	IDToken string `json:"id_token"`
}

// TODO: Use a better test server.
func fakeOauthServer(t *testing.T, redirect, clientId string) *httptest.Server {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	redirectUrl, err := url.Parse(redirect)
	if err != nil {
		panic(err)
	}
	srv := httptest.NewServer(nil)

	eng := gin.New()
	eng.GET("/oidc/.well-known/openid-configuration", func(c *gin.Context) {
		c.JSON(http.StatusOK, map[string]string{
			"issuer":                 srv.URL + "/oidc",
			"authorization_endpoint": srv.URL + "/oauth2/authorize",
			"token_endpoint":         srv.URL + "/oauth2/token",
			"userinfo_endpoint":      srv.URL + "/userinfo",
			"end_session_endpoint":   srv.URL + "/logout",
			"jwks_uri":               srv.URL + "/oidc/jwks",
		})
	})
	eng.GET("/oauth2/authorize", func(c *gin.Context) {
		values := url.Values{}
		values.Set("code", "test")
		values.Set("state", c.Query("state"))
		redirectUrl.RawQuery = values.Encode()
		c.Redirect(http.StatusFound, redirectUrl.String())
	})
	eng.POST("/oauth2/token", func(c *gin.Context) {
		// Standard OIDC claims
		claims := jwt.MapClaims{
			"iss":   srv.URL + "/oidc",                   // issuer
			"sub":   "1234567890",                        // subject (user ID)
			"aud":   clientId,                            // audience (client ID)
			"exp":   time.Now().Add(time.Hour).Unix(),    // expiration time
			"iat":   time.Now().Add(-time.Minute).Unix(), // issued at time
			"kid":   "test",                              // key ID
			"nonce": c.PostForm("nonce"),                 // nonce copied from the request
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed, _ := token.SignedString(priv)

		c.JSON(http.StatusOK, tokenJSON{
			AccessToken:      "test",
			TokenType:        "Bearer",
			RefreshToken:     "",
			ExpiresIn:        3600,
			ErrorCode:        "",
			ErrorDescription: "",
			ErrorURI:         "",
			IDToken:          signed,
		})
	})
	eng.GET("/oidc/jwks", func(c *gin.Context) {
		pubKey, _ := jwk.FromRaw(priv.Public())
		pubKey.Set(jwk.KeyIDKey, "test")
		pubKey.Set(jwk.AlgorithmKey, "RS256")
		pubKey.Set(jwk.KeyUsageKey, "sig")
		keys := jwk.NewSet()
		keys.AddKey(pubKey)

		c.JSON(http.StatusOK, keys)
	})

	srv.Config.Handler = eng
	return srv
}

// This test is intended to ensure that requests lacking the valid CSRF token fail.
// The first client will connect to the login handler and store the CSRF token is stored
// in the session. The second client represents either malicious actor who does not have access
// to the sessoin -- This is either a different client entirely or it is a different security context
// in the browser. We expect the second client to fail to pass the HandleRedirect handler since it does
// not have access to the necessary information stored in the session of the first client.
// This of course does not thouroughally test the CSRF mitigation, doesn't test browser behavior, etc.
func TestCSRFMitigation(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	t.Logf("Starting server at %s", srv.URL)
	redirect := srv.URL + "/callback"
	clientId := "clientID123456"
	authServer := fakeOauthServer(t, redirect, clientId)
	defer authServer.Close()
	t.Logf("Starting auth server at %s", authServer.URL)
	handlers := NewOauthHandlers(
		authServer.URL+"/oidc",
		clientId,
		"clientSecret123456",
		redirect,
		"http://example.com/logout",
		"pkceSecret",
		"loginSession",
		nil,
	)
	eng := gin.Default()
	memsessions := cookie.NewStore(random32(), random32())
	eng.Use(sessions.SessionsMany([]string{"loginSession"}, memsessions))
	eng.GET("/login", handlers.HandleLogin)
	eng.GET("/callback", handlers.HandleRedirect)
	eng.GET("/logout", handlers.HandleLogout)
	srv.Config.Handler = eng

	noRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	goodClient := http.Client{
		CheckRedirect: noRedirect,
	}
	badClient := http.Client{
		CheckRedirect: noRedirect,
	}
	// Step 1: Good Client logs in. CSRF token is in the the cookies.
	goodLoginResp, err := goodClient.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("failed to login: %v", err)
	}
	defer goodLoginResp.Body.Close()
	// Step 2: Good Client follows the redirect to the auth server and logs in.
	// gets an auth code
	goodAuthorizeResp, err := goodClient.Get(goodLoginResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("failed to authorize: %v", err)
	}
	// step 3. Good client follows the redirect to the callback, including cookies.
	goodRedirectReq, err := http.NewRequest(http.MethodGet, goodAuthorizeResp.Header.Get("Location"), nil)
	if err != nil {
		t.Fatalf("failed to create redirect request: %v", err)
	}
	for _, cookie := range goodLoginResp.Cookies() {
		goodRedirectReq.AddCookie(cookie)
	}
	goodRedirectResp, err := goodClient.Do(goodRedirectReq)
	if err != nil {
		t.Fatalf("failed to callback: %v", err)
	}
	// Happy path! The good client should have been logged in and gets a redirect to the protected URL.
	assert.Equal(t, http.StatusTemporaryRedirect, goodRedirectResp.StatusCode, "good client should have been redirected")
	// but the bad client has sniffed out the URL with the auth code in it. Make sure gets a failure.
	badRedirectResp, err := badClient.Get(goodAuthorizeResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("failed to authorize: %v", err)
	}
	assert.Equal(t, http.StatusBadRequest, badRedirectResp.StatusCode, "bad client should have been rejected")

}
