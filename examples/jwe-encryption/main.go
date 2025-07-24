package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"os"

	"crypto/sha256"

	"github.com/coryschwartz/gin-oidc-client/crypt"
	"github.com/coryschwartz/gin-oidc-client/handlers"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"net/http"
)

// This example builds on the using-handlers example, adds a few more features that are specific for
// decrypting encrypted tokens.
//
// To handle encrypted tokens, we need to instantiate a TokenDecrypter.
// The TokenDecrypter has a method that can, as you might expect, decrypt tokens.
// It requires a little more setup and integration with your OIDC provider, and each one is a little different.
// In general, you're going to generate one or public/private key pairs. Keep the private key to yourself, and give
// the public key to your auth server.
// Many auth servers will provide a web portal where you can upload a key.
// If you happen to be using OpenIDConnect with automated registration, you might be able to point your auth auth
// server to a JWKS endpoint so it can obtain public keys this way. We can do both.

// This example will load a key from disk, create oauth handlers with verbose options, and expose a JWKS endpoint.

var (
	// you need to replace at *least* these three variables.
	// These are provided just as an example. Your actual values will come from your OIDC provider.
	oidcProvider      = "http://localhost:9000/application/o/example/"
	oauthClientID     = "YOC27qqLBmtmInrCc2ueoHwgVzZDAU5PcH0uwpBx"
	oauthClientSecret = "qlPpK3FOMCPcBXuaZ033TBkwmeWTgdHrh60MPZlgPRxICPYbNHlUNHzaBqCQ65CrNvBkRaRCWpKLWs6Umr4MXHvYPaO6DKLJQr8nKcJYIuiMmW9lzPsxGOD23eBr3eM7"

	// Where is my key?
	JweKeyLocation = "./private.key"

	oauthRedirectUrl = "http://localhost:8080/oauth/redirect"
	oauthLogoutUrl   = ""
	oauthPKCESecret  = "some junk"
	oauthSessionName = "login"
	oauthScopes      = []string{"profile", "email"}
	sessionSigning   = "some more junk"
	sessionEncrypt   = "even more junk"
)

func main() {
	session_sign_key := sha256.Sum256([]byte(sessionSigning))
	session_encryption_key := sha256.Sum256([]byte(sessionEncrypt))
	sessionStore := memstore.NewStore(session_sign_key[:], session_encryption_key[:])

	engine := gin.Default()
	engine.Use(sessions.SessionsMany([]string{oauthSessionName}, sessionStore))

	// open JweKeyLocation and create an rsa private key
	key, err := readRSAPrivateKeyFromFile(JweKeyLocation)
	if err != nil {
		panic(fmt.Sprintf("failed to read private key: %v", err))
	}
	// each jwks key has an identifier. Use a signature, a UUIDv4, or something else.
	// Your auth server might ask you to provde an identifier, or it might generate one for you.
	keyId := "wowThats1UniqueKey"

	// Create a the decrypter with the private key.
	// This decrypter is used to decrypt tokens and also to provide the JWKS endpoint if you need it!
	// don't forget to configure your auth server with the public key!
	jwksDec, err := crypt.NewJwksSetDecrypterFromKey(key, keyId)
	if err != nil {
		panic(err)
	}

	provider, err := oidc.NewProvider(context.Background(), oidcProvider)
	if err != nil {
		panic(fmt.Sprintf("failed to create OIDC provider: %v", err))
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID: oauthClientID,
	})

	// Create oauth handlers including our decrypter.
	opts := []handlers.OauthHandlersOption{
		handlers.WithOauth2Config(&oauth2.Config{
			ClientID:     oauthClientID,
			ClientSecret: oauthClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  provider.Endpoint().AuthURL,
				TokenURL: provider.Endpoint().TokenURL,
			},
			RedirectURL: oauthRedirectUrl,
			Scopes:      append([]string{oidc.ScopeOpenID}, oauthScopes...),
		}),
		handlers.WithOauthLogoutUrl("http://localhost:9000/application/o/example/end-session/"),
		handlers.WithOauthSessionName(oauthSessionName),
		handlers.WithOauthPKCESecret(oauthPKCESecret),
		handlers.WithOidcProvider(provider),
		handlers.WithVerifier(verifier),
		handlers.WithTokenDecrypter(jwksDec), // <-------don't forget!
	}
	oh, err := handlers.NewOauthHandlersWithOptions(opts...)
	if err != nil {
		panic(err)
	}

	// These three handlers  need to be setup for OAUTH to work.
	engine.GET("/oauth/login", oh.HandleLogin)
	engine.GET("/oauth/redirect", oh.HandleRedirect)
	engine.GET("/oauth/logout", oh.HandleLogout)

	// Unprotected area
	engine.GET("/", rootHandler)

	// JWKS endpoint. public keys on display.
	engine.GET("/.well-known/jwks.json", jwksDec.HandleJWKS)

	// login-only area
	protected := engine.Group("/protected")
	protected.Use(oh.MiddlewareRequireLogin("/oauth/login"))

	protected.GET("/whoami", userDetail)

	engine.Run(":8080")
}

func rootHandler(c *gin.Context) {
	c.Writer.Write([]byte("sup, nerds!"))
}

// This function shows information that is available after login automatically.
// This function doesn't do any extra API calls to get the information.
func userDetail(c *gin.Context) {
	// Information about the user is stored in the session.
	// If you know what keys to look for, you can get it directly, like this:
	// subject, found := c.Get("subject")
	// claims, found := c.Get("claims")
	// You can also use the helper functions, which will comfortably cast the values for you.
	subject, err := handlers.GetSubjectFromContext(c)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error getting subject: %v", err)
		return
	}
	claims, err := handlers.GetClaimsFromContext(c)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error getting claims: %v", err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{
		"subject": subject,
		"claims":  claims,
	})
}

// the provided make-self-signed-cert.sh creates a private key that you can likely copy to your
// auth server. This function reads the private key and creates creates a *crypto/rsa.PrivateKey
func readRSAPrivateKeyFromFile(filePath string) (*rsa.PrivateKey, error) {
	// Step 1: Read the PEM file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read all bytes from the file
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	fileBytes := make([]byte, fileInfo.Size())
	_, err = file.Read(fileBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Step 2: Decode the PEM block
	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Step 3: Parse the PEM block to an RSA private key
	var privateKey *rsa.PrivateKey

	// PKCS#1 format (traditional)
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		privateKey = key
	} else {
		// PKCS#8 format (modern)
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		// The parsed key could have different types (e.g. ECDSA), so check it's RSA.
		var ok bool
		privateKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
	}

	return privateKey, nil
}
