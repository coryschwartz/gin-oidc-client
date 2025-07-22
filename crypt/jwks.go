package crypt

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var _ TokenDecrypter = (*JwksSetDecrypter)(nil)

// JwksSetDecrypter is a TokenDecrypter that uses a JWK set to decrypt JWE tokens.
// In many oauth scenarios where JWE tokens are used, the authorization server will
// be configured with the public key of the client and will use that key to encrypt tokens.
// The Oauth client (that's us!) will have access to the private key which it can use to decrypt tokens.
type JwksSetDecrypter struct {
	set jwk.Set
}

// Constructs a JwksSetDecrypter connects to a JWKS endpoint and retrieves the JWK set.
// The JWKS endpoint is polled to keep the cache relatively fresh.
// You probably do *not* want to use this. The JWKS endpoint you point this at will probably contain a
// set of *public* keys.
func NewJwksCacheDecrypter(ctx context.Context, jwksUrl string, minInterval, maxInterval time.Duration) (*JwksSetDecrypter, error) {
	clientOpts := []httprc.NewClientOption{}
	client := httprc.NewClient(clientOpts...)
	jwksCache, err := jwk.NewCache(ctx, client)
	if err != nil {
		return nil, err
	}
	registerOpts := []jwk.RegisterOption{
		jwk.WithWaitReady(true),
		jwk.WithMinInterval(minInterval),
		jwk.WithMaxInterval(maxInterval),
	}
	err = jwksCache.Register(ctx, jwksUrl, registerOpts...)
	if err != nil {
		return nil, err
	}
	cachedSet, err := jwksCache.CachedSet(jwksUrl)
	if err != nil {
		return nil, err
	}
	return NewJwksSetDecrypter(cachedSet), nil
}

// construct a JwksSetDecrypter with a single key.
// The key can be any raw key supported by the jwx library.
// This is useful for auth servers such as Auth0, or Authentik that support JWE
// by importing or generating a single certificate.
// rawKey is expected to be a private key.
// keyId is an optional string identifier for the key.
func NewJwksSetDecrypterFromKey(rawKey any, keyId string) (*JwksSetDecrypter, error) {
	key, err := jwk.Import(rawKey)
	if err != nil {
		return nil, err
	}
	if keyId != "" {
		key.Set(jwk.KeyIDKey, keyId)
	}
	set := jwk.NewSet()
	if err = set.AddKey(key); err != nil {
		return nil, err
	}
	return NewJwksSetDecrypter(set), nil
}

// construct a JwksSetDecrypter with a JWK set you've already obtained.
func NewJwksSetDecrypter(set jwk.Set) *JwksSetDecrypter {
	return &JwksSetDecrypter{
		set: set,
	}
}

func (jcd *JwksSetDecrypter) DecryptToken(ctx context.Context, encToken []byte) ([]byte, error) {
	decryptOpts := []jwe.DecryptOption{
		jwe.WithKeySet(jcd.set),
	}
	return jwe.Decrypt(encToken, decryptOpts...)
}

// HandleJWKS creates a Gin handler that serves the public keys from a JWK set
// as a JWKS endpoint. This is useful for OIDC dynamic client registration where
// the authorization server needs to fetch the client's public keys for encryption.
//
// The handler will:
// - Extract only public keys from the set (filters out private key material)
// - Return proper JWKS JSON format with "keys" array
// - Set appropriate cache headers
// - Handle errors gracefully
//
// Usage:
//
//	router.GET("/.well-known/jwks.json", decrypter.HandleJWKS)
func (jcd *JwksSetDecrypter) HandleJWKS(c *gin.Context) {
	// Create a new set containing only public keys
	publicSet := jwk.NewSet()

	for i := range jcd.set.Len() {
		key, ok := jcd.set.Key(i)
		if !ok {
			continue // huh?
		}
		pubKey, err := key.PublicKey()
		if err != nil {
			c.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to extract public key",
			})
			return
		}
		err = publicSet.AddKey(pubKey)
		if err != nil {
			c.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to add public key to JWKS set",
			})
			return
		}

	}

	// Set appropriate headers
	c.Header("Content-Type", "application/json")
	c.Header("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	c.Header("Access-Control-Allow-Origin", "*")      // Allow CORS for auth servers

	// Return the JWKS
	c.JSON(http.StatusOK, publicSet)
}
