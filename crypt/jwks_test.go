package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Generate crypto keys and return JWKS key sets for private and public keys.
func generateJwksKeySet(numKeys int) (privSet jwk.Set, pubSet jwk.Set, err error) {
	privSet = jwk.NewSet()
	pubSet = jwk.NewSet()

	for range numKeys {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate the private key: %w", err)
		}

		// determine a key id.
		pkcsPub := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
		keyId := fmt.Sprintf("%x", sha256.Sum256(pkcsPub))

		// Create a JWK from the RSA private key
		jwkKey, err := jwk.Import(privateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create JWK: %w", err)
		}
		if err = jwkKey.Set("kid", keyId); err != nil {
			return nil, nil, fmt.Errorf("failed to set key ID: %w", err)
		}
		// and the public key with the same key ID.
		jwkPubKey, err := jwkKey.PublicKey()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get public key from JWK: %w", err)
		}

		// Add to keysets.
		if err = privSet.AddKey(jwkKey); err != nil {
			return nil, nil, fmt.Errorf("failed to add private key to set: %w", err)
		}
		if err = pubSet.AddKey(jwkPubKey); err != nil {
			return nil, nil, fmt.Errorf("failed to add public key to set: %w", err)
		}
	}

	return privSet, pubSet, nil
}

// Test that every key in the encrypting set is decryptable using a decrypter setup with the decryption set.
// Loop over every key in the encrypting set
// encrypt a message using the encrypting key.
// Decrypt the message using the decrypter.
func encDecLoop(t *testing.T, encSet, decSet jwk.Set) {
	jcd := NewJwksSetDecrypter(decSet)
	for _, kid := range encSet.Keys() {
		message := []byte("test message...")

		// private key to encrypt the message
		encKey, ok := encSet.LookupKeyID(kid)
		if !ok {
			t.Fatalf("failed to find key with ID %s in encryption key set", kid)
		}
		// encrypt a JWE token using the private key.
		encryptOptions := []jwe.EncryptOption{
			jwe.WithKey(jwa.RSA_OAEP(), encKey),
		}
		encToken, err := jwe.Encrypt(message, encryptOptions...)
		assert.NoError(t, err, "failed to encrypt message")

		// decrypt the JWE token using the decrypter.
		dec, err := jcd.DecryptToken(t.Context(), encToken)
		assert.NoError(t, err, "failed to decrypt token")
		assert.Equal(t, message, dec, "decrypted message should match original")
	}
}

func TestJwksDecrypter(t *testing.T) {
	t.Run("encrypt with public, decrypt with private (typical for JWE, RFC 7516 sec. 5)", func(t *testing.T) {
		privSet, pubSet, err := generateJwksKeySet(10)
		if err != nil {
			t.Fatalf("failed to generate JWKS key sets: %v", err)
		}
		encDecLoop(t, pubSet, privSet)
	})
	t.Run("encrypt with private, decrypt with public (unusual use case)", func(t *testing.T) {
		privSet, pubSet, err := generateJwksKeySet(10)
		if err != nil {
			t.Fatalf("failed to generate JWKS key sets: %v", err)
		}
		encDecLoop(t, privSet, pubSet)
	})
}

func TestJwksSetJwksHandler(t *testing.T) {
	privSet, pubSet, err := generateJwksKeySet(10)
	require.NoError(t, err, "failed to generate JWKS key sets")

	jcd := NewJwksSetDecrypter(privSet)
	recorder := httptest.NewRecorder()

	gin.SetMode(gin.TestMode)
	eng := gin.New()

	eng.GET("/.well-known/jwks.json", jcd.HandleJWKS)

	req, err := http.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	require.NoError(t, err, "failed to create request")

	eng.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code, "expected 200 OK response")

	// Parse the retrieved JWKS
	retrievedSet, err := jwk.Parse(recorder.Body.Bytes())
	require.NoError(t, err, "failed to parse JWKS response")

	t.Run("jwks should host all the public keys", func(t *testing.T) {
		assert.Equal(t, pubSet.Len(), retrievedSet.Len(), "retrieved JWKS set should have same number of keys as expected public set")
	})

	t.Run("jwks should only host public keys", func(t *testing.T) {
		for i := range retrievedSet.Keys() {
			key, ok := retrievedSet.Key(i)
			require.True(t, ok, "failed to get key from retrieved JWKS set")
			var isPublic bool
			switch key.(type) {
			case jwk.RSAPublicKey:
				isPublic = true
			default:
				isPublic = false
			}
			require.True(t, isPublic, "retrieved key should be a public key")
		}
	})
	t.Run("jwks public keys should correspond to the private keys", func(t *testing.T) {
		encDecLoop(t, retrievedSet, privSet)
	})
}
