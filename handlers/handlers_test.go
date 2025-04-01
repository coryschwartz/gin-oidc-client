package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"net/url"
	"strings"
	"testing"
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
		CSRF:      csrf,
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
