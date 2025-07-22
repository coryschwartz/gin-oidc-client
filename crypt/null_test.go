package crypt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// The Null decryptor does not decrypt anything.
func TestNullDecryptPassthrough(t *testing.T) {
	nd := NullDecrypter{}
	token := []byte("test-token-abc123")
	NewToken, err := nd.DecryptToken(t.Context(), token)
	assert.Nil(t, err, "expected no error during nil decryption")
	assert.Equal(t, token, NewToken, "expected the token to remain unchanged during nil decryption")
}
