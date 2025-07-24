package crypt

import (
	"context"
)

var (
	_ TokenDecrypter = (*NullDecrypter)(nil) // Ensure NullDecrypter implements TokenDecrypter interface
)

// NullDecrypter is a no-op implementation of TokenDecrypter.
type NullDecrypter struct{}

// No decryption is performed, simply return the input token as is.
func (nd *NullDecrypter) DecryptToken(ctx context.Context, encToken []byte) ([]byte, error) {
	return encToken, nil
}
