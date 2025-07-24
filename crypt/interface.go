package crypt

import (
	"context"
)

type TokenDecrypter interface {
	DecryptToken(context.Context, []byte) ([]byte, error)
}
