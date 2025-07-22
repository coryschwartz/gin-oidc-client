package crypt

import (
	"errors"
)

var (
	ErrNoKeyIDInJWE = errors.New("JWE token does not specify a key ID")
)
