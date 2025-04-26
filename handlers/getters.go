package handlers

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// This file contains helper functions for users of this package to get information.
// Most of the functions simply get information out of the *gin.Context

var (
	ErrClaimNotExists = errors.New("claim not found in context")
	ErrKeyNotExists   = errors.New("key not found in context")
	ErrKeyWrongType   = errors.New("key is not of the expected type")
)

func GetAccessTokenStringFromContext(c *gin.Context) (string, error) {
	return GetStringFromContext(c, AccessTokenKey)
}

func GetRefreshTokenStringFromContext(c *gin.Context) (string, error) {
	return GetStringFromContext(c, RefreshTokenKey)
}

func GetIDTokenStringFromContext(c *gin.Context) (string, error) {
	return GetStringFromContext(c, IDTokenKey)
}

func GetSubjectFromContext(c *gin.Context) (string, error) {
	return GetStringFromContext(c, SubjectKey)
}

func GetStringFromContext(c *gin.Context, key string) (string, error) {
	idToken, exists := c.Get(key)
	if !exists {
		return "", ErrKeyNotExists
	}
	idTokenStr, ok := idToken.(string)
	if !ok {
		return "", ErrKeyWrongType
	}
	return idTokenStr, nil
}

func GetClaimsFromContext(c *gin.Context) (map[string]any, error) {
	claims, exists := c.Get(ClaimsKey)
	if !exists {
		return nil, ErrKeyNotExists
	}
	claimsMap, ok := claims.(map[string]any)
	if !ok {
		return nil, ErrKeyWrongType
	}
	return claimsMap, nil
}

func GetClaimFromContext(c *gin.Context, claim string) (any, error) {
	claims, err := GetClaimsFromContext(c)
	if err != nil {
		return nil, err
	}
	claimValue, exists := claims[claim]
	if !exists {
		return nil, ErrClaimNotExists
	}
	return claimValue, nil
}

func TokenSource(oh *OauthHandlers, ctx context.Context, refreshToken string) oauth2.TokenSource {
	return oh.oauth2config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	})
}
