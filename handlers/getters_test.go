package handlers

import (
	"fmt"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestGetStringTokens(t *testing.T) {
	tests := []struct {
		Key    string
		Getter func(*gin.Context) (string, error)
	}{
		{Key: AccessTokenKey, Getter: GetAccessTokenStringFromContext},
		{Key: RefreshTokenKey, Getter: GetRefreshTokenStringFromContext},
		{Key: IDTokenKey, Getter: GetIDTokenStringFromContext},
	}
	for _, test := range tests {
		t.Run(test.Key, func(t *testing.T) {
			c := &gin.Context{}
			value := fmt.Sprintf("test_%s", test.Key)
			c.Set(test.Key, value)
			got, err := test.Getter(c)
			assert.NoError(t, err, "should not return an error")
			assert.Equal(t, value, got, "should return the correct value")
		})
	}
}

func TestGetClaim(t *testing.T) {
	claims := map[string]any{
		"claim1": "value1",
	}
	c := &gin.Context{}
	c.Set(ClaimsKey, claims)
	got, err := GetClaimFromContext(c, "claim1")
	assert.NoError(t, err, "should not return an error")
	assert.Equal(t, "value1", got, "should return the correct value")
}
