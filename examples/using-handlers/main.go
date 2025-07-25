package main

import (
	"crypto/sha256"
	"github.com/coryschwartz/gin-oidc-client/handlers"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"net/http"
)

var (
	// you need to replace at *least* these three variables.
	// These are provided just as an example. Your actual values will come from your OIDC provider.
	oidcProvider      = "http://localhost:9000/application/o/example/"
	oauthClientID     = "YOC27qqLBmtmInrCc2ueoHwgVzZDAU5PcH0uwpBx"
	oauthClientSecret = "qlPpK3FOMCPcBXuaZ033TBkwmeWTgdHrh60MPZlgPRxICPYbNHlUNHzaBqCQ65CrNvBkRaRCWpKLWs6Umr4MXHvYPaO6DKLJQr8nKcJYIuiMmW9lzPsxGOD23eBr3eM7"

	oauthRedirectUrl = "http://localhost:8080/oauth/redirect"
	oauthScopes      = []string{"profile", "email"}

	sessionSigning = "some more junk"
	sessionEncrypt = "even more junk"
)

func main() {
	session_sign_key := sha256.Sum256([]byte(sessionSigning))
	session_encryption_key := sha256.Sum256([]byte(sessionEncrypt))
	sessionStore := memstore.NewStore(session_sign_key[:], session_encryption_key[:])

	engine := gin.Default()
	engine.Use(sessions.SessionsMany([]string{"login"}, sessionStore))

	oh, err := handlers.NewOauthHandlers(
		oidcProvider,
		oauthClientID,
		oauthClientSecret,
		oauthRedirectUrl,
		oauthScopes,
	)
	if err != nil {
		panic(err)
	}

	// These three handlers  need to be setup for OAUTH to work.
	engine.GET("/oauth/login", oh.HandleLogin)
	engine.GET("/oauth/redirect", oh.HandleRedirect)
	engine.GET("/oauth/logout", oh.HandleLogout)

	// Unprotected area
	engine.GET("/", rootHandler)

	// login-only area
	protected := engine.Group("/protected")
	protected.Use(oh.MiddlewareRequireLogin("/oauth/login"))

	protected.GET("/whoami", userDetail)
	protected.GET("/expensivewhoami", userInfo)

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

// This function hits the userinfo endpoint of the OIDC provider.
// This requires an additional API call to the auth provider, so it's not done automatically.
func userInfo(c *gin.Context) {
	info, err := handlers.UserInfoFromContext(c)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error getting userinfo: %v", err)
		return
	}
	claimMap := make(map[string]any)
	if err := info.Claims(&claimMap); err != nil {
		c.String(http.StatusInternalServerError, "Error parsing userinfo claims: %v", err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{
		"info":   info,
		"claims": claimMap,
	})
}
