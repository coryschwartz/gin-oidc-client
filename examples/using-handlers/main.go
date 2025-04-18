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
	oidcProvider      = ""
	oauthClientID     = ""
	oauthClientSecret = ""

	oauthRedirectUrl = "http://localhost:8080/oauth/redirect"
	oauthLogoutUrl   = ""
	oauthPKCESecret  = "some junk"
	oauthSessionName = "login"
	oauthScopes      = []string{"profile", "email"}
	sessionSigning   = "some more junk"
	sessionEncrypt   = "even more junk"
)

func main() {
	session_sign_key := sha256.Sum256([]byte(sessionSigning))
	session_encryption_key := sha256.Sum256([]byte(sessionEncrypt))
	sessionStore := memstore.NewStore(session_sign_key[:], session_encryption_key[:])

	engine := gin.Default()
	engine.Use(sessions.SessionsMany([]string{oauthSessionName}, sessionStore))

	oh := handlers.NewOauthHandlers(
		oidcProvider,
		oauthClientID,
		oauthClientSecret,
		oauthRedirectUrl,
		oauthLogoutUrl,
		oauthPKCESecret,
		oauthSessionName,
		oauthScopes,
	)

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

	engine.Run(":8080")
}

func rootHandler(c *gin.Context) {
	c.Writer.Write([]byte("sup, nerds!"))
}

func userDetail(c *gin.Context) {
	subject, _ := c.Get("subject")
	claims, _ := c.Get("claims")
	c.IndentedJSON(http.StatusOK, gin.H{
		"subject": subject,
		"claims":  claims,
	})
}
