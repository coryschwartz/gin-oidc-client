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
	oauthClientID     = "IlGGjmXSFkQRyLphxoCM90aQtAx3i9X7Gk6GoOIY"
	oauthClientSecret = "aGIKi0XYbUq7UKTfhUKOBIPpcoIfIDUeE7o0vp2aKNvj4foZ8UlYhU4xVxIDrHoxLkOfyA4vQtXy8CUEjCl1mHfD2RPmFgObjVoiiZKvZ5eANDxY29BM8BakHxsb7FcN"

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

	oh, err := handlers.NewOauthHandlers(
		oidcProvider,
		oauthClientID,
		oauthClientSecret,
		oauthRedirectUrl,
		oauthLogoutUrl,
		oauthPKCESecret,
		oauthSessionName,
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

	engine.Run(":8080")
}

func rootHandler(c *gin.Context) {
	c.Writer.Write([]byte("sup, nerds!"))
}

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
