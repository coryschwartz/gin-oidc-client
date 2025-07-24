package handlers

import (
	"context"

	"github.com/coryschwartz/gin-oidc-client/crypt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OauthHandlers struct {
	oauthLogoutUrl     string
	oauthRevocationUrl string
	oauthPKCESecret    string
	oauthSessionName   string
	oauth2config       *oauth2.Config
	verifier           *oidc.IDTokenVerifier
	oidcProvider       *oidc.Provider
	decrypter          crypt.TokenDecrypter
}

// OauthHandlers holds the configuration used by an Oauth/Oidc Client.
// oidcProvider:
//
//	This is the oidc discovery URL. Your OIDC provider shuold inform you what this URL should be.
//	The client will pull a configuration file at <oidcProvider>/.well-known/openid-configuration.
//
// oauthClientID:
//
//	This is a unique identifier representing account this application has with your oauth provider.
//
// oauthClientSecret:
//
//	Your application's password with the oauth provider. This is secret. Don't give it to anyone.
//
// oauthRedirectUrl:
//
//	This is sometiems also called the "callback" url. When you register your application with
//	the oauth provider, you will have to inform them what the redirect URL is, and we need to pass
//	the same URL. It should be set to the URL where users can connect to your application where the
//	HandleRedirect handler is listening.
//
// oauthLogoutUrl:
//
//	Where should users go after they log out? Check if your oauth provider has a logout endpoint.
//	If they do, you should set that URL here. If set to an empty string, I'll try to figure it out
//	using the openidc provider metadata. No promises.
//
// oauthPKCESecret:
//
//	PKCE (RFC7636) is a good security practice. The general idea is that in the first Oauth phase,
//	we pass a hash sum to the auth server. Then, when we do token exchange we pass the original data.
//	The auth server can then know that both requests came from the same place. Generally, you have to
//	store this data somehow. In this implementation, we are stuffing this data into the state and
//	encrypting it. This is the encryption key. This is an implementation detail.
//
// oauthSessionName:
//
//	We're using gin-contrib/sessions to store the oidc idtoken and other data to the session. You should
//	create a session using whatever storage medium you wish. Use encryption if able. Use this variable
//	to tell us which session you want login information to be stored.
//
// oauthScopes:
//
//	A list of scopes we should request the auth server to send us. Just because you request it, doesn't
//	mean the auth server will oblige. Your oauth server documentation will tell you what scopes are
//	available. When you add additional scopes, the auth server will return additional claims
//	during token exchange. The content of the claims are various. If you use the MiddlewareRequireLogin,
//	you will find the claims are made available as a gin context value.
func NewOauthHandlers(
	oidcProvider,
	oauthClientID,
	oauthClientSecret,
	oauthRedirectUrl,
	oauthLogoutUrl,
	oauthPKCESecret,
	oauthSessionName string,
	oauthScopes []string) (*OauthHandlers, error) {

	opts := []OauthHandlersOption{
		WithOauthSessionName(oauthSessionName),
		WithOauthPKCESecret(oauthPKCESecret),
	}
	provider, err := oidc.NewProvider(context.Background(), oidcProvider)
	if err != nil {
		return nil, err
	}
	opts = append(opts, WithOidcProvider(provider))
	claims := make(map[string]any)
	provider.Claims(&claims)
	if oauthLogoutUrl == "" {
		// This key is *not* in the documented provider metadata
		// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
		// However, sometimes it is used.
		if val, ok := claims["end_session_endpoint"].(string); ok {
			oauthLogoutUrl = val
		} else {
			oauthLogoutUrl = "/"
		}
	}
	opts = append(opts, WithOauthLogoutUrl(oauthLogoutUrl))
	// Sometimes, there is a revocation endpoint. Sometimes.
	// This endpoint can be used to revoke individual tokens.
	if val, ok := claims["revocation_endpoint"].(string); ok {
		opts = append(opts, WithOauthRevocationUrl(val))
	}
	oauth2config := &oauth2.Config{
		ClientID:     oauthClientID,
		ClientSecret: oauthClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  oauthRedirectUrl,
		Scopes:       append([]string{oidc.ScopeOpenID}, oauthScopes...),
	}
	opts = append(opts, WithOauth2Config(oauth2config))
	verifier := provider.Verifier(&oidc.Config{
		ClientID: oauth2config.ClientID,
	})
	opts = append(opts, WithVerifier(verifier))
	opts = append(opts, WithTokenDecrypter(&crypt.NullDecrypter{})) // Default to no JWE support.
	return NewOauthHandlersWithOptions(opts...)
}

func NewOauthHandlersWithOptions(opts ...OauthHandlersOption) (*OauthHandlers, error) {
	oh := new(OauthHandlers)
	for _, opt := range opts {
		if err := opt(oh); err != nil {
			return nil, err
		}
	}
	return oh, nil
}

type OauthHandlersOption (func(*OauthHandlers) error)

func WithOauthLogoutUrl(logoutUrl string) OauthHandlersOption {
	return func(oh *OauthHandlers) error {
		oh.oauthLogoutUrl = logoutUrl
		return nil
	}
}

func WithOauthRevocationUrl(revocationUrl string) OauthHandlersOption {
	return func(oh *OauthHandlers) error {
		oh.oauthRevocationUrl = revocationUrl
		return nil
	}
}

func WithOauthPKCESecret(pkcesecret string) OauthHandlersOption {
	return func(oh *OauthHandlers) error {
		oh.oauthPKCESecret = pkcesecret
		return nil
	}
}

func WithOauthSessionName(sessionName string) OauthHandlersOption {
	return func(oh *OauthHandlers) error {
		oh.oauthSessionName = sessionName
		return nil
	}
}

func WithOauth2Config(oauth2config *oauth2.Config) OauthHandlersOption {
	return func(oh *OauthHandlers) error {
		oh.oauth2config = oauth2config
		return nil
	}
}

func WithVerifier(verifier *oidc.IDTokenVerifier) OauthHandlersOption {
	return func(oh *OauthHandlers) error {
		oh.verifier = verifier
		return nil
	}
}

func WithOidcProvider(oidcProvider *oidc.Provider) OauthHandlersOption {
	return func(oh *OauthHandlers) error {
		oh.oidcProvider = oidcProvider
		return nil
	}
}

func WithTokenDecrypter(decrypter crypt.TokenDecrypter) OauthHandlersOption {
	return func(oh *OauthHandlers) error {
		oh.decrypter = decrypter
		return nil
	}
}
