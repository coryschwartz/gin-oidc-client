# Easy Oauth/Oidc on with for Gin servers.

There are plenty of go modules that handle oauth token exchange, and support various flows. Likewise for OIDC, the identity protocol
that runs on top of it. There is, however, a dirth of ready-to-go handlers. What's more, if authentication isn't something you're
truely interested in, there is a dizzying amount of documentation stretching back over a decade. You could spend hours...days even... pouring over documentation
Flows? Codes? Assertions? Tokens? Ahh! And what do I even do with tokens once I've gotten them?

If you have specific requirements, want implicit flows or otherwise. Sorry, probably might what you want.
If you find yourself saying "dude, come on, I don't want to know how many legs oauth has. I just want a some way to tell me if users are logged in."
then maybe this repo is worth investigating.

This repo will turn your basic gin web application into a convidential Oauth client that obtain user information from an OIDC provider. Just what you needed!

It turns out that, at least for web applications, a lot of applications that need to authenticate users need basic access to account details, and the auth server
does all the complex dirty work. So I hope this fits the bill for applications with unexceptional, easy to understand authentication requirements. I intend to help
you establish a sane baseline that works without too much hassle. Take a look at the example to see just how easy it is.

# Try the example.

Let's setup the example in this repo to authenticate against Google.

1. Create an application with the auth provider. In the case of Google, you need to do it here:
https://console.cloud.google.com/auth/clients


2. Create a new Oauth App.

```
Application Type: Web application
Name: Anything you want
Authorized redirect URIs: http://localhost:8080/oauth/redirect
```

3. Gather information

Your authentication service will generate a client ID and secret for you Copy that down!

```
Client ID:         This is the account that your application has with the auth server.
Client Secrets:    This is the password your application has with the app server.
```

Finally, you need to know the OIDC Provider.
For google, it's `https://accounts.google.com`

4. Edit the example.

open up examples/using-handlers/main.go

Edit it with your information. It'll look something like this:

```

var (
	// you need to replace at *least* these three variables.
	oidcProvider      = "https://accounts.google.com"
	oauthClientID     = "111111111111-iamareeeeeeeeeeeealylongusername.apps.googleusercontent.com"
	oauthClientSecret = "GOCSPX-S3cR3tp/\$$W0RDNn5kDMfto1SII"

	oauthRedirectUrl = "http://localhost:8080/oauth/redirect"
...
```

5. Visit the protected resource in your web browser.

```
go run examples/using-handlers/main.go
```

and navigate your browser to http://localhost:8080/protected/whoami


If all is working correctly, you'll be redirected to google where you can log in, then redirected back. Once you're back, the application will have access to a little
bit of your account information.


hint: Play with the claims!

# NOTE: Use a secure session!

This implementation places id_token and access_token in the session. The security of the session is what makes this this a confidentail oauth client. You MUST use a secure session for this purpose.
Particularly if you are using cookie sessions, you need to enable encryption. Failure to do so will result in dire security consiquences. Your dog will catch fire. Your hair will begin to grow at an
exponential rate. Your girlfriend will break up with you. Your mom will forget your birthday. The sun will dry up all the oceans before it becomes supernova. Do it.

# How do I know who is logged in?

Using the provided middleware, you can get access to user details using gin values.

```go
func(c *gin.Context) {
    user := c.Get("subject")
}
```

# ahem. I didn't mean account number. How do know the *name* of who is logged in.

You probably need the profile scope. "profile" to the oauth scopes in the example, and try again.
Most auth servers use this scope to include information such as the user's name. 


# How do I allow certain users to do certain things

I recommend that you do this at the auth server. Most auth servers will have some mechanism saying that users belong to groups, or teams, roles, etc. and
you can apply permissions at that level.

However, *some* auth servers will allow you to membersips, which you could use to enforce permissions. Your milage may vary.

```go
oauthScopes = []string{"profile", "groups", "email"}

...

func(c gin.Context) {
    claims := c.Get("claims")
    groups := claims["groups"].([]string)
    for _, group := range groups {
	if group == "reallycoolpeople" {
	    doSomething()
	    break
	}
    }
}
```

# Implementation decisions

These are some of the design decisions I made and a little justification.

* "Login" not "Authorize" -- I'm thinking about user login, not necessarially third party delegation. Although, the access_token is also delivered.
* Token Security -- I have to admit that this implementaion punts this issue to the user. I give an option to use a specific named session, which I hope is encryped and otherwise secured.
* State includes the next url -- Not a requirement in the specs, but it's a common practice and it makes sense for the middleware case so you can go away to authenticate and come back to the same place.
* Optional features -- This implementation uses PKCE, which is optional for auth code flows, and uses the OIDC nonce checking. There could be an odd auth server that doesn't play well with these. However,
  I decided include these features in this implementation. There are a few more slices on the swiss cheese model.
* The encrypted state with pkce challenge. See below.
* Automatic access token refresh? -- Nope. Some authentication servers (authentik) require a specific scope. Others don't support it at all. If you want "offline" access, you're on your own.


# What's going on with the PKCE challenge?

This implementation uses an aditional secret you might not see in other implementations, so it deserves a little explanation.

The general idea behind PKCE that you generate some random data and then make a hash of it and you use that to prove to the auth server that you're the same source.

The first message you send to the auth server via the HTTP redirect contains the hash.
The second message you send to the auth server during code exchange contains the original.

The auth server can verify that the guy doing code exchange is the same one who sent the first message. 
If you don't use PKCE, then you will have to simply log into the auth server using your "client secret" and the auth server will verify you that way. I think using PKCE is still a good idea in case
your client secret is accidently committed to git and has been compromised, the auth server can still validate that you have initiated the flow using this second method.

One possibility is to simply use the SessionID as the the PKCE verifier. That's unique and unknown to the auth server right? This is a bad idea. The browser also knows what the session ID, so a
misbehaving browser would have enough information to generate PKCE challenges. No, this won't do -- we need to generate a PKCE challenge independently and store it in a way that nobody but us can access it.
This means it needs to be encrypted and can be placed either in the state or into session storage. I've chosen to use the state for this purpose since this is such a transitory secret and I wanted to be sure
it wasn't cluttering up the browser or asking the browser re-transmit it in a cookie on subsequent requests. There is an obvous downside to using the state as a storage medium -- the URLs are longer.

I've chosen to use an encryption scheme that uses a secret (the pkce secret) paired with the session to derive an encryption key. This scheme serves a double duty as part of the CSRF forgery
mitigation. The auth server can't decrypt the state ever. The browser can't decrypt the state because they don't know the pkce secret. We can't decrypt ourselves if the state if it's tried in the wrong session.

In a similar fashion, I use this challenge to generate the token Nonce. I generate the Nonce at the beginning of the process in the Login handler and send that along to the auth server. I expect a well-behaved
auth server to include this Nonce during token exchagne. After I get the token, I genrate the Nonce again and compare it to the one in the token. A well-behaved auth server will sign this nonce and return
it back to me, and I'm confident that the token I'm receiving is a response to the request I initiated and it is untampered.

# See a bug? Tell me.

If you see something in this code that you don't like. A bug? A flaw in my thinking? A missing feature? Please let me know by opening an issue or sending me an email.
