# OhAuth

[![GoDoc](https://godoc.org/github.com/disintegrator/ohauth?status.png)](https://godoc.org/github.com/disintegrator/ohauth)

OAuth 2 provider library for Go as defined in [RFC 6749][6].

This library intends to define a stricter type of OAuth providers that follow
recommendations from various researchers (see references)

## Example Usage

The following example shows how to setup a provider with some test clients and
install the handlers into a gin app. The implementation of the Authenticator
(created by `NewDefaultAuthenticator`) is left as an exercise for the reader.


    package main

    import (
        "fmt"
        "net/http"

        "github.com/disintegrator/ohauth"
        "github.com/gin-gonic/gin"
    )

    func main() {
        authz := ohauth.MustParseURL("https://authz.saas.dev:3000/oauth")
        authn := ohauth.MustParseURL("https://authn.saas.dev:3000/")
        s, err := ohauth.NewTestingStore()
        if err != nil {
            panic(err)
        }

        ac := createClient(s, ohauth.AuthorizationCode)
        ic := createClient(s, ohauth.Implicit)
        pc := createClient(s, ohauth.Password)
        cc := createClient(s, ohauth.ClientCredentials)

        a, err := NewDefaultAuthenticator(authn)
        if err != nil {
            panic(err)
        }
        p := ohauth.NewProvider(authz, a, s)

        e := gin.Default()
        e.Group("/oauth").Any("*action", gin.WrapH(p.Handler()))
        e.GET("/_health", func(c *gin.Context) {
            c.String(http.StatusOK, "ok")
        })

        fmt.Printf("Authorization code client registered with id: %s - %s\n", ac.ID, ac.Secret)
        fmt.Printf("Implicit client registered with id: %s - %s\n", ic.ID, ic.Secret)
        fmt.Printf("Password client registered with id: %s - %s\n", pc.ID, pc.Secret)
        fmt.Printf("Client credentials client registered with id: %s - %s\n", cc.ID, cc.Secret)
        e.Run(":3000")
    }


## References

- [OAuth 2.0 Threat Model and Security Considerations][1]
- [OAuth Security][2]
- [Common OAuth2 Vulnerabilities and Mitigation Techniques][3]
- [OAuth1, OAuth2, OAuth...?][4]

[1]: https://tools.ietf.org/html/rfc6819
[2]: http://www.oauthsecurity.com/
[3]: http://leastprivilege.com/2013/03/15/common-oauth2-vulnerabilities-and-mitigation-techniques/
[4]: http://homakov.blogspot.de/2013/03/oauth1-oauth2-oauth.html
[5]: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12#section-3
[6]: https://tools.ietf.org/html/rfc6749
[7]: http://openid.net/specs/openid-connect-core-1_0.html
