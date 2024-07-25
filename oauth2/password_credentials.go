// Package passwordcredentials implements the OAuth2.0 "password credentials" token flow.
// See https://tools.ietf.org/html/rfc6749#section-4.3
package passwordcredentials

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
)

func ContextClient(ctx context.Context) *http.Client {
	if ctx != nil {
		if hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
			return hc
		}
	}
	return http.DefaultClient
}

// Config describes a Resource Owner Password Credentials OAuth2 flow, with the
// client application information, resource owner credentials and the server's
// endpoint URLs.
type Config struct {
	// Resource owner domain
	Domain string

	// Resource owner username
	Username string

	// Resource owner password
	Password string

	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via site-specific packages, such as
	// google.Endpoint or github.Endpoint.
	Endpoint oauth2.Endpoint
}

// Client returns an HTTP client using the provided token.
// The token will auto-refresh as necessary. The underlying
// HTTP transport will be obtained using the provided context.
// The returned client and its Transport should not be modified.
func (c *Config) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, c.TokenSource(ctx))
}

// TokenSource returns a TokenSource that returns t until t expires,
// automatically refreshing it as necessary using the provided context and the
// client ID and client secret.
//
// Most users will use Config.Client instead.
func (c *Config) TokenSource(ctx context.Context) oauth2.TokenSource {
	source := &tokenSource{
		ctx:  ctx,
		conf: c,
	}
	return oauth2.ReuseTokenSource(nil, source)
}

type tokenSource struct {
	ctx  context.Context
	conf *Config
}

// Token refreshes the token by using a new password credentials request.
// tokens received this way do not include a refresh token
func (c *tokenSource) Token() (*oauth2.Token, error) {
	v := map[string]string{
		"domain":   c.conf.Domain,
		"username": c.conf.Username,
		"password": c.conf.Password,
	}
	hc := ContextClient(c.ctx)
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", c.conf.Endpoint.AuthURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if c := r.StatusCode; c < 200 || c > 299 {
		return nil, &oauth2.RetrieveError{
			Response: r,
			Body:     body,
		}
	}
	var tokenRes struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tokenRes); err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	token := &oauth2.Token{
		AccessToken:  tokenRes.AccessToken,
		RefreshToken: tokenRes.RefreshToken,
	}
	raw := make(map[string]interface{})
	json.Unmarshal(body, &raw) // no error checks for optional fields
	token = token.WithExtra(raw)
	// decode returned access token to get expiry
	claimSet, err := jws.Decode(token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("oauth2: error decoding JWT token: %v", err)
	}
	token.Expiry = time.Unix(claimSet.Exp, 0)
	return token, nil
}
