// Package clientcredentials helps with oauth2 client-credentials flow.
package clientcredentials

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/modernprogram/groupcache/v2"
	cc "github.com/udhos/oauth2clientcredentials/clientcredentials"
)

// DefaultGroupCacheSizeBytes is default group cache size when unspecified.
const DefaultGroupCacheSizeBytes = 10_000_000

// HTTPClientDoer interface allows the caller to easily plug in a custom http client.
type HTTPClientDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Options define client options.
type Options struct {
	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	TokenURL string

	// ClientID is the application's ID. See also GetCredentialsFromRequestHeader.
	ClientID string

	// ClientSecret is the application's secret. See also GetCredentialsFromRequestHeader.
	ClientSecret string

	// Scope specifies optional space-separated requested permissions.
	Scope string

	// HTTPClient provides the actual HTTP client to use.
	// If unspecified, defaults to http.DefaultClient.
	HTTPClient HTTPClientDoer

	// HTTPStatusOkMin is the minimum token server response status code accepted as Ok.
	// If undefined, defaults to 200.
	HTTPStatusOkMin int

	// HTTPStatusOkMax is the maximum token server response status code accepted as Ok.
	// If undefined, defaults to 299.
	HTTPStatusOkMax int

	// SoftExpireInSeconds specifies how early before hard expiration the
	// token should be considered expired to trigger renewal. This
	// prevents from using an expired token due to clock
	// differences.
	//
	// 0 defaults to 10 seconds. Set to -1 to no soft expire.
	//
	// Example: consider expire_in = 30 seconds and soft expire = 10 seconds.
	// The token will hard expire after 30 seconds, but we will consider it
	// expired after (30-10) = 20 seconds, in order to attempt renewal before
	// hard expiration.
	//
	SoftExpireInSeconds int

	// GroupcacheWorkspace is required groupcache workspace.
	GroupcacheWorkspace *groupcache.Workspace

	// GroupcacheName gives a unique cache name. If unspecified, defaults to oauth2.
	GroupcacheName string

	// GroupcacheSizeBytes limits the cache size. If unspecified, defaults to 10MB.
	GroupcacheSizeBytes int64

	// Logf provides logging function, if undefined defaults to log.Printf
	Logf func(format string, v ...any)

	// Debug enables debug logging.
	Debug bool

	// DisablePurgeExpired disables removing all expired items when the oldest item is removed.
	DisablePurgeExpired bool

	// ExpiredKeysEvictionInterval sets interval for periodic eviction of expired keys.
	// If unset, defaults to 30-minute period.
	// Set to -1 to disable periodic eviction of expired keys.
	ExpiredKeysEvictionInterval time.Duration

	// GroupcacheMainCacheWeight defaults to 8 if unspecified.
	GroupcacheMainCacheWeight int64

	// GroupcacheHotCacheWeight defaults to 1 if unspecified.
	GroupcacheHotCacheWeight int64

	// GetCredentialsFromRequestHeader enables retrieving client credentials from headers.
	// If enabled, static credentials ClientID and ClientSecret are ignored.
	GetCredentialsFromRequestHeader bool

	// ForwardHeaderCredentials forwards consumed sensitive credentials headers.
	ForwardHeaderCredentials bool

	// HeaderClientID defaults to "oauth2-client-id".
	HeaderClientID string

	// HeaderClientSecret defaults to "oauth2-client-secret".
	HeaderClientSecret string

	// IsBadTokenStatus checks if the server response status is bad token.
	// If undefined, defaults to DefaultBadTokenStatusFunc that just checks for 401.
	IsBadTokenStatus func(status int) bool
}

// DefaultBadTokenStatusFunc is used as default when option IsBadTokenStatus is left undefined.
// DefaultBadTokenStatusFunc reports if status is 401.
func DefaultBadTokenStatusFunc(status int) bool {
	return status == 401
}

// Client is context for invokations with client-credentials flow.
type Client struct {
	options        Options
	group          *groupcache.Group
	getCredentials func(arg interface{}) (string, string)
}

// New creates a client.
func New(options Options) *Client {
	if options.GroupcacheWorkspace == nil {
		panic("groupcache workspace is nil")
	}

	if options.HTTPClient == nil {
		options.HTTPClient = http.DefaultClient
	}

	switch options.SoftExpireInSeconds {
	case 0:
		options.SoftExpireInSeconds = 10
	case -1:
		options.SoftExpireInSeconds = 0
	}

	if options.HTTPStatusOkMin == 0 {
		options.HTTPStatusOkMin = 200
	}
	if options.HTTPStatusOkMax == 0 {
		options.HTTPStatusOkMax = 299
	}

	if options.Logf == nil {
		options.Logf = log.Printf
	}

	if options.HeaderClientID == "" {
		options.HeaderClientID = "oauth2-client-id"
	}

	if options.HeaderClientSecret == "" {
		options.HeaderClientSecret = "oauth2-client-secret"
	}

	if options.IsBadTokenStatus == nil {
		options.IsBadTokenStatus = DefaultBadTokenStatusFunc
	}

	c := &Client{
		options: options,
	}

	if options.GetCredentialsFromRequestHeader {
		c.getCredentials = func(arg interface{}) (string, string) {
			h := arg.(http.Header)
			id := h.Get(options.HeaderClientID)
			secret := h.Get(options.HeaderClientSecret)

			c.debugf("getCredentials: id=%s secret=%s", id, secret)
			return id, secret
		}
	}

	cacheSizeBytes := options.GroupcacheSizeBytes
	if cacheSizeBytes == 0 {
		cacheSizeBytes = DefaultGroupCacheSizeBytes
	}

	cacheName := options.GroupcacheName
	if cacheName == "" {
		cacheName = "oauth2"
	}

	o := groupcache.Options{
		Workspace:                   options.GroupcacheWorkspace,
		Name:                        cacheName,
		PurgeExpired:                !options.DisablePurgeExpired,
		ExpiredKeysEvictionInterval: options.ExpiredKeysEvictionInterval,
		CacheBytesLimit:             cacheSizeBytes,
		Getter: groupcache.GetterFunc(
			func(ctx context.Context, _ /*key*/ string, dest groupcache.Sink,
				info *groupcache.Info) error {

				ti, errTok := c.fetchToken(ctx, info)
				if errTok != nil {
					return errTok
				}

				softExpire := time.Duration(options.SoftExpireInSeconds) * time.Second

				expire := time.Now().Add(ti.expiresIn - softExpire)

				return dest.SetString(ti.accessToken, expire)
			}),
		MainCacheWeight: options.GroupcacheMainCacheWeight,
		HotCacheWeight:  options.GroupcacheHotCacheWeight,
	}

	group := groupcache.NewGroupWithWorkspace(o)

	c.group = group

	return c
}

func (c *Client) errorf(format string, v ...any) {
	c.options.Logf("ERROR: "+format, v...)
}

func (c *Client) debugf(format string, v ...any) {
	if c.options.Debug {
		c.options.Logf("DEBUG: "+format, v...)
	}
}

// Do sends an HTTP request and returns an HTTP response.
// The actual HTTPClient provided in the Options is used to make the requests
// and also to retrieve the required client_credentials token.
// Do retrieves the token and renews it as necessary for making the request.
func (c *Client) Do(req *http.Request) (*http.Response, error) {

	ctx := req.Context()

	accessToken, errToken := c.getToken(ctx, req.Header)
	if errToken != nil {
		return nil, errToken
	}

	if c.options.GetCredentialsFromRequestHeader &&
		!c.options.ForwardHeaderCredentials {
		// do not forward sensitive consumed headers
		delete(req.Header, c.options.HeaderClientID)
		delete(req.Header, c.options.HeaderClientSecret)
	}

	resp, errResp := c.send(req, accessToken)
	if errResp != nil {
		return resp, errResp
	}

	if c.options.IsBadTokenStatus(resp.StatusCode) {
		//
		// the server refused our token, so we expire it in order to
		// renew it at the next invokation.
		//
		if errRemove := c.group.Remove(ctx, c.options.ClientID); errRemove != nil {
			c.errorf("cache remove error: %v", errRemove)
		}
	}

	return resp, errResp
}

func (c *Client) send(req *http.Request, accessToken string) (*http.Response, error) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return c.options.HTTPClient.Do(req)
}

func (c *Client) getToken(ctx context.Context, h http.Header) (string, error) {
	var info *groupcache.Info
	var id, secret string

	if c.getCredentials != nil {
		id, secret = c.getCredentials(h)
		info = &groupcache.Info{Ctx1: id, Ctx2: secret}
	} else {
		id = c.options.ClientID
	}

	c.debugf("credentialsFromHeader:%t func:%v clientID=%s clientSecret=%s",
		c.options.GetCredentialsFromRequestHeader, c.getCredentials, id, secret)

	var accessToken string
	errGet := c.group.Get(ctx, id, groupcache.StringSink(&accessToken), info)
	return accessToken, errGet
}

// fetchToken actually retrieves token from token server.
func (c *Client) fetchToken(ctx context.Context, info *groupcache.Info) (tokenInfo, error) {

	const me = "fetchToken"

	begin := time.Now()

	var clientID, clientSecret string
	if info == nil {
		clientID = c.options.ClientID
		clientSecret = c.options.ClientSecret
	} else {
		clientID = info.Ctx1
		clientSecret = info.Ctx2
	}

	var ti tokenInfo

	resp, errDo := cc.SendRequest(ctx, c.options.HTTPClient, c.options.TokenURL,
		clientID, clientSecret, c.options.Scope)
	if errDo != nil {
		return ti, errDo
	}
	defer resp.Body.Close()

	body, errBody := io.ReadAll(resp.Body)
	if errBody != nil {
		return ti, errBody
	}

	elap := time.Since(begin)

	c.debugf("%s: elapsed:%v token: %s", me, elap, string(body))

	if resp.StatusCode < c.options.HTTPStatusOkMin || resp.StatusCode > c.options.HTTPStatusOkMax {
		return ti, fmt.Errorf("bad token server response http status: status:%d body:%v", resp.StatusCode, string(body))
	}

	tokenResp, errDecode := cc.DecodeResponseBody(body)
	if errDecode != nil {
		return ti, fmt.Errorf("decode token response: %v", errDecode)
	}
	if tokenResp.AccessToken == "" {
		return ti, fmt.Errorf("missing access_token in token response")
	}

	ti.accessToken = tokenResp.AccessToken
	ti.expiresIn = time.Duration(tokenResp.ExpiresIn) * time.Second

	return ti, nil
}

type tokenInfo struct {
	accessToken string
	expiresIn   time.Duration
}
