package clientcredentials

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/modernprogram/groupcache/v2"
)

func TestClientCredentials(t *testing.T) {

	clientID := "clientID"
	clientSecret := "clientSecret"
	token := "abc"
	expireIn := 60
	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	ts := newTokenServer(&tokenServerStat, clientID, clientSecret, token, expireIn)
	defer ts.Close()

	validToken := func(t string) bool { return t == token }

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, clientID, clientSecret, softExpire, false)

	// send 1

	{
		_, errSend := send(client, srv.URL, nil)
		if errSend != nil {
			t.Errorf("send 1: %v", errSend)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("send 1: unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 1 {
			t.Errorf("send 1: unexpected server access count: %d", serverStat.count)
		}
	}

	// send 2

	_, errSend2 := send(client, srv.URL, nil)
	if errSend2 != nil {
		t.Errorf("send 2: %v", errSend2)
	}
	if tokenServerStat.count != 1 {
		t.Errorf("send 2: unexpected token server access count: %d", tokenServerStat.count)
	}
	if serverStat.count != 2 {
		t.Errorf("send 2: unexpected server access count: %d", serverStat.count)
	}
}

// go test -count 1 -run ^TestCredsFromHeader$ ./...
func TestCredsFromHeader(t *testing.T) {

	clientID := "clientID"
	clientSecret := "clientSecret"
	token := "abc"
	expireIn := 60
	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	ts := newTokenServer(&tokenServerStat, clientID, clientSecret, token, expireIn)
	defer ts.Close()

	validToken := func(t string) bool { return t == token }

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, "clientIDWrong", "clientSecretWrong", softExpire, true)

	h := map[string]string{
		"oauth2-client-id":     clientID,
		"oauth2-client-secret": clientSecret,
	}

	// send 1

	{
		_, errSend := send(client, srv.URL, h)
		if errSend != nil {
			t.Errorf("send 1: %v", errSend)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("send 1: unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 1 {
			t.Errorf("send 1: unexpected server access count: %d", serverStat.count)
		}
	}

	// send 2

	_, errSend2 := send(client, srv.URL, h)
	if errSend2 != nil {
		t.Errorf("send 2: %v", errSend2)
	}
	if tokenServerStat.count != 1 {
		t.Errorf("send 2: unexpected token server access count: %d", tokenServerStat.count)
	}
	if serverStat.count != 2 {
		t.Errorf("send 2: unexpected server access count: %d", serverStat.count)
	}
}

// go test -count 1 -run ^TestCredsFromHeaderWithFallback$ ./...
func TestCredsFromHeaderWithFallback(t *testing.T) {

	clientID := "clientID"
	clientSecret := "clientSecret"
	token := "abc"
	expireIn := 60
	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	ts := newTokenServer(&tokenServerStat, clientID, clientSecret, token, expireIn)
	defer ts.Close()

	validToken := func(t string) bool { return t == token }

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, clientID, clientSecret, softExpire, true)

	h := map[string]string{}

	// send 1

	{
		_, errSend := send(client, srv.URL, h)
		if errSend != nil {
			t.Errorf("send 1: %v", errSend)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("send 1: unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 1 {
			t.Errorf("send 1: unexpected server access count: %d", serverStat.count)
		}
	}

	// send 2

	_, errSend2 := send(client, srv.URL, h)
	if errSend2 != nil {
		t.Errorf("send 2: %v", errSend2)
	}
	if tokenServerStat.count != 1 {
		t.Errorf("send 2: unexpected token server access count: %d", tokenServerStat.count)
	}
	if serverStat.count != 2 {
		t.Errorf("send 2: unexpected server access count: %d", serverStat.count)
	}
}

func TestConcurrency(t *testing.T) {

	clientID := "clientID"
	clientSecret := "clientSecret"
	token := "abc"
	expireIn := 1
	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	ts := newTokenServer(&tokenServerStat, clientID, clientSecret, token, expireIn)
	defer ts.Close()

	validToken := func(t string) bool { return t == token }

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, clientID, clientSecret, softExpire, false)

	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {

			for j := 0; j < 100; j++ {
				_, errSend := send(client, srv.URL, nil)
				if errSend != nil {
					t.Errorf("send1: %v", errSend)
				}
			}

			wg.Done()
		}()
	}

	wg.Wait()
}

func TestClientCredentialsExpiration(t *testing.T) {

	clientID := "clientID"
	clientSecret := "clientSecret"
	token := "abc"
	expireIn := 1
	softExpire := -1 // disable soft expire

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	ts := newTokenServer(&tokenServerStat, clientID, clientSecret, token, expireIn)
	defer ts.Close()

	validToken := func(t string) bool { return t == token }

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, clientID, clientSecret, softExpire, false)

	// send 1

	{
		_, errSend := send(client, srv.URL, nil)
		if errSend != nil {
			t.Errorf("send: %v", errSend)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 1 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	// send 2

	{
		_, errSend2 := send(client, srv.URL, nil)
		if errSend2 != nil {
			t.Errorf("send: %v", errSend2)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 2 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}
}

func TestForcedExpiration(t *testing.T) {

	clientID := "clientID"
	clientSecret := "clientSecret"
	token := "abc"
	expireIn := 60
	softExpire := -1 // disable soft expire

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	ts := newTokenServer(&tokenServerStat, clientID, clientSecret, token, expireIn)
	defer ts.Close()

	validToken := func(t string) bool { return t == token }

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, clientID, clientSecret, softExpire, false)

	// send 1: get first token

	{
		_, errSend := send(client, srv.URL, nil)
		if errSend != nil {
			t.Errorf("send: %v", errSend)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 1 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	// send 2: get cached token

	{
		_, errSend2 := send(client, srv.URL, nil)
		if errSend2 != nil {
			t.Errorf("send: %v", errSend2)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 2 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	// send 3: break cached token

	token = "broken"

	{
		result, errSend3 := send(client, srv.URL, nil)
		if errSend3 == nil {
			t.Errorf("unexpected send sucesss")
		}
		if result.status != 401 {
			t.Errorf("unexpected status: %d", result.status)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 3 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	// send 4: fix token

	token = "abc"

	{
		_, errSend3 := send(client, srv.URL, nil)
		if errSend3 != nil {
			t.Errorf("send: %v", errSend3)
		}
		if tokenServerStat.count != 2 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 4 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

}

func TestServerBrokenURL(t *testing.T) {

	clientID := "clientID"
	clientSecret := "clientSecret"
	token := "abc"
	expireIn := 0
	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	ts := newTokenServer(&tokenServerStat, clientID, clientSecret, token, expireIn)
	defer ts.Close()

	client := newClient(ts.URL, clientID, clientSecret, softExpire, false)

	// send

	{
		_, errSend := send(client, "broken-url", nil)
		if errSend == nil {
			t.Errorf("unexpected success from broken server")
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 0 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}
}

func TestTokenServerBrokenURL(t *testing.T) {

	clientID := "clientID"
	clientSecret := "clientSecret"
	token := "abc"
	softExpire := 0

	serverStat := serverStat{}

	validToken := func(t string) bool { return t == token }

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient("broken-url", clientID, clientSecret, softExpire, false)

	// send 1

	_, errSend := send(client, srv.URL, nil)
	if errSend == nil {
		t.Errorf("unexpected send success")
	}
}

func TestBrokenTokenServer(t *testing.T) {

	clientID := "clientID"
	clientSecret := "clientSecret"
	token := "abc"
	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	ts := newTokenServerBroken(&tokenServerStat)
	defer ts.Close()

	validToken := func(t string) bool { return t == token }

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, clientID, clientSecret, softExpire, false)

	// send 1

	{
		_, errSend := send(client, srv.URL, nil)
		if errSend == nil {
			t.Errorf("unexpected success with broken token server")
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 0 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	// send 2

	{
		_, errSend := send(client, srv.URL, nil)
		if errSend == nil {
			t.Errorf("unexpected success with broken token server")
		}
		if tokenServerStat.count != 2 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 0 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

}

func TestLockedTokenServer(t *testing.T) {

	clientID := "clientID"
	clientSecret := "clientSecret"
	token := "abc"
	expireIn := 60
	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	ts := newTokenServer(&tokenServerStat, clientID, "WRONG-SECRET", token, expireIn)
	defer ts.Close()

	validToken := func(t string) bool { return t == token }

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, clientID, clientSecret, softExpire, false)

	// send 1

	{
		_, errSend := send(client, srv.URL, nil)
		if errSend == nil {
			t.Errorf("unexpected success with locked token server")
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 0 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	// send 2

	{
		_, errSend := send(client, srv.URL, nil)
		if errSend == nil {
			t.Errorf("unexpected success with locked token server")
		}
		if tokenServerStat.count != 2 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 0 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}
}

type sendResult struct {
	body   string
	status int
}

func send(client *Client, serverURL string, h map[string]string) (sendResult, error) {

	var result sendResult

	req, errReq := http.NewRequestWithContext(context.TODO(), "GET", serverURL, nil)
	if errReq != nil {
		return result, fmt.Errorf("request: %v", errReq)
	}

	for k, v := range h {
		//log.Printf("send: header=%s value=%s", k, v)
		req.Header.Set(k, v)
	}

	resp, errDo := client.Do(req)
	if errDo != nil {
		return result, fmt.Errorf("do: %v", errDo)
	}
	defer resp.Body.Close()

	body, errBody := io.ReadAll(resp.Body)
	if errBody != nil {
		return result, fmt.Errorf("body: %v", errBody)
	}

	bodyStr := string(body)

	result.body = bodyStr
	result.status = resp.StatusCode

	if resp.StatusCode != 200 {
		return result, fmt.Errorf("bad status:%d body:%v", resp.StatusCode, bodyStr)
	}

	return result, nil
}

func formParam(r *http.Request, key string) string {
	v := r.Form[key]
	if v == nil {
		return ""
	}
	return v[0]
}

func newServer(stat *serverStat, validToken func(token string) bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stat.inc()
		h := r.Header.Get("Authorization")
		t := strings.TrimPrefix(h, "Bearer ")
		if !validToken(t) {
			httpJSON(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		httpJSON(w, `{"message":"ok"}`, http.StatusOK)
	}))
}

// httpJSON replies to the request with the specified error message and HTTP code.
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
// The message should be JSON.
func httpJSON(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprintln(w, message)
}

type serverStat struct {
	count int
	mutex sync.Mutex
}

func (stat *serverStat) inc() {
	stat.mutex.Lock()
	stat.count++
	stat.mutex.Unlock()
}

func newTokenServer(serverInfo *serverStat, clientID, clientSecret, token string, expireIn int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		serverInfo.inc()

		r.ParseForm()
		formGrantType := formParam(r, "grant_type")
		formClientID := formParam(r, "client_id")
		formClientSecret := formParam(r, "client_secret")

		if formGrantType != "client_credentials" || formClientID != clientID || formClientSecret != clientSecret {
			httpJSON(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		var t string

		if expireIn > 0 {
			t = fmt.Sprintf(`{"access_token":"%s","expires_in":%d}`, token, expireIn)
		} else {
			t = fmt.Sprintf(`{"access_token":"%s"}`, token)
		}

		httpJSON(w, t, http.StatusOK)
	}))
}

func newTokenServerBroken(serverInfo *serverStat) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ /*r*/ *http.Request) {
		serverInfo.inc()
		httpJSON(w, "broken-token", http.StatusOK)
	}))
}

func newClient(tokenURL, clientID, clientSecret string, softExpire int,
	credsFromHeader bool) *Client {

	options := Options{
		TokenURL:                        tokenURL,
		ClientID:                        clientID,
		ClientSecret:                    clientSecret,
		Scope:                           "scope1 scope2",
		HTTPClient:                      http.DefaultClient,
		SoftExpireInSeconds:             softExpire,
		GroupcacheWorkspace:             groupcache.NewWorkspace(),
		GetCredentialsFromRequestHeader: credsFromHeader,
		Debug:                           true,
	}

	client := New(options)

	return client
}
