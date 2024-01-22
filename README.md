[![license](http://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/udhos/groupcache_oauth2/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/udhos/groupcache_oauth2)](https://goreportcard.com/report/github.com/udhos/groupcache_oauth2)
[![Go Reference](https://pkg.go.dev/badge/github.com/udhos/groupcache_oauth2.svg)](https://pkg.go.dev/github.com/udhos/groupcache_oauth2)

# groupcache_oauth2

https://github.com/udhos/groupcache_oauth2 implements the oauth2 client_credentials flow cacheing tokens with [groupcache](https://github.com/modernprogram/groupcache).

# Usage

FIXME WRITEME

# Example client

See [cmd/groupcache-oauth2-client-example/main.go](cmd/groupcache-oauth2-client-example/main.go).

# Test with example client

Test using this token server: https://oauth.tools/collection/1599045253169-GHF

```bash
go install github.com/udhos/oauth2/cmd/groupcache-oauth2-client-example@latest

groupcache-oauth2-client-example -tokenURL https://login-demo.curity.io/oauth/v2/oauth-token -clientID demo-backend-client -clientSecret MJlO3binatD9jk1
```

# Development

```bash
git clone https://github.com/udhos/groupcache_oauth2
cd groupcache_oauth2
./build.sh
```
