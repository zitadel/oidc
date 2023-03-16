# OpenID Connect SDK (client and server) for Go

[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Release](https://github.com/zitadel/oidc/workflows/Release/badge.svg)](https://github.com/zitadel/oidc/actions)
[![GoDoc](https://godoc.org/github.com/zitadel/oidc?status.png)](https://pkg.go.dev/github.com/zitadel/oidc)
[![license](https://badgen.net/github/license/zitadel/oidc/)](https://github.com/zitadel/oidc/blob/master/LICENSE)
[![release](https://badgen.net/github/release/zitadel/oidc/stable)](https://github.com/zitadel/oidc/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/zitadel/oidc)](https://goreportcard.com/report/github.com/zitadel/oidc)
[![codecov](https://codecov.io/gh/zitadel/oidc/branch/main/graph/badge.svg)](https://codecov.io/gh/zitadel/oidc)

![openid_certified](https://cloud.githubusercontent.com/assets/1454075/7611268/4d19de32-f97b-11e4-895b-31b2455a7ca6.png)

## What Is It

This project is an easy-to-use client (RP) and server (OP) implementation for the `OIDC` (OpenID Connect) standard written for `Go`.

The RP is certified for the [basic](https://www.certification.openid.net/plan-detail.html?public=true&plan=uoprP0OO8Z4Qo) and [config](https://www.certification.openid.net/plan-detail.html?public=true&plan=AYSdLbzmWbu9X) profile.

Whenever possible we tried to reuse / extend existing packages like `OAuth2 for Go`.

## Basic Overview

The most important packages of the library:
<pre>
/pkg
    /client            clients using the OP for retrieving, exchanging and verifying tokens       
        /rp            definition and implementation of an OIDC Relying Party (client)
        /rs            definition and implementation of an OAuth Resource Server (API)
    /op                definition and implementation of an OIDC OpenID Provider (server)
    /oidc              definitions shared by clients and server

/example
    /client/api        example of an api / resource server implementation using token introspection
    /client/app        web app / RP demonstrating authorization code flow using various authentication methods (code, PKCE, JWT profile)
    /client/github     example of the extended OAuth2 library, providing an HTTP client with a reuse token source
    /client/service    demonstration of JWT Profile Authorization Grant
    /server            examples of an OpenID Provider implementations (including dynamic) with some very basic login UI
</pre>

## How To Use It

Check the `/example` folder where example code for different scenarios is located.

```bash
# start oidc op server
# oidc discovery http://localhost:9998/.well-known/openid-configuration
go run github.com/zitadel/oidc/v2/example/server
# start oidc web client (in a new terminal)
CLIENT_ID=web CLIENT_SECRET=secret ISSUER=http://localhost:9998/ SCOPES="openid profile" PORT=9999 go run github.com/zitadel/oidc/v2/example/client/app
```

- open http://localhost:9999/login in your browser
- you will be redirected to op server and the login UI 
- login with user `test-user@localhost` and password `verysecure`
- the OP will redirect you to the client app, which displays the user info

for the dynamic issuer, just start it with:
```bash
go run github.com/zitadel/oidc/v2/example/server/dynamic
``` 
the oidc web client above will still work, but if you add `oidc.local` (pointing to 127.0.0.1) in your hosts file you can also start it with:
```bash
CLIENT_ID=web CLIENT_SECRET=secret ISSUER=http://oidc.local:9998/ SCOPES="openid profile" PORT=9999 go run github.com/zitadel/oidc/v2/example/client/app
```

> Note: Usernames are suffixed with the hostname (`test-user@localhost` or `test-user@oidc.local`)

## Features

|                  | Code Flow | Implicit Flow | Hybrid Flow | Discovery | PKCE | Token Exchange | mTLS    | JWT Profile | Refresh Token | Client Credentials |
|------------------|-----------|---------------|-------------|-----------|------|----------------|---------|-------------|---------------|--------------------|
| Relying Party    | yes       | no[^1]        | no          | yes       | yes  | partial        | not yet | yes         | yes           | not yet            |
| OpenID Provider  | yes       | yes           | not yet     | yes       | yes  | not yet        | not yet | yes         | yes           | yes                |

## Contributors

<a href="https://github.com/zitadel/oidc/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=zitadel/oidc" alt="Screen with contributors' avatars from contrib.rocks" />
</a>

Made with [contrib.rocks](https://contrib.rocks).

### Resources

For your convenience you can find the relevant standards linked below.

- [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
- [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 Token Exchange](https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-19)
- [OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://tools.ietf.org/html/draft-ietf-oauth-mtls-17)
- [JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7523)
- [OIDC/OAuth Flow in Zitadel (using this library)](https://zitadel.com/docs/guides/integrate/login-users)

## Supported Go Versions

For security reasons, we only support and recommend the use of one of the latest two Go versions (:white_check_mark:).  
Versions that also build are marked with :warning:.

| Version | Supported          |
|---------|--------------------|
| <1.18   | :x:                |
| 1.18    | :warning:          |
| 1.19    | :white_check_mark: |
| 1.20    | :white_check_mark: |

## Why another library

As of 2020 there are not a lot of `OIDC` library's in `Go` which can handle server and client implementations. ZITADEL is strongly committed to the general field of IAM (Identity and Access Management) and as such, we need solid frameworks to implement services.

### Goals

- [Certify this library as OP](https://openid.net/certification/#OPs)

### Other Go OpenID Connect libraries

[https://github.com/coreos/go-oidc](https://github.com/coreos/go-oidc)

The `go-oidc` does only support `RP` and is not feasible to use as `OP` that's why we could not rely on `go-oidc`

[https://github.com/ory/fosite](https://github.com/ory/fosite)

We did not choose `fosite` because it implements `OAuth 2.0` on its own and does not rely on the golang provided package. Nonetheless this is a great project.

## License

The full functionality of this library is and stays open source and free to use for everyone. Visit
our [website](https://zitadel.com) and get in touch.

See the exact licensing terms [here](LICENSE)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.


[^1]: https://github.com/zitadel/oidc/issues/135#issuecomment-950563892
