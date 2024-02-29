# OpenID Connect SDK (client and server) for Go

[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Release](https://github.com/zitadel/oidc/workflows/Release/badge.svg)](https://github.com/zitadel/oidc/actions)
[![Go Reference](https://pkg.go.dev/badge/github.com/zitadel/oidc/v3.svg)](https://pkg.go.dev/github.com/zitadel/oidc/v3)
[![license](https://badgen.net/github/license/zitadel/oidc/)](https://github.com/zitadel/oidc/blob/master/LICENSE)
[![release](https://badgen.net/github/release/zitadel/oidc/stable)](https://github.com/zitadel/oidc/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/zitadel/oidc/v3)](https://goreportcard.com/report/github.com/zitadel/oidc/v3)
[![codecov](https://codecov.io/gh/zitadel/oidc/branch/main/graph/badge.svg)](https://codecov.io/gh/zitadel/oidc)

[![openid_certified](https://cloud.githubusercontent.com/assets/1454075/7611268/4d19de32-f97b-11e4-895b-31b2455a7ca6.png)](https://openid.net/certification/)

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


### Semver

This package uses [semver](https://semver.org/) for [releases](https://github.com/zitadel/oidc/releases). Major releases ship breaking changes. Starting with the `v2` to `v3` increment we provide an [upgrade guide](UPGRADING.md) to ease migration to a newer version.

## How To Use It

Check the `/example` folder where example code for different scenarios is located.

```bash
# start oidc op server
# oidc discovery http://localhost:9998/.well-known/openid-configuration
go run github.com/zitadel/oidc/v3/example/server
# start oidc web client (in a new terminal)
CLIENT_ID=web CLIENT_SECRET=secret ISSUER=http://localhost:9998/ SCOPES="openid profile" PORT=9999 go run github.com/zitadel/oidc/v3/example/client/app
```

- open http://localhost:9999/login in your browser
- you will be redirected to op server and the login UI 
- login with user `test-user@localhost` and password `verysecure`
- the OP will redirect you to the client app, which displays the user info

for the dynamic issuer, just start it with:
```bash
go run github.com/zitadel/oidc/v3/example/server/dynamic
``` 
the oidc web client above will still work, but if you add `oidc.local` (pointing to 127.0.0.1) in your hosts file you can also start it with:
```bash
CLIENT_ID=web CLIENT_SECRET=secret ISSUER=http://oidc.local:9998/ SCOPES="openid profile" PORT=9999 go run github.com/zitadel/oidc/v3/example/client/app
```

> Note: Usernames are suffixed with the hostname (`test-user@localhost` or `test-user@oidc.local`)

## Features

|                      | Relying party | OpenID Provider | Specification                             |
| -------------------- | ------------- | --------------- | ----------------------------------------- |
| Code Flow            | yes           | yes             | OpenID Connect Core 1.0, [Section 3.1][1] |
| Implicit Flow        | no[^1]        | yes             | OpenID Connect Core 1.0, [Section 3.2][2] |
| Hybrid Flow          | no            | not yet         | OpenID Connect Core 1.0, [Section 3.3][3] |
| Client Credentials   | yes           | yes             | OpenID Connect Core 1.0, [Section 9][4]   |
| Refresh Token        | yes           | yes             | OpenID Connect Core 1.0, [Section 12][5]  |
| Discovery            | yes           | yes             | OpenID Connect [Discovery][6] 1.0         |
| JWT Profile          | yes           | yes             | [RFC 7523][7]                             |
| PKCE                 | yes           | yes             | [RFC 7636][8]                             |
| Token Exchange       | yes           | yes             | [RFC 8693][9]                             |
| Device Authorization | yes           | yes             | [RFC 8628][10]                            |
| mTLS                 | not yet       | not yet         | [RFC 8705][11]                            |

[1]: <https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth> "3.1. Authentication using the Authorization Code Flow"
[2]: <https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth> "3.2. Authentication using the Implicit Flow"
[3]: <https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth> "3.3. Authentication using the Hybrid Flow"
[4]: <https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication> "9. Client Authentication"
[5]: <https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens> "12. Using Refresh Tokens"
[6]: <https://openid.net/specs/openid-connect-discovery-1_0.html> "OpenID Connect Discovery 1.0 incorporating errata set 1"
[7]: <https://www.rfc-editor.org/rfc/rfc7523.html> "JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants"
[8]: <https://www.rfc-editor.org/rfc/rfc7636.html> "Proof Key for Code Exchange by OAuth Public Clients"
[9]: <https://www.rfc-editor.org/rfc/rfc8693.html> "OAuth 2.0 Token Exchange"
[10]: <https://www.rfc-editor.org/rfc/rfc8628.html> "OAuth 2.0 Device Authorization Grant"
[11]: <https://www.rfc-editor.org/rfc/rfc8705.html> "OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens"

## Contributors

<a href="https://github.com/zitadel/oidc/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=zitadel/oidc" alt="Screen with contributors' avatars from contrib.rocks" />
</a>

Made with [contrib.rocks](https://contrib.rocks).

### Resources

For your convenience you can find the relevant guides linked below.

- [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
- [OIDC/OAuth Flow in Zitadel (using this library)](https://zitadel.com/docs/guides/integrate/login-users)

## Supported Go Versions

For security reasons, we only support and recommend the use of one of the latest two Go versions (:white_check_mark:).  
Versions that also build are marked with :warning:.

| Version | Supported          |
| ------- | ------------------ |
| <1.21   | :x:                |
| 1.21    | :white_check_mark: |
| 1.22    | :white_check_mark: |

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
