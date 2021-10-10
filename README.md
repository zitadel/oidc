# OpenID Connect SDK (client and server) for Go

[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Release](https://github.com/caos/oidc/workflows/Release/badge.svg)](https://github.com/caos/oidc/actions)
[![license](https://badgen.net/github/license/caos/oidc/)](https://github.com/caos/oidc/blob/master/LICENSE)
[![release](https://badgen.net/github/release/caos/oidc/stable)](https://github.com/caos/oidc/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/caos/oidc)](https://goreportcard.com/report/github.com/caos/oidc)
[![codecov](https://codecov.io/gh/caos/oidc/branch/master/graph/badge.svg)](https://codecov.io/gh/caos/oidc)

![openid_certified](https://cloud.githubusercontent.com/assets/1454075/7611268/4d19de32-f97b-11e4-895b-31b2455a7ca6.png)

## What Is It

This project is a easy to use client (RP) and server (OP) implementation for the `OIDC` (Open ID Connect) standard written for `Go`.

The RP is certified for the [basic](https://www.certification.openid.net/plan-detail.html?public=true&plan=uoprP0OO8Z4Qo) and [config](https://www.certification.openid.net/plan-detail.html?public=true&plan=AYSdLbzmWbu9X) profile.

Whenever possible we tried to reuse / extend existing packages like `OAuth2 for Go`.

## How To Use It

Check the `/example` folder where example code for different scenarios is located.

```bash
# start oidc op server
# oidc discovery http://localhost:9998/.well-known/openid-configuration
CAOS_OIDC_DEV=1 go run github.com/caos/oidc/example/server/default
# start oidc web client
CLIENT_ID=web CLIENT_SECRET=web ISSUER=http://localhost:9998/ SCOPES=openid PORT=5556 go run github.com/caos/oidc/example/client/app
```

- browser http://localhost:5556/login will redirect to op server
- input id to login
- redirect to client app display user info

## Features

|                | Code Flow | Implicit Flow | Hybrid Flow | Discovery | PKCE | Token Exchange | mTLS    | JWT Profile | Refresh Token |
|----------------|-----------|---------------|-------------|-----------|------|----------------|---------|-------------|---------------|
| Relaying Party | yes       | yes           | not yet     | yes       | yes  | partial        | not yet | yes         | yes           |
| Origin Party   | yes       | yes           | not yet     | yes       | yes  | not yet        | not yet | yes         | yes           |

### Resources

For your convenience you can find the relevant standards linked below.

- [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
- [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 Token Exchange](https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-19)
- [OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://tools.ietf.org/html/draft-ietf-oauth-mtls-17)
- [JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7523)

## Supported Go Versions

| Version | Supported          |
|---------|--------------------|
| <1.13   | :x:                |
| 1.14    | :white_check_mark: |
| 1.15    | :white_check_mark: |
| 1.16    | :white_check_mark: |
| 1.17    | :white_check_mark: |

## Why another library

As of 2020 there are not a lot of `OIDC` library's in `Go` which can handle server and client implementations. CAOS is strongly committed to the general field of IAM (Identity and Access Management) and as such, we need solid frameworks to implement services.

### Goals

- [Certify this library as OP](https://openid.net/certification/#OPs)

### Other Go OpenID Connect libraries

[https://github.com/coreos/go-oidc](https://github.com/coreos/go-oidc)

The `go-oidc` does only support `RP` and is not feasible to use as `OP` that's why we could not rely on `go-oidc`

[https://github.com/ory/fosite](https://github.com/ory/fosite)

We did not choose `fosite` because it implements `OAuth 2.0` on its own and does not rely on the golang provided package. Nonetheless this is a great project.

## License

The full functionality of this library is and stays open source and free to use for everyone. Visit our [website](https://caos.ch) and get in touch.

See the exact licensing terms [here](./LICENSE)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
