# OpenID Connect SDK (client and server) for Go

[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Release](https://github.com/caos/oidc/workflows/Release/badge.svg)](https://github.com/caos/oidc/actions)
[![license](https://badgen.net/github/license/caos/oidc/)](https://github.com/caos/oidc/blob/master/LICENSE)
[![release](https://badgen.net/github/release/caos/oidc/stable)](https://github.com/caos/oidc/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/caos/oidc)](https://goreportcard.com/report/github.com/caos/oidc)

> This project is in alpha state. It can AND will continue breaking until version 1.0.0 is released

## What Is It

This project is a easy to use client and server implementation for the `OIDC` (Open ID Connect) standard written for `Go`. 

Whenever possible we tried to reuse / extend existing packages like `OAuth2 for Go`.

## How To Use It

TBD

## Features

|                | Code Flow | Implicit Flow | Hybrid Flow | Discovery | PKCE | Token Exchange | mTLS    |
|----------------|-----------|---------------|-------------|-----------|------|----------------|---------|
| Relaying Party | yes       | yes           | not yet     | yes       | yes  | partial        | not yet |
| Origin Party   | yes       | yes           | not yet     | yes       | yes  | not yet        | not yet |

### Resources

For your convinience you can find the relevant standards linked below.

- [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
- [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 Token Exchange](https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-19)
- [OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://tools.ietf.org/html/draft-ietf-oauth-mtls-17)

## Supported Go Versions

| Version | Supported          |
|---------|--------------------|
| <1.11   | :x:                |
| 1.11    | :white_check_mark: |
| 1.12    | :white_check_mark: |
| 1.13    | :white_check_mark: |
| 1.14    | :white_check_mark: |

## Why another library

As of 2020 there are not a lot of `OIDC` librarys in `Go` which can handle server and client implementations. CAOS is strongly commited to the general field of IAM (Identity and Access Management) and as such, we need solid frameworks to implement services.

## License

The full functionality of this library is and stays open source and free to use for everyone. Visit our [website](https://caos.ch) and get in touch.

See the exact licensing terms [here](./LICENSE)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
