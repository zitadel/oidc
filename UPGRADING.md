# Upgrading

All commands are executed from the root of the project that imports oidc packages.
`sed` commands are created with **GNU sed** in mind and might need alternate syntax
on non-GNU systems, such as MacOS.
Alternatively, GNU sed can be installed on such systems. (`coreutils` package?).

## V2 to V3

**TL;DR** at the [bottom](#full-script) of this chapter is a full `sed` script
containing all automatic steps at once.


As first steps we will:
1. Download the latest v3 module;
2. Replace imports in all Go files;
3. Tidy the module file;

```bash
go get -u github.com/zitadel/oidc/v3
find . -type f -name '*.go' | xargs sed -i \
    -e 's/github\.com\/zitadel\/oidc\/v2/github.com\/zitadel\/oidc\/v3/g'
go mod tidy
```

### global

#### go-jose package

`gopkg.in/square/go-jose.v2` import has been changed to `github.com/go-jose/go-jose/v3`.
That means that the imported types are also changed and imports need to be adapted.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/gopkg.in\/square\/go-jose\.v2/github.com\/go-jose\/go-jose\/v3/g'
go mod tidy
```

### op

```go
import "github.com/zitadel/oidc/v3/pkg/op"
```

#### Logger

This version of OIDC adds logging to the framework. For this we use the new Go standard library `log/slog`. (Until v3.12.0 we used `x/exp/slog`).
Mostly OIDC will use error level logs where it's returning an error through a HTTP handler. OIDC errors that are user facing don't carry much context, also for security reasons. With logging we are now able to print the error context, so that developers can more easily find the source of their issues. Previously we just discarded such context.

Most users of the OP package with the storage interface will not experience breaking changes. However if you use `RequestError()` directly in your code, you now need to give it a `Logger` as final argument.

The `OpenIDProvider` and sub-interfaces like `Authorizer` and `Exchanger` got a `Logger()` method to return the configured logger. This logger is in turn used by `AuthRequestError()`. You configure the logger with the `WithLogger()` for the `Provider`. By default the `slog.Default()` is used.

We also provide a new optional interface: [`LogAuthRequest`](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/op#LogAuthRequest). If an `AuthRequest` implements this interface, it is completely passed into the logger after an error. Its `LogValue()` will be used by `slog` to print desired fields. This allows omitting sensitive fields you wish not no print. If the interface is not implemented, no `AuthRequest` details will ever be printed.

#### Server interface

We've added a new [`Server`](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/op#Server) interface. This interface is experimental and subject to change. See [issue 440](https://github.com/zitadel/oidc/issues/440) for the motivation and discussion around this new interface.
Usage of the new interface is not required, but may be used for advanced scenarios when working with the `Storage` interface isn't the optimal solution for your app (like we experienced in [Zitadel](https://github.com/zitadel/zitadel)).

#### AuthRequestError

`AuthRequestError` now takes the complete `Authorizer` as final argument, instead of only the encoder.
This is to facilitate the use of the `Logger` as described above.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/\bAuthRequestError(w, r, authReq, err, authorizer.Encoder())/AuthRequestError(w, r, authReq, err, authorizer)/g'
```

Note: the sed regex might not find all uses if the local variables of the passed arguments use different names.

#### AccessTokenVerifier

`AccessTokenVerifier` interface has become a struct type. `NewAccessTokenVerifier` now returns a pointer to `AccessTokenVerifier`.
Variable and struct fields declarations need to be changed from `op.AccessTokenVerifier` to `*op.AccessTokenVerifier`.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/\bop\.AccessTokenVerifier\b/*op.AccessTokenVerifier/g'
```

#### JWTProfileVerifier

`JWTProfileVerifier` interface has become a struct type. `NewJWTProfileVerifier` now returns a pointer to `JWTProfileVerifier`.
Variable and struct fields declarations need to be changed from `op.JWTProfileVerifier` to `*op.JWTProfileVerifier`.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/\bop\.JWTProfileVerifier\b/*op.JWTProfileVerifier/g'
```

#### IDTokenHintVerifier

`IDTokenHintVerifier` interface has become a struct type. `NewIDTokenHintVerifier` now returns a pointer to `IDTokenHintVerifier`.
Variable and struct fields declarations need to be changed from `op.IDTokenHintVerifier` to `*op.IDTokenHintVerifier`.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/\bop\.IDTokenHintVerifier\b/*op.IDTokenHintVerifier/g'
```

#### ParseRequestObject

`ParseRequestObject` no longer returns `*oidc.AuthRequest` as it already operates on the pointer for the passed `authReq` argument. As such the argument and the return value were the same pointer. Callers can just use the original `*oidc.AuthRequest` now.

#### Endpoint Configuration

`Endpoint`s returned from `Configuration` interface methods are now pointers. Usually, `op.Provider` is the main implementation of the `Configuration` interface. However, if a custom implementation is used, you should be able to update it using the following:

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/AuthorizationEndpoint() Endpoint/AuthorizationEndpoint() *Endpoint/g' \
    -e 's/TokenEndpoint() Endpoint/TokenEndpoint() *Endpoint/g' \
    -e 's/IntrospectionEndpoint() Endpoint/IntrospectionEndpoint() *Endpoint/g' \
    -e 's/UserinfoEndpoint() Endpoint/UserinfoEndpoint() *Endpoint/g' \
    -e 's/RevocationEndpoint() Endpoint/RevocationEndpoint() *Endpoint/g' \
    -e 's/EndSessionEndpoint() Endpoint/EndSessionEndpoint() *Endpoint/g' \
    -e 's/KeysEndpoint() Endpoint/KeysEndpoint() *Endpoint/g' \
    -e 's/DeviceAuthorizationEndpoint() Endpoint/DeviceAuthorizationEndpoint() *Endpoint/g'
```

#### CreateDiscoveryConfig

`CreateDiscoveryConfig` now takes a context as first argument. The following adds `context.TODO()` to the function:

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/op\.CreateDiscoveryConfig(/op.CreateDiscoveryConfig(context.TODO(), /g'
```

It now takes the issuer out of the context using the [`IssuerFromContext`](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/op#IssuerFromContext) functionality,
instead of the `config.IssuerFromRequest()` method.

#### CreateRouter

`CreateRouter` now returns a `chi.Router` instead of `*mux.Router`.
Usually this function is called when the Provider is constructed and not by package consumers.
However if your project does call this function directly, manual update of the code is required.

#### DeviceAuthorizationStorage

`DeviceAuthorizationStorage` dropped the following methods:

- `GetDeviceAuthorizationByUserCode`
- `CompleteDeviceAuthorization`
- `DenyDeviceAuthorization`

These methods proved not to be required from a library point of view.
Implementations of a device authorization flow may take care of these calls in a way they see fit.

#### AuthorizeCodeChallenge

The `AuthorizeCodeChallenge` function now only takes the `CodeVerifier` argument, instead of the complete `*oidc.AccessTokenRequest`.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/op\.AuthorizeCodeChallenge(tokenReq/op.AuthorizeCodeChallenge(tokenReq.CodeVerifier/g'
```

### client

```go
import "github.com/zitadel/oidc/v3/pkg/client"
```

#### Context

All client calls now take a context as first argument. The following adds `context.TODO()` to all the affected functions:

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/client\.Discover(/client.Discover(context.TODO(), /g' \
    -e 's/client\.CallTokenEndpoint(/client.CallTokenEndpoint(context.TODO(), /g' \
    -e 's/client\.CallEndSessionEndpoint(/client.CallEndSessionEndpoint(context.TODO(), /g' \
    -e 's/client\.CallRevokeEndpoint(/client.CallRevokeEndpoint(context.TODO(), /g' \
    -e 's/client\.CallTokenExchangeEndpoint(/client.CallTokenExchangeEndpoint(context.TODO(), /g' \
    -e 's/client\.CallDeviceAuthorizationEndpoint(/client.CallDeviceAuthorizationEndpoint(context.TODO(), /g' \
    -e 's/client\.JWTProfileExchange(/client.JWTProfileExchange(context.TODO(), /g'
```

#### keyFile type

The `keyFile` struct type is now exported a `KeyFile` and returned by the `ConfigFromKeyFile` and `ConfigFromKeyFileData`. No changes are needed on the caller's side.

### client/profile

The package now defines a new interface `TokenSource` which compliments the `oauth2.TokenSource` with a `TokenCtx` method, so that a context can be explicitly added on each call. Users can migrate to the new method when they whish.

`NewJWTProfileTokenSource` now takes a context as first argument, so do the related `NewJWTProfileTokenSourceFromKeyFile` and `NewJWTProfileTokenSourceFromKeyFileData`. The context is used for the Discovery request.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/profile\.NewJWTProfileTokenSource(/profile.NewJWTProfileTokenSource(context.TODO(), /g' \
    -e 's/profile\.NewJWTProfileTokenSourceFromKeyFileData(/profile.NewJWTProfileTokenSourceFromKeyFileData(context.TODO(), /g' \
    -e 's/profile\.NewJWTProfileTokenSourceFromKeyFile(/profile.NewJWTProfileTokenSourceFromKeyFile(context.TODO(), /g'
```


### client/rp

```go
import "github.com/zitadel/oidc/v3/pkg/client/rs"
```

#### Discover

The `Discover` function has been removed. Use `client.Discover` instead.

#### Context

Most `rp` functions now require a context as first argument. The following adds `context.TODO()` to the function that have no additional changes. Functions with more complex changes are documented below.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/rp\.NewRelyingPartyOIDC(/rp.NewRelyingPartyOIDC(context.TODO(), /g' \
    -e 's/rp\.EndSession(/rp.EndSession(context.TODO(), /g' \
    -e 's/rp\.RevokeToken(/rp.RevokeToken(context.TODO(), /g' \
    -e 's/rp\.DeviceAuthorization(/rp.DeviceAuthorization(context.TODO(), /g'
```

Remember to replace `context.TODO()` with a context that is applicable for your app, where possible.

#### RefreshAccessToken

1. Renamed to `RefreshTokens`;
2. A context must be passed;
3. An `*oidc.Tokens` object is now returned, which included an ID Token if it was returned by the server;
4. The function is now generic and requires a type argument for the `IDTokenClaims` implementation inside the returned `oidc.Tokens` object;

For most use cases `*oidc.IDTokenClaims` can be used as type argument. A custom implementation of `oidc.IDClaims` can be used if type-safe access to custom claims is required.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/rp\.RefreshAccessToken(/rp.RefreshTokens[*oidc.IDTokenClaims](context.TODO(), /g'
```

Users that called `tokens.Extra("id_token").(string)` and a subsequent `VerifyTokens` to get the claims, no longer need to do this. The ID token is verified (when present) by `RefreshTokens` already.


#### Userinfo

1. A context must be passed as first argument;
2. The function is now generic and requires a type argument for the returned user info object;

For most use cases `*oidc.UserInfo` can be used a type argument. A [custom implementation](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/client/rp#example-Userinfo-Custom) of `rp.SubjectGetter` can be used if type-safe access to custom claims is required.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/rp\.Userinfo(/rp.Userinfo[*oidc.UserInfo](context.TODO(), /g'
```

#### UserinfoCallback

`UserinfoCallback` has an additional type argument fot the `UserInfo` object. Typically the type argument can be inferred by the compiler, by the function that is passed. The actual code update cannot be done by a simple `sed` script and depends on how the caller implemented the function.


#### IDTokenVerifier

`IDTokenVerifier` interface has become a struct type. `NewIDTokenVerifier` now returns a pointer to `IDTokenVerifier`.
Variable and struct fields declarations need to be changed from `rp.IDTokenVerifier` to `*rp.AccessTokenVerifier`.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/\brp\.IDTokenVerifier\b/*rp.IDTokenVerifier/g'
```

### client/rs

```go
import "github.com/zitadel/oidc/v3/pkg/client/rs"
```

#### NewResourceServer

The `NewResourceServerClientCredentials` and `NewResourceServerJWTProfile` constructor functions now take a context as first argument.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/rs\.NewResourceServerClientCredentials(/rs.NewResourceServerClientCredentials(context.TODO(), /g' \
    -e 's/rs\.NewResourceServerJWTProfile(/rs.NewResourceServerJWTProfile(context.TODO(), /g'
```

#### Introspect

`Introspect` is now generic and requires a type argument for the returned introspection response. For most use cases `*oidc.IntrospectionResponse` can be used as type argument. Any other response type if type-safe access to [custom claims](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/client/rs#example-Introspect-Custom) is required.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/rs\.Introspect(/rs.Introspect[*oidc.IntrospectionResponse](/g'
```

### client/tokenexchange

The `TokenExchanger` constructor functions `NewTokenExchanger` and `NewTokenExchangerClientCredentials` now take a context as first argument.
As well as the `ExchangeToken` function.

```bash
find . -type f -name '*.go' | xargs sed -i \
    -e 's/tokenexchange\.NewTokenExchanger(/tokenexchange.NewTokenExchanger(context.TODO(), /g' \
    -e 's/tokenexchange\.NewTokenExchangerClientCredentials(/tokenexchange.NewTokenExchangerClientCredentials(context.TODO(), /g' \
    -e 's/tokenexchange\.ExchangeToken(/tokenexchange.ExchangeToken(context.TODO(), /g'
```

### oidc

#### SpaceDelimitedArray

The `SpaceDelimitedArray` type's `Encode()` function has been renamed to `String()` so it implements the `fmt.Stringer` interface. If the `Encode` method was called by a package consumer, it should be changed manually.

#### Verifier

The `Verifier` interface as been changed into a struct type. The struct type is aliased in the `op` and `rp` packages for the specific token use cases. See the relevant section above.

### Full script

For the courageous this is the full `sed` script which combines all the steps described above.
It should migrate most of the code in a repository to a more-or-less compilable state,
using defaults such as `context.TODO()` where possible.

Warnings:
- Again, this is written for **GNU sed** not the posix variant.
- Assumes imports that use the package names, not aliases.
- Do this on a project with version control (eg Git), that allows you to rollback if things went wrong.
- The script has been tested on the [ZITADEL](https://github.com/zitadel/zitadel) project, but we do not use all affected symbols. Parts of the script are mere guesswork.

```bash
go get -u github.com/zitadel/oidc/v3
find . -type f -name '*.go' | xargs sed -i \
    -e 's/github\.com\/zitadel\/oidc\/v2/github.com\/zitadel\/oidc\/v3/g' \
    -e 's/gopkg.in\/square\/go-jose\.v2/github.com\/go-jose\/go-jose\/v3/g' \
    -e 's/\bAuthRequestError(w, r, authReq, err, authorizer.Encoder())/AuthRequestError(w, r, authReq, err, authorizer)/g' \
    -e 's/\bop\.AccessTokenVerifier\b/*op.AccessTokenVerifier/g' \
    -e 's/\bop\.JWTProfileVerifier\b/*op.JWTProfileVerifier/g' \
    -e 's/\bop\.IDTokenHintVerifier\b/*op.IDTokenHintVerifier/g' \
    -e 's/AuthorizationEndpoint() Endpoint/AuthorizationEndpoint() *Endpoint/g' \
    -e 's/TokenEndpoint() Endpoint/TokenEndpoint() *Endpoint/g' \
    -e 's/IntrospectionEndpoint() Endpoint/IntrospectionEndpoint() *Endpoint/g' \
    -e 's/UserinfoEndpoint() Endpoint/UserinfoEndpoint() *Endpoint/g' \
    -e 's/RevocationEndpoint() Endpoint/RevocationEndpoint() *Endpoint/g' \
    -e 's/EndSessionEndpoint() Endpoint/EndSessionEndpoint() *Endpoint/g' \
    -e 's/KeysEndpoint() Endpoint/KeysEndpoint() *Endpoint/g' \
    -e 's/DeviceAuthorizationEndpoint() Endpoint/DeviceAuthorizationEndpoint() *Endpoint/g' \
    -e 's/op\.CreateDiscoveryConfig(/op.CreateDiscoveryConfig(context.TODO(), /g' \
    -e 's/op\.AuthorizeCodeChallenge(tokenReq/op.AuthorizeCodeChallenge(tokenReq.CodeVerifier/g' \
    -e 's/client\.Discover(/client.Discover(context.TODO(), /g' \
    -e 's/client\.CallTokenEndpoint(/client.CallTokenEndpoint(context.TODO(), /g' \
    -e 's/client\.CallEndSessionEndpoint(/client.CallEndSessionEndpoint(context.TODO(), /g' \
    -e 's/client\.CallRevokeEndpoint(/client.CallRevokeEndpoint(context.TODO(), /g' \
    -e 's/client\.CallTokenExchangeEndpoint(/client.CallTokenExchangeEndpoint(context.TODO(), /g' \
    -e 's/client\.CallDeviceAuthorizationEndpoint(/client.CallDeviceAuthorizationEndpoint(context.TODO(), /g' \
    -e 's/client\.JWTProfileExchange(/client.JWTProfileExchange(context.TODO(), /g' \
    -e 's/profile\.NewJWTProfileTokenSource(/profile.NewJWTProfileTokenSource(context.TODO(), /g' \
    -e 's/profile\.NewJWTProfileTokenSourceFromKeyFileData(/profile.NewJWTProfileTokenSourceFromKeyFileData(context.TODO(), /g' \
    -e 's/profile\.NewJWTProfileTokenSourceFromKeyFile(/profile.NewJWTProfileTokenSourceFromKeyFile(context.TODO(), /g' \
    -e 's/rp\.NewRelyingPartyOIDC(/rp.NewRelyingPartyOIDC(context.TODO(), /g' \
    -e 's/rp\.EndSession(/rp.EndSession(context.TODO(), /g' \
    -e 's/rp\.RevokeToken(/rp.RevokeToken(context.TODO(), /g' \
    -e 's/rp\.DeviceAuthorization(/rp.DeviceAuthorization(context.TODO(), /g' \
    -e 's/rp\.RefreshAccessToken(/rp.RefreshTokens[*oidc.IDTokenClaims](context.TODO(), /g' \
    -e 's/rp\.Userinfo(/rp.Userinfo[*oidc.UserInfo](context.TODO(), /g' \
    -e 's/\brp\.IDTokenVerifier\b/*rp.IDTokenVerifier/g' \
    -e 's/rs\.NewResourceServerClientCredentials(/rs.NewResourceServerClientCredentials(context.TODO(), /g' \
    -e 's/rs\.NewResourceServerJWTProfile(/rs.NewResourceServerJWTProfile(context.TODO(), /g' \
    -e 's/rs\.Introspect(/rs.Introspect[*oidc.IntrospectionResponse](/g' \
    -e 's/tokenexchange\.NewTokenExchanger(/tokenexchange.NewTokenExchanger(context.TODO(), /g' \
    -e 's/tokenexchange\.NewTokenExchangerClientCredentials(/tokenexchange.NewTokenExchangerClientCredentials(context.TODO(), /g' \
    -e 's/tokenexchange\.ExchangeToken(/tokenexchange.ExchangeToken(context.TODO(), /g'
go mod tidy
```