# How to contribute to the OIDC SDK for Go

## Did you find a bug?

Please file an issue [here](https://github.com/zitadel/oidc/issues/new?assignees=&labels=bug&template=bug_report.md&title=).

Bugs are evaluated every day as soon as possible.

## Enhancement

Do you miss a feature? Please file an issue [here](https://github.com/zitadel/oidc/issues/new?assignees=&labels=enhancement&template=feature_request.md&title=)

Enhancements are discussed and evaluated every Wednesday by the ZITADEL core team.

## Grab an Issues

We add the label "good first issue" for problems we think are a good starting point to contribute to the OIDC SDK.

* [Issues for first time contributors](https://github.com/zitadel/oidc/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
* [All issues](https://github.com/zitadel/oidc/issues)

## Submitting a pull request (PR)

If you like to contribute fork the OIDC repository. After you implemented the new feature create a Pull Request in the OIDC repository.

Make sure you use [semantic release messages format](https://github.com/angular/angular.js/blob/master/DEVELOPERS.md#type).

`<type>(<scope>): <short summary>`

### Type

Allowed values are listed in [`.github/semantic.yml`](.github/semantic.yml) under `types:`.

### Scope

This is optional to indicate which component is affected.
Allowed values are listed in [`.github/semantic.yml`](.github/semantic.yml) under `scopes:`.
When in doubt, omit the scope — `<type>: <short summary>` is always valid.

#### Short summary

Provide a brief description of the change.

## Dependency updates

Most dependency bumps (Dependabot or manual) can be merged once CI is green.
There is one exception that CI here cannot catch: **OpenTelemetry**.

### OpenTelemetry must not get ahead of k6

[`zitadel/xk6-modules`](https://github.com/zitadel/xk6-modules) — the k6 extension used for
ZITADEL's load tests — imports both this library and [k6](https://github.com/grafana/k6).
k6 pins the whole OpenTelemetry family (API, SDK and exporters) to a single version.
Go's minimal version selection means an `otel` requirement in *our* `go.mod` that is higher
than k6's raises only the API modules, while k6 keeps the SDK and exporters at its own
version. That mixed set has broken the xk6 build in the past.

So the rule is: **never require a `go.opentelemetry.io/otel*` version higher than the one in
the latest tagged k6 release.** Being on the same version, or lower, is fine.

### How to verify

CI does this for you: the **otel not ahead of k6** check
([`otel-k6-compat.yml`](.github/workflows/otel-k6-compat.yml)) runs on every PR and fails
if this module requires a newer otel than the latest k6 release. To run the same check
locally:

```bash
.github/scripts/check-otel-k6-compat.sh
```

It resolves the latest tagged k6 release on the major line `xk6-modules` builds against,
reads the otel versions from that tag's `go.mod`, and compares them with ours. Set
`K6_VERSION=v2.1.0` to check against a specific k6 tag instead.

By hand, the same thing is: read k6's `go.mod` at a **tagged release** (not `master`, which
is usually ahead) and compare with our [`go.mod`](go.mod):

```bash
tag=$(gh release view --repo grafana/k6 --json tagName -q .tagName)
curl -sL "https://raw.githubusercontent.com/grafana/k6/${tag}/go.mod" | grep opentelemetry
```

If the PR would push us above k6, hold it until k6 catches up.

Alternatively, from a checkout of `xk6-modules`, Grafana's
[`xk6 sync`](https://github.com/grafana/xk6#xk6-sync) command aligns an extension's
dependencies with the k6 version in its `go.mod` and shows the mismatches. A quick manual
check is to bump the otel modules in `xk6-modules` to the proposed version *without*
touching the k6 requirement, and confirm `go build ./...` still passes.

### The `2.12.x` branch

`2.12.x` is the maintenance branch for v2 and still targets an old Go version. Dependabot
regularly proposes bumps there (OpenTelemetry included) that rewrite the `go` directive and
break the build. Those PRs should be closed rather than merged unless the bump is a security
fix that genuinely applies to v2.

## Want to use the library?

Checkout the [examples folder](example) for different client and server implementations.

Or checkout how we use it ourselves in our OpenSource Identity and Access Management [ZITADEL](https://github.com/zitadel/zitadel).

## **Did you find a security flaw?**

* Please read [Security Policy](SECURITY.md).