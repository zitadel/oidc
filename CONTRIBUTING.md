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

## Want to use the library?

Checkout the [examples folder](example) for different client and server implementations.

Or checkout how we use it ourselves in our OpenSource Identity and Access Management [ZITADEL](https://github.com/zitadel/zitadel).

## **Did you find a security flaw?**

* Please read [Security Policy](SECURITY.md).