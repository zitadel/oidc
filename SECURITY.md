# Security Policy

At ZITADEL we are extremely grateful for security aware people that disclose vulnerabilities to us and the open source community. All reports will be investigated by our team.

## Supported Versions

We currently support the following version of the OIDC framework:

| Version  | Supported          | Branch      | Details                               |
| -------- | ------------------ | ----------- | ------------------------------------- |
| 0.x.x    | :x:                |             | not maintained                        |
| <1.13    | :x:                |             | not maintained                        |
| 1.13.x   | :lock: :warning:   | [1.13.x][1] | security only, [community effort][2] |
| 2.x.x    | :heavy_check_mark: | [main][3]   | supported                             |
| 3.0.0-xx | :white_check_mark: | [next][5] | [developement branch][4]              |

[1]: https://github.com/zitadel/oidc/tree/1.13.x
[2]: https://github.com/zitadel/oidc/discussions/378
[3]: https://github.com/zitadel/oidc/tree/main
[4]: https://github.com/zitadel/oidc/tree/next
[5]: https://github.com/zitadel/oidc/milestone/2

## Reporting a vulnerability

To file a incident, please disclose by email to security@zitadel.com with the security details.

At the moment GPG encryption is no yet supported, however you may sign your message at will.

### When should I report a vulnerability

* You think you discovered a ...
  * ... potential security vulnerability in the SDK
  * ... vulnerability in another project that this SDK bases on
* For projects with their own vulnerability reporting and disclosure process, please report it directly there

### When should I NOT report a vulnerability

* You need help applying security related updates
* Your issue is not security related

## Security Vulnerability Response

TBD

## Public Disclosure

All accepted and mitigated vulnerabilities will be published on the [Github Security Page](https://github.com/zitadel/oidc/security/advisories)

### Timing

We think it is crucial to publish advisories `ASAP` as mitigations are ready. But due to the unknown nature of the disclosures the time frame can range from 7 to 90 days.
