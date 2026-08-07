#!/usr/bin/env bash
#
# Verify that this module does not require a newer OpenTelemetry version than the
# latest tagged k6 release.
#
# Why: zitadel/xk6-modules imports both this library and k6, and k6 pins the whole
# OpenTelemetry family (API, SDK and exporters) to a single version. If our go.mod
# asks for a higher otel version, minimal version selection raises only the API
# modules there while the SDK and exporters stay on k6's version. That mixed set has
# broken the load test build before. See CONTRIBUTING.md.
#
# Reads only public data and needs no credentials.
#
# Usage:
#   .github/scripts/check-otel-k6-compat.sh
#
# Environment:
#   K6_VERSION    check against this k6 tag instead of resolving the latest release
#
set -euo pipefail

XK6_GOMOD_URL="https://raw.githubusercontent.com/zitadel/xk6-modules/main/go.mod"
K6_REPO_URL="https://github.com/grafana/k6"
K6_GOMOD_URL="https://raw.githubusercontent.com/grafana/k6/%s/go.mod"

# Stable otel modules only: the whole go.opentelemetry.io/otel tree shares one version,
# but go.opentelemetry.io/auto/sdk and go.opentelemetry.io/proto/otlp are versioned
# independently, and the signal packages that are still v0 (log, ...) are not lock-stepped
# with the v1 ones either.
otel_versions() {
  grep -oE 'go\.opentelemetry\.io/otel(/[a-z0-9/]+)? v1\.[0-9]+\.[0-9]+' \
    | awk '{print $2}' | sort -Vu
}

ours=$(otel_versions < go.mod | tail -1)
[ -n "$ours" ] || { echo "go.mod requires no stable go.opentelemetry.io/otel module, nothing to check"; exit 0; }

# The k6 major line the load tests build against, e.g. "go.k6.io/k6/v2" -> "v2".
k6_major=$(curl -sSfL "$XK6_GOMOD_URL" | grep -oE 'go\.k6\.io/k6(/v[0-9]+)?' | head -1 | grep -oE 'v[0-9]+$' || true)
k6_major=${k6_major:-v1}

if [ -n "${K6_VERSION:-}" ]; then
  k6_tag="$K6_VERSION"
else
  # Release tags straight from the remote: no API, so no rate limit and no token.
  # Draft releases do not push a tag, and the pattern drops prereleases (v2.0.0-rc1).
  k6_tag=$(git ls-remote --tags --refs "$K6_REPO_URL" "${k6_major}.*" \
    | awk -F/ '{print $NF}' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
    | sort -V | tail -1)
  [ -n "$k6_tag" ] || { echo "::error::could not resolve the latest k6 ${k6_major} release"; exit 1; }
fi

# The lowest otel version k6 pins is the ceiling: anything above it is a version
# the k6 build will not have.
theirs=$(curl -sSfL "$(printf "$K6_GOMOD_URL" "$k6_tag")" | otel_versions | head -1)
[ -n "$theirs" ] || { echo "::error::no stable otel requirement found in k6 ${k6_tag} go.mod"; exit 1; }

echo "this module requires otel  ${ours}"
echo "k6 ${k6_tag} pins otel     ${theirs}"

if [ "$(printf '%s\n%s\n' "$ours" "$theirs" | sort -V | tail -1)" != "$theirs" ]; then
  cat <<EOF
::error::otel ${ours} is newer than the ${theirs} pinned by k6 ${k6_tag}
This would break the zitadel/xk6-modules build used for the ZITADEL load tests.
Hold this bump until k6 ships a release on otel ${ours} or newer.
See the "Dependency updates" section in CONTRIBUTING.md.
EOF
  exit 1
fi

echo "ok: otel is aligned with k6 ${k6_tag}"
