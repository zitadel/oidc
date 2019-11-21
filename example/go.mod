module github.com/caos/oidc/example

go 1.13

replace github.com/caos/oidc => /Users/livio/workspaces/go/src/github.com/caos/oidc

replace github.com/caos/oidc/pkg/oidc => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/oidc

replace github.com/caos/oidc/pkg/op => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/op

replace github.com/caos/oidc/pkg/rp => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/rp

replace github.com/caos/oidc/pkg/utils => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/utils

require (
	github.com/caos/oidc/pkg/oidc v0.0.0-00010101000000-000000000000
	github.com/caos/oidc/pkg/op v0.0.0-00010101000000-000000000000
	github.com/caos/oidc/pkg/rp v0.0.0-00010101000000-000000000000
	github.com/caos/oidc/pkg/utils v0.0.0-00010101000000-000000000000
	github.com/caos/utils/logging v0.0.0-20191104132131-b318678afbef
	github.com/google/uuid v1.1.1
	golang.org/x/crypto v0.0.0-20191117063200-497ca9f6d64f
)
