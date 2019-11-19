module github.com/caos/oidc/example

go 1.13

replace github.com/caos/oidc => /Users/livio/workspaces/go/src/github.com/caos/oidc

replace github.com/caos/oidc/pkg/oidc => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/oidc

replace github.com/caos/oidc/pkg/server => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/server

replace github.com/caos/oidc/pkg/client => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/client

replace github.com/caos/oidc/pkg/utils => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/utils

require (
	github.com/caos/oidc/pkg/client v0.0.0-00010101000000-000000000000
	github.com/caos/oidc/pkg/oidc v0.0.0-00010101000000-000000000000
	github.com/caos/oidc/pkg/server v0.0.0-00010101000000-000000000000
	github.com/caos/oidc/pkg/utils v0.0.0-00010101000000-000000000000
	github.com/caos/utils/logging v0.0.0-20191104132131-b318678afbef
	github.com/google/uuid v1.1.1
)
