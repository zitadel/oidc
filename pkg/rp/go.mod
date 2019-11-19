module github.com/caos/oidc/pkg/client

go 1.13

require (
	github.com/caos/oidc/pkg/oidc v0.0.0-00010101000000-000000000000
	github.com/caos/oidc/pkg/rp v0.0.0-00010101000000-000000000000
	github.com/caos/oidc/pkg/utils v0.0.0-00010101000000-000000000000
	github.com/caos/utils v0.0.0-20191104132131-b318678afbef
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	gopkg.in/square/go-jose.v2 v2.4.0
)

replace github.com/caos/oidc/pkg/oidc => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/oidc

replace github.com/caos/oidc/pkg/rp => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/rp

replace github.com/caos/oidc/pkg/utils => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/utils
