module github.com/caos/oidc/pkg/op

go 1.13

replace github.com/caos/oidc => /Users/livio/workspaces/go/src/github.com/caos/oidc

replace github.com/caos/oidc/pkg/oidc => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/oidc

replace github.com/caos/oidc/pkg/utils => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/utils

replace github.com/caos/oidc/pkg/op => /Users/livio/workspaces/go/src/github.com/caos/oidc/pkg/op

require (
	github.com/caos/oidc/pkg/oidc v0.0.0-00010101000000-000000000000
	github.com/caos/oidc/pkg/utils v0.0.0-00010101000000-000000000000
	github.com/caos/utils v0.0.0-20191104132131-b318678afbef
	github.com/caos/utils/logging v0.0.0-20191104132131-b318678afbef
	github.com/golang/mock v1.3.1
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/schema v1.1.0
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.4.0
	gopkg.in/square/go-jose.v2 v2.4.0
	gopkg.in/yaml.v2 v2.2.7 // indirect
)
