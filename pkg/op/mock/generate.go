package mock

//go:generate mockgen -package mock -destination ./storage.mock.go github.com/caos/oidc/pkg/op Storage
//go:generate mockgen -package mock -destination ./authorizer.mock.go github.com/caos/oidc/pkg/op Authorizer
//go:generate mockgen -package mock -destination ./client.mock.go github.com/caos/oidc/pkg/op Client
//go:generate mockgen -package mock -destination ./configuration.mock.go github.com/caos/oidc/pkg/op Configuration
//go:generate mockgen -package mock -destination ./signer.mock.go github.com/caos/oidc/pkg/op Signer
