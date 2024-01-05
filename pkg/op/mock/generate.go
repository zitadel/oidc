package mock

//go:generate go install github.com/golang/mock/mockgen@v1.6.0
//go:generate mockgen -package mock -destination ./storage.mock.go github.com/zitadel/oidc/v3/pkg/op Storage
//go:generate mockgen -package mock -destination ./authorizer.mock.go github.com/zitadel/oidc/v3/pkg/op Authorizer
//go:generate mockgen -package mock -destination ./client.mock.go github.com/zitadel/oidc/v3/pkg/op Client
//go:generate mockgen -package mock -destination ./glob.mock.go github.com/zitadel/oidc/v3/pkg/op HasRedirectGlobs
//go:generate mockgen -package mock -destination ./configuration.mock.go github.com/zitadel/oidc/v3/pkg/op Configuration
//go:generate mockgen -package mock -destination ./discovery.mock.go github.com/zitadel/oidc/v3/pkg/op DiscoverStorage
//go:generate mockgen -package mock -destination ./signer.mock.go github.com/zitadel/oidc/v3/pkg/op SigningKey,Key
//go:generate mockgen -package mock -destination ./key.mock.go github.com/zitadel/oidc/v3/pkg/op KeyProvider
