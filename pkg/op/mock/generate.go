package mock

//go:generate mockgen -package mock -destination ./storage.mock.go github.com/caos/oidc/pkg/op/u Storage
//go:generate mockgen -package mock -destination ./authorizer.mock.go github.com/caos/oidc/pkg/op Authorizer
