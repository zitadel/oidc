package mock

//go:generate mockgen -package mock -destination ./verifier.mock.go github.com/caos/oidc/pkg/rp Verifier
