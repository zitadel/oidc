package mock

//go:generate mockgen -package mock -destination ./verifier.mock.go github.com/zitadel/oidc/pkg/rp Verifier
