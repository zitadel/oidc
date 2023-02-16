package mock

//go:generate mockgen -package mock -destination ./verifier.mock.go github.com/zitadel/oidc/v2/pkg/rp Verifier
