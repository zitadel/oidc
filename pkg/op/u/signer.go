package u

import (
	"github.com/caos/oidc/pkg/oidc"
)

type Signer interface {
	Sign(claims *oidc.IDTokenClaims) (string, error)
}
