package oidc

import (
	"crypto/sha256"
	"slices"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

const (
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
	CodeChallengeMethodS256  CodeChallengeMethod = "S256"
)

// AllCodeChallengeMethods lists the PKCE code challenge methods
// that VerifyCodeChallenge can verify.
var AllCodeChallengeMethods = []CodeChallengeMethod{
	CodeChallengeMethodPlain, CodeChallengeMethodS256,
}

type CodeChallengeMethod string

// IsSupported reports whether m is one of AllCodeChallengeMethods.
// An empty method is not a method; RFC 7636, section 4.3, defaults it to plain.
func (m CodeChallengeMethod) IsSupported() bool {
	return slices.Contains(AllCodeChallengeMethods, m)
}

type CodeChallenge struct {
	Challenge string
	Method    CodeChallengeMethod
}

func NewSHACodeChallenge(code string) string {
	return crypto.HashString(sha256.New(), code, false)
}

// VerifyCodeChallenge reports whether codeVerifier matches the challenge c.
// An empty method is verified as plain. An unsupported method never matches,
// rather than being compared as if it were plain.
func VerifyCodeChallenge(c *CodeChallenge, codeVerifier string) bool {
	if c == nil {
		return false
	}
	if c.Method != "" && !c.Method.IsSupported() {
		return false
	}
	if c.Method == CodeChallengeMethodS256 {
		codeVerifier = NewSHACodeChallenge(codeVerifier)
	}
	return codeVerifier == c.Challenge
}
