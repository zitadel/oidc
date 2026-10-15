package oidc

import (
	"crypto/sha256"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

const (
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
	CodeChallengeMethodS256  CodeChallengeMethod = "S256"
)

type CodeChallengeMethod string

// IsSupported reports whether m is a code challenge method that
// VerifyCodeChallenge can verify: plain or S256.
// An empty method is not a method; RFC 7636, section 4.3, defaults it to plain.
func (m CodeChallengeMethod) IsSupported() bool {
	switch m {
	case CodeChallengeMethodPlain, CodeChallengeMethodS256:
		return true
	default:
		return false
	}
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
	switch c.Method {
	case CodeChallengeMethodS256:
		codeVerifier = NewSHACodeChallenge(codeVerifier)
	case "", CodeChallengeMethodPlain:
	default:
		return false
	}
	return codeVerifier == c.Challenge
}
