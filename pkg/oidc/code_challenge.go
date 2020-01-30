package oidc

import (
	"crypto/sha256"

	"github.com/caos/oidc/pkg/utils"
)

const (
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
	CodeChallengeMethodS256  CodeChallengeMethod = "S256"
)

type CodeChallengeMethod string

type CodeChallenge struct {
	Challenge string
	Method    CodeChallengeMethod
}

func NewSHACodeChallenge(code string) string {
	return utils.HashString(sha256.New(), code)
}

func VerifyCodeChallenge(c *CodeChallenge, codeVerifier string) bool {
	if c == nil {
		return false //TODO: ?
	}
	if c.Method == CodeChallengeMethodS256 {
		codeVerifier = NewSHACodeChallenge(codeVerifier)
	}
	return codeVerifier == c.Challenge
}
