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

func (c *CodeChallenge) Verify(codeVerifier string) bool {
	if c.Method == CodeChallengeMethodS256 {
		codeVerifier = utils.HashString(sha256.New(), codeVerifier)
	}
	return codeVerifier == c.Challenge
}
