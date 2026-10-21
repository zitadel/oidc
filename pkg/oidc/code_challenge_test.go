package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCodeChallengeMethod_IsSupported(t *testing.T) {
	tests := []struct {
		name   string
		method CodeChallengeMethod
		want   bool
	}{
		{name: "plain", method: CodeChallengeMethodPlain, want: true},
		{name: "S256", method: CodeChallengeMethodS256, want: true},
		{name: "empty", method: "", want: false},
		{name: "lower-case s256", method: "s256", want: false},
		{name: "S512", method: "S512", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.method.IsSupported())
		})
	}
}

func TestVerifyCodeChallenge(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	s256 := NewSHACodeChallenge(verifier)
	tests := []struct {
		name      string
		challenge *CodeChallenge
		want      bool
	}{
		{name: "nil challenge", challenge: nil, want: false},
		{name: "S256", challenge: &CodeChallenge{Challenge: s256, Method: CodeChallengeMethodS256}, want: true},
		{name: "S256 mismatch", challenge: &CodeChallenge{Challenge: verifier, Method: CodeChallengeMethodS256}, want: false},
		{name: "plain", challenge: &CodeChallenge{Challenge: verifier, Method: CodeChallengeMethodPlain}, want: true},
		{name: "empty method is plain", challenge: &CodeChallenge{Challenge: verifier}, want: true},
		// An unsupported method must not fall back to a plain comparison.
		{name: "unsupported method", challenge: &CodeChallenge{Challenge: verifier, Method: "S512"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, VerifyCodeChallenge(tt.challenge, verifier))
		})
	}
}
