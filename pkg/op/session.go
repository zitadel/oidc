package op

import "github.com/caos/oidc/pkg/oidc"

func NeedsExistingSession(authRequest *oidc.AuthRequest) bool {
	if authRequest == nil {
		return true
	}
	if authRequest.Prompt == oidc.PromptNone {
		return true
	}
	return false
}
