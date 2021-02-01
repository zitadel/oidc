package tokenexchange

const (
	AccessTokenType     = "urn:ietf:params:oauth:token-type:access_token"
	RefreshTokenType    = "urn:ietf:params:oauth:token-type:refresh_token"
	IDTokenType         = "urn:ietf:params:oauth:token-type:id_token"
	JWTTokenType        = "urn:ietf:params:oauth:token-type:jwt"
	DelegationTokenType = AccessTokenType

	TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
)

type TokenExchangeRequest struct {
	grantType          string   `schema:"grant_type"`
	subjectToken       string   `schema:"subject_token"`
	subjectTokenType   string   `schema:"subject_token_type"`
	actorToken         string   `schema:"actor_token"`
	actorTokenType     string   `schema:"actor_token_type"`
	resource           []string `schema:"resource"`
	audience           []string `schema:"audience"`
	scope              []string `schema:"scope"`
	requestedTokenType string   `schema:"requested_token_type"`
}

func NewTokenExchangeRequest(subjectToken, subjectTokenType string, opts ...TokenExchangeOption) *TokenExchangeRequest {
	t := &TokenExchangeRequest{
		grantType:          TokenExchangeGrantType,
		subjectToken:       subjectToken,
		subjectTokenType:   subjectTokenType,
		requestedTokenType: AccessTokenType,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

type TokenExchangeOption func(*TokenExchangeRequest)

func WithActorToken(token, tokenType string) func(*TokenExchangeRequest) {
	return func(req *TokenExchangeRequest) {
		req.actorToken = token
		req.actorTokenType = tokenType
	}
}

func WithAudience(audience []string) func(*TokenExchangeRequest) {
	return func(req *TokenExchangeRequest) {
		req.audience = audience
	}
}

func WithGrantType(grantType string) TokenExchangeOption {
	return func(req *TokenExchangeRequest) {
		req.grantType = grantType
	}
}

func WithRequestedTokenType(tokenType string) func(*TokenExchangeRequest) {
	return func(req *TokenExchangeRequest) {
		req.requestedTokenType = tokenType
	}
}

func WithResource(resource []string) func(*TokenExchangeRequest) {
	return func(req *TokenExchangeRequest) {
		req.resource = resource
	}
}

func WithScope(scope []string) func(*TokenExchangeRequest) {
	return func(req *TokenExchangeRequest) {
		req.scope = scope
	}
}
