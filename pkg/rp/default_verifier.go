package rp

import (
	"context"
	"fmt"
	"time"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

//DefaultVerifier implements the `Verifier` interface
type DefaultVerifier struct {
	config *verifierConfig
	keySet oidc.KeySet
}

//ConfFunc is the type for providing dynamic options to the DefaultVerfifier
type ConfFunc func(*verifierConfig)

//NewDefaultVerifier creates `DefaultVerifier` with the given
//issuer, clientID, keyset and possible configOptions
func NewDefaultVerifier(issuer, clientID string, keySet oidc.KeySet, confOpts ...ConfFunc) Verifier {
	conf := &verifierConfig{
		issuer:   issuer,
		clientID: clientID,
		iat:      &iatConfig{
			// offset: time.Duration(500 * time.Millisecond),
		},
	}

	for _, opt := range confOpts {
		if opt != nil {
			opt(conf)
		}
	}
	return &DefaultVerifier{config: conf, keySet: keySet}
}

//WithIgnoreAudience will turn off validation for audience claim (should only be used for id_token_hints)
func WithIgnoreAudience() func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.ignoreAudience = true
	}
}

//WithIgnoreExpiration will turn off validation for expiration claim (should only be used for id_token_hints)
func WithIgnoreExpiration() func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.ignoreExpiration = true
	}
}

//WithIgnoreIssuedAt will turn off iat claim verification
func WithIgnoreIssuedAt() func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.iat.ignore = true
	}
}

//WithIssuedAtOffset mitigates the risk of iat to be in the future
//because of clock skews with the ability to add an offset to the current time
func WithIssuedAtOffset(offset time.Duration) func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.iat.offset = offset
	}
}

//WithIssuedAtMaxAge provides the ability to define the maximum duration between iat and now
func WithIssuedAtMaxAge(maxAge time.Duration) func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.iat.maxAge = maxAge
	}
}

//WithNonce TODO: ?
func WithNonce(nonce string) func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.nonce = nonce
	}
}

//WithACRVerifier sets the verifier for the acr claim
func WithACRVerifier(verifier oidc.ACRVerifier) func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.acr = verifier
	}
}

//WithAuthTimeMaxAge provides the ability to define the maximum duration between auth_time and now
func WithAuthTimeMaxAge(maxAge time.Duration) func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.maxAge = maxAge
	}
}

//WithSupportedSigningAlgorithms overwrites the default RS256 signing algorithm
func WithSupportedSigningAlgorithms(algs ...string) func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.supportedSignAlgs = algs
	}
}

type verifierConfig struct {
	issuer            string
	clientID          string
	nonce             string
	ignoreAudience    bool
	ignoreExpiration  bool
	iat               *iatConfig
	acr               oidc.ACRVerifier
	maxAge            time.Duration
	supportedSignAlgs []string

	// httpClient *http.Client

	now time.Time
}

type iatConfig struct {
	ignore bool
	offset time.Duration
	maxAge time.Duration
}

//DefaultACRVerifier implements `ACRVerifier` returning an error
//if non of the provided values matches the acr claim
func DefaultACRVerifier(possibleValues []string) oidc.ACRVerifier {
	return func(acr string) error {
		if !utils.Contains(possibleValues, acr) {
			return fmt.Errorf("expected one of: %v, got: %q", possibleValues, acr)
		}
		return nil
	}
}

//Verify implements the `Verify` method of the `Verifier` interface
//according to https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
//and https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation
func (v *DefaultVerifier) Verify(ctx context.Context, accessToken, idTokenString string) (*oidc.IDTokenClaims, error) {
	v.config.now = time.Now().UTC()
	return VerifyTokens(ctx, accessToken, idTokenString, v)
}

//Verify implements the `VerifyIDToken` method of the `Verifier` interface
//according to https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (v *DefaultVerifier) VerifyIDToken(ctx context.Context, idTokenString string) (*oidc.IDTokenClaims, error) {
	return VerifywIDToken(ctx, idTokenString, v)
}

func (v *DefaultVerifier) now() time.Time {
	if v.config.now.IsZero() {
		v.config.now = time.Now().UTC().Round(time.Second)
	}
	return v.config.now
}

func (v *DefaultVerifier) Issuer() string {
	return v.config.issuer
}

func (v *DefaultVerifier) ClientID() string {
	return v.config.clientID
}

func (v *DefaultVerifier) SupportedSignAlgs() []string {
	return v.config.supportedSignAlgs
}

func (v *DefaultVerifier) KeySet() oidc.KeySet {
	return v.keySet
}

func (v *DefaultVerifier) ACR() oidc.ACRVerifier {
	return v.config.acr
}

func (v *DefaultVerifier) MaxAge() time.Duration {
	return v.config.maxAge
}

func (v *DefaultVerifier) MaxAgeIAT() time.Duration {
	return v.config.iat.maxAge
}

func (v *DefaultVerifier) Offset() time.Duration {
	return v.config.iat.offset
}
