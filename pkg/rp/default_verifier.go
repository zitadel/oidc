package rp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
	str_utils "github.com/caos/utils/strings"
)

//DefaultVerifier implements the `Verifier` interface
type DefaultVerifier struct {
	config *verifierConfig
	keySet oidc.KeySet
}

//ConfFunc is the type for providing dynamic verifierConfig
type ConfFunc func(*verifierConfig)

//ACRVerifier specifies the function to be used by the `DefaultVerifier` for validating the acr claim
type ACRVerifier func(string) error

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
func WithACRVerifier(verifier ACRVerifier) func(*verifierConfig) {
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

// func WithVerifierHTTPClient(client *http.Client) func(*verifierConfig) {
// 	return func(conf *verifierConfig) {
// 		conf.httpClient = client
// 	}
// }

type verifierConfig struct {
	issuer            string
	clientID          string
	nonce             string
	iat               *iatConfig
	acr               ACRVerifier
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
func DefaultACRVerifier(possibleValues []string) ACRVerifier {
	return func(acr string) error {
		if !str_utils.Contains(possibleValues, acr) {
			return ErrAcrInvalid(possibleValues, acr)
		}
		return nil
	}
}

//Verify implements the `Verify` method of the `Verifier` interface
//according to https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
//and https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation
func (v *DefaultVerifier) Verify(ctx context.Context, accessToken, idTokenString string) (*oidc.IDTokenClaims, error) {
	v.config.now = time.Now().UTC()
	idToken, err := v.VerifyIDToken(ctx, idTokenString)
	if err != nil {
		return nil, err
	}
	if err := v.verifyAccessToken(accessToken, idToken.AccessTokenHash, idToken.Signature); err != nil { //TODO: sig from token
		return nil, err
	}
	return idToken, nil
}

func (v *DefaultVerifier) now() time.Time {
	if v.config.now.IsZero() {
		v.config.now = time.Now().UTC().Round(time.Second)
	}
	return v.config.now
}

//VerifyIDToken: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (v *DefaultVerifier) VerifyIDToken(ctx context.Context, idTokenString string) (*oidc.IDTokenClaims, error) {
	//1. if encrypted --> decrypt
	decrypted, err := v.decryptToken(idTokenString)
	if err != nil {
		return nil, err
	}
	claims, payload, err := v.parseToken(decrypted)
	if err != nil {
		return nil, err
	}
	// token, err := jwt.ParseWithClaims(decrypted, claims, func(token *jwt.Token) (interface{}, error) {
	//2, check issuer (exact match)
	if err := v.checkIssuer(claims.Issuer); err != nil {
		return nil, err
	}

	//3. check aud (aud must contain client_id, all aud strings must be allowed)
	if err = v.checkAudience(claims.Audiences); err != nil {
		return nil, err
	}

	if err = v.checkAuthorizedParty(claims.Audiences, claims.AuthorizedParty); err != nil {
		return nil, err
	}

	//6. check signature by keys
	//7. check alg default is rs256
	//8. check if alg is mac based (hs...) -> audience contains client_id. for validation use utf-8 representation of your client_secret
	claims.Signature, err = v.checkSignature(ctx, decrypted, payload)
	if err != nil {
		return nil, err
	}

	//9. check exp before now
	if err = v.checkExpiration(claims.Expiration); err != nil {
		return nil, err
	}

	//10. check iat duration is optional (can be checked)
	if err = v.checkIssuedAt(claims.IssuedAt); err != nil {
		return nil, err
	}

	//11. check nonce (check if optional possible) id_token.nonce == sentNonce
	if err = v.checkNonce(claims.Nonce); err != nil {
		return nil, err
	}

	//12. if acr requested check acr
	if err = v.checkAuthorizationContextClassReference(claims.AuthenticationContextClassReference); err != nil {
		return nil, err
	}

	//13. if auth_time requested check if auth_time is less than max age
	if err = v.checkAuthTime(claims.AuthTime); err != nil {
		return nil, err
	}
	//return idtoken struct, err

	return claims, nil
	// })
	// _ = token
	// return err
}

func (v *DefaultVerifier) parseToken(tokenString string) (*oidc.IDTokenClaims, []byte, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, nil, ValidationError("token contains an invalid number of segments") //TODO: err NewValidationError("token contains an invalid number of segments", ValidationErrorMalformed)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	idToken := new(oidc.IDTokenClaims)
	err = json.Unmarshal(payload, idToken)
	return idToken, payload, err
}

func (v *DefaultVerifier) checkIssuer(issuer string) error {
	if v.config.issuer != issuer {
		return ErrIssuerInvalid(v.config.issuer, issuer)
	}
	return nil
}

func (v *DefaultVerifier) checkAudience(audiences []string) error {
	if !str_utils.Contains(audiences, v.config.clientID) {
		return ErrAudienceMissingClientID(v.config.clientID)
	}

	//TODO: check aud trusted
	return nil
}

//4. if multiple aud strings --> check if azp
//5. if azp --> check azp == client_id
func (v *DefaultVerifier) checkAuthorizedParty(audiences []string, authorizedParty string) error {
	if len(audiences) > 1 {
		if authorizedParty == "" {
			return ErrAzpMissing()
		}
	}
	if authorizedParty != "" && authorizedParty != v.config.clientID {
		return ErrAzpInvalid(authorizedParty, v.config.clientID)
	}
	return nil
}

func (v *DefaultVerifier) checkSignature(ctx context.Context, idTokenString string, payload []byte) (jose.SignatureAlgorithm, error) {
	jws, err := jose.ParseSigned(idTokenString)
	if err != nil {
		return "", err
	}
	if len(jws.Signatures) == 0 {
		return "", nil //TODO: error
	}
	if len(jws.Signatures) > 1 {
		return "", nil //TODO: error
	}
	sig := jws.Signatures[0]
	supportedSigAlgs := v.config.supportedSignAlgs
	if len(supportedSigAlgs) == 0 {
		supportedSigAlgs = []string{"RS256"}
	}
	if !str_utils.Contains(supportedSigAlgs, sig.Header.Algorithm) {
		return "", fmt.Errorf("oidc: id token signed with unsupported algorithm, expected %q got %q", supportedSigAlgs, sig.Header.Algorithm)
	}

	signedPayload, err := v.keySet.VerifySignature(ctx, jws)
	if err != nil {
		return "", err
		//TODO:
	}

	if !bytes.Equal(signedPayload, payload) {
		return "", ErrSignatureInvalidPayload() //TODO: err
	}
	return jose.SignatureAlgorithm(sig.Header.Algorithm), nil
}

// type KeySet struct {
// 	remoteURL  url.URL
// 	httpClient *http.Client
// 	keys       []jose.JSONWebKey

// 	m        sync.Mutex
// 	inflight *inflight
// }

// func (k *KeySet) GetKey(ctx context.Context, keyID string) (*jose.JSONWebKey, error) {
// 	key, err := k.getKey(keyID)
// 	if err != nil {
// 		//lock
// 		k.updateKeys(ctx)
// 		//unlock
// 		return k.getKey(keyID)
// 	}
// 	return key, nil
// }

// func (k *KeySet) getKey(keyID string) (*jose.JSONWebKey, error) {
// 	k.m.Lock()
// 	keys := k.keys
// 	k.m.Unlock()
// 	for _, key := range keys {
// 		if key.KeyID == keyID {
// 			return &key, nil
// 		}
// 	}
// 	return nil, nil //TODO: err
// }

// func (k *KeySet) retrieveNewKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
// 	resp, err := k.httpClient.Get(k.remoteURL.String())
// 	if err != nil {
// 		return nil, err
// 	}
// 	if resp.StatusCode != http.StatusOK {
// 		return nil, nil //TODO: errs
// 	}

// 	defer resp.Body.Close()
// 	body, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var keySet jose.JSONWebKeySet
// 	err = json.Unmarshal(body, keySet)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return keySet.Keys, nil
// }

// func (k *KeySet) updateKeys(ctx context.Context) error {
// 	k.inflight
// 	k.m.Lock()
// 	k.keys = keySet.Keys
// 	return nil
// }

func (v *DefaultVerifier) checkExpiration(expiration time.Time) error {
	expiration = expiration.Round(time.Second)
	if !v.now().Before(expiration) {
		return ErrExpInvalid(expiration)
	}
	return nil
}

func (v *DefaultVerifier) checkIssuedAt(issuedAt time.Time) error {
	if v.config.iat.ignore {
		return nil
	}
	issuedAt = issuedAt.Round(time.Second)
	offset := v.now().Add(v.config.iat.offset).Round(time.Second)
	if issuedAt.After(offset) {
		return ErrIatInFuture(issuedAt, offset)
	}
	if v.config.iat.maxAge == 0 {
		return nil
	}
	maxAge := v.now().Add(-v.config.iat.maxAge).Round(time.Second)
	if issuedAt.Before(maxAge) {
		return ErrIatToOld(maxAge, issuedAt)
	}
	return nil
}
func (v *DefaultVerifier) checkNonce(nonce string) error {
	if v.config.nonce == "" {
		return nil
	}
	if v.config.nonce != nonce {
		return ErrNonceInvalid(v.config.nonce, nonce)
	}
	return nil
}
func (v *DefaultVerifier) checkAuthorizationContextClassReference(acr string) error {
	if v.config.acr != nil {
		return v.config.acr(acr)
	}
	return nil
}
func (v *DefaultVerifier) checkAuthTime(authTime time.Time) error {
	if v.config.maxAge == 0 {
		return nil
	}
	if authTime.IsZero() {
		return ErrAuthTimeNotPresent()
	}
	authTime = authTime.Round(time.Second)
	maxAge := v.now().Add(-v.config.maxAge).Round(time.Second)
	if authTime.Before(maxAge) {
		return ErrAuthTimeToOld(maxAge, authTime)
	}
	return nil
}

func (v *DefaultVerifier) decryptToken(tokenString string) (string, error) {
	return tokenString, nil //TODO: impl
}

// func (v *Verifier) parseIDToken(tokenString string) (IDToken, error) {
// 	var claims jwt.StandardClaims
// 	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
// 		claims.VerifyIssuer(v.config.Issuer, true)

// 		// return token.Header["alg"]
// 	})

// 	payload, err := parseJWT(rawIDToken)
// 	if err != nil {
// 		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
// 	}
// 	var token IDToken
// 	if err := json.Unmarshal(payload, &token); err != nil {
// 		return nil, fmt.Errorf("oidc: failed to unmarshal claims: %v", err)
// 	}
// 	return token, nil //TODO: impl
// }

func (v *DefaultVerifier) verifyAccessToken(accessToken, atHash string, sigAlgorithm jose.SignatureAlgorithm) error {
	if atHash == "" {
		return nil //TODO: return error
	}

	tokenHash, err := getHashAlgorithm(sigAlgorithm)
	if err != nil {
		return err
	}

	tokenHash.Write([]byte(accessToken)) // hash documents that Write will never return an error
	sum := tokenHash.Sum(nil)[:tokenHash.Size()/2]
	actual := base64.RawURLEncoding.EncodeToString(sum)
	if actual != atHash {
		return nil //TODO: error
	}
	return nil
}

func getHashAlgorithm(sigAlgorithm jose.SignatureAlgorithm) (hash.Hash, error) {
	switch sigAlgorithm {
	case jose.RS256, jose.ES256, jose.PS256:
		return sha256.New(), nil
	case jose.RS384, jose.ES384, jose.PS384:
		return sha512.New384(), nil
	case jose.RS512, jose.ES512, jose.PS512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("oidc: unsupported signing algorithm %q", sigAlgorithm)
	}
}
