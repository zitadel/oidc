package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/op"
)

//storage implements the op.Storage interface
//typically you would implement this as a layer on top of your database
//for simplicity this example keeps everything in-memory
type storage struct {
	authRequests  map[string]*AuthRequest
	codes         map[string]string
	tokens        map[string]*Token
	clients       map[string]*Client
	users         map[string]*User
	services      map[string]Service
	refreshTokens map[string]*RefreshToken
	signingKey    signingKey
}

type signingKey struct {
	ID        string
	Algorithm string
	Key       *rsa.PrivateKey
}

func NewStorage() *storage {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &storage{
		authRequests:  make(map[string]*AuthRequest),
		codes:         make(map[string]string),
		tokens:        make(map[string]*Token),
		refreshTokens: make(map[string]*RefreshToken),
		clients:       clients,
		signingKey: signingKey{
			ID:        "id",
			Algorithm: "RS256",
			Key:       key,
		},
	}
}

//CheckUsernamePassword implements the `authenticate` interface of the login
func (s *storage) CheckUsernamePassword(username, password, id string) error {
	//for demonstration purposes we'll check on a static list with plain text password
	//for real world scenarios, be sure to have the password hashed and salted (e.g. using bcrypt)
	user, ok := s.users[username]
	if !ok || user.password != password {
		return fmt.Errorf("username or password wrong")
	}
	request, ok := s.authRequests[id]
	if !ok {
		return fmt.Errorf("request not found")
	}

	//be sure to set user id into the auth request after the user was checked (either with or without password),
	//so that you'll be able to get more information about the user after the login
	request.UserID = user.id

	//you will have to change some state on the request to guide the user through possible multiple steps of the login process
	//in this example we'll simply check the username / password and set a boolean to true
	//therefore we will also just check this boolean if the request / login has been finished
	request.passwordChecked = true
	return nil
}

//CreateAuthRequest implements the op.Storage interface
//it will be called after parsing and validation of the authentication request
func (s *storage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	//typically, you'll fill your internal / storage model with the information of the passed object
	request := authRequestToInternal(authReq, userID)

	//you'll also have to create a unique id for the request (this might be done by your database; we'll use a uuid)
	request.ID = uuid.NewString()

	//and save it in your database (for demonstration purposed we will use a simple map)
	s.authRequests[request.ID] = request

	//finally, return the request (which implements the AuthRequest interface of the OP
	return request, nil
}

//AuthRequestByID implements the op.Storage interface
//it will be called after the Login UI redirects back to the OIDC endpoint
func (s *storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	request, ok := s.authRequests[id]
	if !ok {
		return nil, fmt.Errorf("request not found")
	}
	return request, nil
}

//AuthRequestByCode implements the op.Storage interface
//it will be called after parsing and validation of the token request (in an authorization code flow)
func (s *storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	//for this example we read the id by code and then get the request by id
	requestID, ok := s.codes[code]
	if !ok {
		return nil, fmt.Errorf("code invalid or expired")
	}
	return s.AuthRequestByID(ctx, requestID)
}

//SaveAuthCode implements the op.Storage interface
//it will be called after the authentication has been successful and before redirecting the user agent to the redirect_uri
//(in an authorization code flow)
func (s *storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	//for this example we'll just save the authRequestID to the code
	s.codes[code] = id
	return nil
}

//DeleteAuthRequest implements the op.Storage interface
//it will be called after creating the token response (id and access tokens) for a valid
//- authentication request (in an implicit flow)
//- token request (in an authorization code flow)
func (s *storage) DeleteAuthRequest(ctx context.Context, id string) error {
	//you can simply delete all reference to the auth request
	delete(s.authRequests, id)
	for code, requestID := range s.codes {
		if id == requestID {
			delete(s.codes, code)
			return nil
		}
	}
	return nil
}

//CreateAccessToken implements the op.Storage interface
//it will be called for all requests able to return an access token (Authorization Code Flow, Implicit Flow, JWT Profile, ...)
func (s *storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	var applicationID string
	//if authenticated for an app (auth code / implicit flow) we must save the client_id to the token
	authReq, ok := request.(*AuthRequest)
	if ok {
		applicationID = authReq.ApplicationID
	}
	token, err := s.accessToken(applicationID, "", request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID, token.Expiration, nil
}

//CreateAccessAndRefreshTokens implements the op.Storage interface
//it will be called for all requests able to return an access and refresh token (Authorization Code Flow, Refresh Token Request)
func (s *storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	//get the information depending on the request type / implementation
	applicationID, authTime, amr := getInfoFromRequest(request)

	//if currentRefreshToken is empty (Code Flow) we will have to create a new refresh token
	if currentRefreshToken == "" {
		refreshTokenID := uuid.NewString()
		accessToken, err := s.accessToken(applicationID, refreshTokenID, request.GetSubject(), request.GetAudience(), request.GetScopes())
		if err != nil {
			return "", "", time.Time{}, err
		}
		refreshToken, err := s.createRefreshToken(accessToken, amr, authTime)
		if err != nil {
			return "", "", time.Time{}, err
		}
		return accessToken.ID, refreshToken, accessToken.Expiration, nil
	}

	//if we get here, the currentRefreshToken was not empty, so the call is a refresh token request
	//we therefore will have to check the currentRefreshToken and renew the refresh token
	refreshToken, refreshTokenID, err := s.renewRefreshToken(currentRefreshToken)
	if err != nil {
		return "", "", time.Time{}, err
	}
	accessToken, err := s.accessToken(applicationID, refreshTokenID, request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}
	return accessToken.ID, refreshToken, accessToken.Expiration, nil
}

//TokenRequestByRefreshToken implements the op.Storage interface
//it will be called after parsing and validation of the refresh token request
func (s *storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	token, ok := s.refreshTokens[refreshToken]
	if !ok {
		return nil, fmt.Errorf("invalid refresh_token")
	}
	return RefreshTokenRequestFromBusiness(token), nil
}

//TerminateSession implements the op.Storage interface
//it will be called after the user signed out, therefore the access and refresh token of the user of this client must be removed
func (s *storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	for _, token := range s.tokens {
		if token.ApplicationID == clientID && token.Subject == userID {
			delete(s.tokens, token.ID)
			delete(s.refreshTokens, token.RefreshTokenID)
			return nil
		}
	}
	return nil
}

//RevokeToken implements the op.Storage interface
//it will be called after parsing and validation of the token revocation request
func (s *storage) RevokeToken(ctx context.Context, token string, userID string, clientID string) *oidc.Error {
	//a single token was requested to be removed
	accessToken, ok := s.tokens[token]
	if ok {
		if accessToken.ApplicationID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		//if it is an access token, just remove it
		//you could also remove the corresponding refresh token if really necessary
		delete(s.tokens, accessToken.ID)
		return nil
	}
	refreshToken, ok := s.refreshTokens[token]
	if !ok {
		//if the token is neither an access nor a refresh token, just ignore it, the expected behaviour of
		//being not valid (anymore) is achieved
		return nil
	}
	if refreshToken.ApplicationID != clientID {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}
	//if it is a refresh token, you will have to remove the access token as well
	delete(s.refreshTokens, refreshToken.ID)
	for _, accessToken := range s.tokens {
		if accessToken.RefreshTokenID == refreshToken.ID {
			delete(s.tokens, accessToken.ID)
			return nil
		}
	}
	return nil
}

//GetSigningKey implements the op.Storage interface
//it will be called when creating the OpenID Provider
func (s *storage) GetSigningKey(ctx context.Context, keyCh chan<- jose.SigningKey) {
	//in this example the signing key is a static rsa.PrivateKey and the algorithm used is RS256
	//you would obviously have a more complex implementation and store / retrieve the key from your database as well
	//
	//the idea of the signing key channel is, that you can (with what ever mechanism) rotate your signing key and
	//switch the key of the signer via this channel
	keyCh <- jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(s.signingKey.Algorithm), //always tell the signer with algorithm to use
		Key: jose.JSONWebKey{
			KeyID: s.signingKey.ID, //always give the key an id so, that it will include it in the token header as `kid` claim
			Key:   s.signingKey.Key,
		},
	}
}

//GetKeySet implements the op.Storage interface
//it will be called to get the current (public) keys, among others for the keys_endpoint or for validating access_tokens on the userinfo_endpoint, ...
func (s *storage) GetKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	//as mentioned above, this example only has a single signing key without key rotation,
	//so it will directly use its public key
	//
	//when using key rotation you typically would store the public keys alongside the private keys in your database
	//and give both of them an expiration date, with the public key having a longer lifetime (e.g. rotate private key every
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{
			KeyID:     s.signingKey.ID,
			Algorithm: s.signingKey.Algorithm,
			Use:       oidc.KeyUseSignature,
			Key:       &s.signingKey.Key.PublicKey,
		}},
	}, nil
}

//GetClientByClientID implements the op.Storage interface
//it will be called whenever information (type, redirect_uris, ...) about the client behind the client_id is needed
func (s *storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	client, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found")
	}
	return client, nil
}

//AuthorizeClientIDSecret implements the op.Storage interface
//it will be called for validating the client_id, client_secret on token or introspection requests
func (s *storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	client, ok := s.clients[clientID]
	if !ok {
		return fmt.Errorf("client not found")
	}
	//for this example we directly check the secret
	//obviously you would not have the secret in plain text, but rather hashed and salted (e.g. using bcrypt)
	if client.secret != clientSecret {
		return fmt.Errorf("invalid secret")
	}
	return nil
}

//SetUserinfoFromScopes implements the op.Storage interface
//it will be called for the creation of an id_token, so we'll just pass it to the private function without any further check
func (s *storage) SetUserinfoFromScopes(ctx context.Context, userinfo oidc.UserInfoSetter, userID, clientID string, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, userID, clientID, scopes)
}

//SetUserinfoFromToken implements the op.Storage interface
//it will be called for the userinfo endpoint, so we read the token and pass the information from that to the private function
func (s *storage) SetUserinfoFromToken(ctx context.Context, userinfo oidc.UserInfoSetter, tokenID, subject, origin string) error {
	token, ok := s.tokens[tokenID]
	if !ok {
		return fmt.Errorf("token is invalid or has expired")
	}
	//the userinfo endpoint should support CORS. If it's not possible to specify a specific origin in the CORS handler,
	//and you have to specify a wildcard (*) origin, then you could also check here if the origin which called the userinfo endpoint here directly
	//note that the origin can be empty (if called by a web client)
	//
	//if origin != "" {
	//	client, ok := s.clients[token.ApplicationID]
	//	if !ok {
	//		return fmt.Errorf("client not found")
	//	}
	//	if err := checkAllowedOrigins(client.allowedOrigins, origin); err != nil {
	//		return err
	//	}
	//}
	return s.setUserinfo(ctx, userinfo, token.Subject, token.ApplicationID, token.Scopes)
}

//SetIntrospectionFromToken implements the op.Storage interface
//it will be called for the introspection endpoint, so we read the token and pass the information from that to the private function
func (s *storage) SetIntrospectionFromToken(ctx context.Context, introspection oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	token, ok := s.tokens[tokenID]
	if !ok {
		return fmt.Errorf("token is invalid or has expired")
	}
	//check if the client is part of the requested audience
	for _, aud := range token.Audience {
		if aud == clientID {
			//the introspection response only has to return a boolean (active) if the token is active
			//this will automatically be done by the library if you don't return an error
			//you can also return further information about the user / associated token
			//e.g. the userinfo (equivalent to userinfo endpoint)
			err := s.setUserinfo(ctx, introspection, subject, clientID, token.Scopes)
			if err != nil {
				return err
			}
			//...and also the requested scopes...
			introspection.SetScopes(token.Scopes)
			//...and the client the token was issued to
			introspection.SetClientID(token.ApplicationID)
			return nil
		}
	}
	return fmt.Errorf("token is not valid for this client")
}

//GetPrivateClaimsFromScopes implements the op.Storage interface
//it will be called for the creation of a JWT access token to assert claims for custom scopes
func (s *storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (claims map[string]interface{}, err error) {
	for _, scope := range scopes {
		switch scope {
		case CustomScope:
			claims = appendClaim(claims, CustomClaim, customClaim(clientID))
		}
	}
	return claims, nil
}

//GetKeyByIDAndUserID implements the op.Storage interface
//it will be called to validate the signatures of a JWT (JWT Profile Grant and Authentication)
func (s *storage) GetKeyByIDAndUserID(ctx context.Context, keyID, userID string) (*jose.JSONWebKey, error) {
	service, ok := s.services[userID]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	key, ok := service.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	return &jose.JSONWebKey{
		KeyID: keyID,
		Use:   "sig",
		Key:   key,
	}, nil
}

//ValidateJWTProfileScopes implements the op.Storage interface
//it will be called to validate the scopes of a JWT Profile Authorization Grant request
func (s *storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	allowedScopes := make([]string, 0)
	for _, scope := range scopes {
		if scope == oidc.ScopeOpenID {
			allowedScopes = append(allowedScopes, scope)
		}
	}
	return allowedScopes, nil
}

//Health implements the op.Storage interface
func (s *storage) Health(ctx context.Context) error {
	return nil
}

//createRefreshToken will store a refresh_token in-memory based on the provided information
func (s *storage) createRefreshToken(accessToken *Token, amr []string, authTime time.Time) (string, error) {
	token := &RefreshToken{
		ID:            accessToken.RefreshTokenID,
		Token:         accessToken.RefreshTokenID,
		AuthTime:      authTime,
		AMR:           amr,
		ApplicationID: accessToken.ApplicationID,
		UserID:        accessToken.Subject,
		Audience:      accessToken.Audience,
		Expiration:    time.Now().Add(5 * time.Hour),
		Scopes:        accessToken.Scopes,
	}
	s.refreshTokens[token.ID] = token
	return token.Token, nil
}

//renewRefreshToken checks the provided refresh_token and creates a new one based on the current
func (s *storage) renewRefreshToken(currentRefreshToken string) (string, string, error) {
	refreshToken, ok := s.refreshTokens[currentRefreshToken]
	if !ok {
		return "", "", fmt.Errorf("invalid refresh token")
	}
	//deletes the refresh token and all access tokens which were issued based on this refresh token
	delete(s.refreshTokens, currentRefreshToken)
	for _, token := range s.tokens {
		if token.RefreshTokenID == currentRefreshToken {
			delete(s.tokens, token.ID)
			break
		}
	}
	//creates a new refresh token based on the current one
	token := uuid.NewString()
	refreshToken.Token = token
	s.refreshTokens[token] = refreshToken
	return token, refreshToken.ID, nil
}

//createRefreshToken will store an access_token in-memory based on the provided information
func (s *storage) accessToken(applicationID, refreshTokenID, subject string, audience, scopes []string) (*Token, error) {
	token := &Token{
		ID:             uuid.NewString(),
		ApplicationID:  applicationID,
		RefreshTokenID: refreshTokenID,
		Subject:        subject,
		Audience:       audience,
		Expiration:     time.Now().Add(5 * time.Minute),
		Scopes:         scopes,
	}
	s.tokens[token.ID] = token
	return token, nil
}

//setUserinfo sets the info based on the user, scopes and if necessary the clientID
func (s *storage) setUserinfo(ctx context.Context, userInfo oidc.UserInfoSetter, userID, clientID string, scopes []string) (err error) {
	user, ok := s.users[userID]
	if !ok {
		return fmt.Errorf("user not found")
	}
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			userInfo.SetSubject(user.id)
		case oidc.ScopeEmail:
			userInfo.SetEmail(user.email, user.emailVerified)
		case oidc.ScopeProfile:
			userInfo.SetPreferredUsername(user.username)
			userInfo.SetName(user.firstname + " " + user.lastname)
			userInfo.SetFamilyName(user.lastname)
			userInfo.SetGivenName(user.firstname)
			userInfo.SetLocale(user.preferredLanguage)
		case oidc.ScopePhone:
			userInfo.SetPhone(user.phone, user.phoneVerified)
		case CustomScope:
			//you can also have a custom scope and assert public or custom claims based on that
			userInfo.AppendClaims(CustomClaim, customClaim(clientID))
		}
	}
	return nil
}

//getInfoFromRequest returns the clientID, authTime and amr depending on the op.TokenRequest type / implementation
func getInfoFromRequest(req op.TokenRequest) (clientID string, authTime time.Time, amr []string) {
	authReq, ok := req.(*AuthRequest) //Code Flow (with scope offline_access)
	if ok {
		return authReq.ApplicationID, authReq.authTime, authReq.GetAMR()
	}
	refreshReq, ok := req.(*RefreshTokenRequest) //Refresh Token Request
	if ok {
		return refreshReq.ApplicationID, refreshReq.AuthTime, refreshReq.AMR
	}
	return "", time.Time{}, nil
}

//customClaim demonstrates how to return custom claims based on provided information
func customClaim(clientID string) map[string]interface{} {
	return map[string]interface{}{
		"client": clientID,
		"other":  "stuff",
	}
}

func appendClaim(claims map[string]interface{}, claim string, value interface{}) map[string]interface{} {
	if claims == nil {
		claims = make(map[string]interface{})
	}
	claims[claim] = value
	return claims
}
