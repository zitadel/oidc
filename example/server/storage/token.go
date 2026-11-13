package storage

import "time"

type Token struct {
	ID             string
	ApplicationID  string
	Subject        string
	RefreshTokenID string
	Audience       []string
	Expiration     time.Time
	Scopes         []string
}

type RefreshToken struct {
	ID            string
	Token         string
	AuthTime      time.Time
	AMR           []string
	Audience      []string
	UserID        string
	ApplicationID string
	Expiration    time.Time
	Scopes        []string
	AccessToken   string // Token.ID

	// Resource holds the resource indicators (RFC 8707) of the original grant, which
	// the refresh token stays bound to. A refresh token request may narrow them down
	// for the access token it receives, without changing them here.
	Resource []string
}
