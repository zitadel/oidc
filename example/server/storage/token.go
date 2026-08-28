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

	// Resource holds the resource indicators (RFC 8707) the token was requested for.
	Resource []string
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

	// Resource holds the resource indicators (RFC 8707) the refresh token was
	// granted for. A refresh token request may narrow them down again.
	Resource []string
}
