package defaults

import (
	"fmt"
	"time"
)

var (
	ErrIssuerInvalid = func(expected, actual string) *validationError {
		return ValidationError("Issuer does not match. Expected: %s, got: %s", expected, actual)
	}
	ErrAudienceMissingClientID = func(clientID string) *validationError {
		return ValidationError("Audience is not valid. Audience must contain client_id (%s)", clientID)
	}
	ErrAzpMissing = func() *validationError {
		return ValidationError("Authorized Party is not set. If Token is valid for multiple audiences, azp must not be empty")
	}
	ErrAzpInvalid = func(azp, clientID string) *validationError {
		return ValidationError("Authorized Party is not valid. azp (%s) must be equal to client_id (%s)", azp, clientID)
	}
	ErrExpInvalid = func(exp time.Time) *validationError {
		return ValidationError("Token has expired %v", exp)
	}
	ErrIatInFuture = func(exp, now time.Time) *validationError {
		return ValidationError("IssuedAt of token is in the future (%v, now with offset: %v)", exp, now)
	}
	ErrIatToOld = func(maxAge, iat time.Time) *validationError {
		return ValidationError("IssuedAt of token must not be older than %v, but was %v (%v to old)", maxAge, iat, maxAge.Sub(iat))
	}
	ErrNonceInvalid = func(expected, actual string) *validationError {
		return ValidationError("nonce does not match. Expected: %s, got: %s", expected, actual)
	}
	ErrAcrInvalid = func(expected []string, actual string) *validationError {
		return ValidationError("acr is invalid. Expected one of: %v, got: %s", expected, actual)
	}

	ErrAuthTimeNotPresent = func() *validationError {
		return ValidationError("claim `auth_time` of token is missing")
	}
	ErrAuthTimeToOld = func(maxAge, authTime time.Time) *validationError {
		return ValidationError("Auth Time of token must not be older than %v, but was %v (%v to old)", maxAge, authTime, maxAge.Sub(authTime))
	}
	ErrSignatureInvalidPayload = func() *validationError {
		return ValidationError("Signature does not match Payload")
	}
)

func ValidationError(message string, args ...interface{}) *validationError {
	return &validationError{fmt.Sprintf(message, args...)} //TODO: impl
}

type validationError struct {
	message string
}

func (v *validationError) Error() string {
	return v.message
}
