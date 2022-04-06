package internal

import (
	"crypto/rsa"

	"golang.org/x/text/language"
)

type User struct {
	id                string
	username          string
	password          string
	firstname         string
	lastname          string
	email             string
	emailVerified     bool
	phone             string
	phoneVerified     bool
	preferredLanguage language.Tag
}

type Service struct {
	keys map[string]*rsa.PublicKey
}
