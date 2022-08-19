package storage

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

type UserStore interface {
	GetUserByID(string) *User
	GetUserByUsername(string) *User
}

type userStore struct {
	users map[string]*User
}

func NewUserStore() UserStore {
	return userStore{
		users: map[string]*User{
			"id1": {
				id:                "id1",
				username:          "test-user",
				password:          "verysecure",
				firstname:         "Test",
				lastname:          "User",
				email:             "test-user@zitadel.ch",
				emailVerified:     true,
				phone:             "",
				phoneVerified:     false,
				preferredLanguage: language.German,
			},
		},
	}
}

func (u userStore) GetUserByID(id string) *User {
	return u.users[id]
}

func (u userStore) GetUserByUsername(username string) *User {
	for _, user := range u.users {
		if user.username == username {
			return user
		}
	}
	return nil
}
