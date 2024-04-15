package oidc

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"reflect"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestFindKey(t *testing.T) {
	type args struct {
		keyID       string
		use         string
		expectedAlg string
		keys        []jose.JSONWebKey
	}
	type res struct {
		key jose.JSONWebKey
		err error
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"no keys, ErrKeyNone",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys:        nil,
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyNone,
			},
		},
		{
			"single key enc, ErrKeyNone",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "enc",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyNone,
			},
		},
		{
			"single key wrong algorithm, ErrKeyNone",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PrivateKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyNone,
			},
		},
		{
			"single key no kid, no jwt kid, match",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use: "sig",
					Key: &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"single key kid, jwt no kid, match",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use:   "sig",
						KeyID: "id",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use:   "sig",
					KeyID: "id",
					Key:   &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"single key no kid, jwt with kid, match",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use: "sig",
					Key: &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"single key no use, jwt with kid, match",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						KeyID: "id",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					KeyID: "id",
					Key:   &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"single key wrong kid, ErrKeyNone",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use:   "sig",
						KeyID: "id2",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyNone,
			},
		},
		{
			"multiple keys no kid, jwt no kid, ErrKeyMultiple",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys with kid, jwt no kid, ErrKeyMultiple",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use:   "sig",
						KeyID: "id1",
						Key:   &rsa.PublicKey{},
					},
					{
						Use:   "sig",
						KeyID: "id2",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys, single sig key, jwt no kid, match",
			args{
				keyID:       "",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
					{
						Use: "enc",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use: "sig",
					Key: &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"multiple keys no kid, jwt with kid, ErrKeyMultiple",
			args{
				keyID:       "id",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys with kid, jwt with kid, match",
			args{
				keyID:       "id1",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use:   "sig",
						KeyID: "id1",
						Key:   &rsa.PublicKey{},
					},
					{
						Use:   "sig",
						KeyID: "id2",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use:   "sig",
					KeyID: "id1",
					Key:   &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"multiple keys, single sig key, jwt with kid, match",
			args{
				keyID:       "id1",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						Use: "sig",
						Key: &rsa.PublicKey{},
					},
					{
						Use: "enc",
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Use: "sig",
					Key: &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"multiple keys, no use, jwt with kid, match",
			args{
				keyID:       "id1",
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						KeyID: "id1",
						Key:   &rsa.PublicKey{},
					},
					{
						KeyID: "id2",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					KeyID: "id1",
					Key:   &rsa.PublicKey{},
				},
				err: nil,
			},
		},
		{
			"multiple keys, no use, jwt without kid, ErrKeyMultiple",
			args{
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keys: []jose.JSONWebKey{
					{
						KeyID: "id1",
						Key:   &rsa.PublicKey{},
					},
					{
						KeyID: "id2",
						Key:   &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys, no use or id, jwt with kid, ErrKeyMultiple",
			args{
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keyID:       "id1",
				keys: []jose.JSONWebKey{
					{
						Key: &rsa.PublicKey{},
					},
					{
						Key: &rsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{},
				err: ErrKeyMultiple,
			},
		},
		{
			"multiple keys (only one matching alg), jwt with kid, match",
			args{
				use:         KeyUseSignature,
				expectedAlg: "RS256",
				keyID:       "id1",
				keys: []jose.JSONWebKey{
					{
						Key: &rsa.PublicKey{},
					},
					{
						Key: &ecdsa.PublicKey{},
					},
				},
			},
			res{
				key: jose.JSONWebKey{
					Key: &rsa.PublicKey{},
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindMatchingKey(tt.args.keyID, tt.args.use, tt.args.expectedAlg, tt.args.keys...)
			if (tt.res.err != nil && !errors.Is(err, tt.res.err)) || (tt.res.err == nil && err != nil) {
				t.Errorf("FindKey() error, got = %v, want = %v", err, tt.res.err)
			}
			if !reflect.DeepEqual(got, tt.res.key) {
				t.Errorf("FindKey() got = %v, want %v", got, tt.res.key)
			}
		})
	}
}
