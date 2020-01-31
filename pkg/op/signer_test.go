package op

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

// func TestNewDefaultSigner(t *testing.T) {
// 	type args struct {
// 		storage Storage
// 	}
// 	tests := []struct {
// 		name    string
// 		args    args
// 		want    Signer
// 		wantErr bool
// 	}{
// 		{
// 			"err initialize storage fails",
// 			args{mock.NewMockStorageSigningKeyError(t)},
// 			nil,
// 			true,
// 		},
// 		{
// 			"err initialize storage fails",
// 			args{mock.NewMockStorageSigningKeyInvalid(t)},
// 			nil,
// 			true,
// 		},
// 		{
// 			"initialize ok",
// 			args{mock.NewMockStorageSigningKey(t)},
// 			&idTokenSigner{Storage: mock.NewMockStorageSigningKey(t)},
// 			false,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			got, err := op.NewDefaultSigner(tt.args.storage)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("NewDefaultSigner() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("NewDefaultSigner() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

func Test_idTokenSigner_Sign(t *testing.T) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("key")}, &jose.SignerOptions{})
	require.NoError(t, err)

	type fields struct {
		signer  jose.Signer
		storage Storage
	}
	type args struct {
		payload []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			"ok",
			fields{signer, nil},
			args{[]byte("test")},
			"eyJhbGciOiJIUzI1NiJ9.dGVzdA.SxYZRsvB_Dr4F7SEFuYXvkMZqCCwzpsPOQXl-vLPEww",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idTokenSigner{
				signer:  tt.fields.signer,
				storage: tt.fields.storage,
			}
			got, err := s.Sign(tt.args.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("idTokenSigner.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("idTokenSigner.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}
