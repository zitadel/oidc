package crypto_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"

	zcrypto "github.com/zitadel/oidc/v3/pkg/crypto"
)

func TestBytesToPrivateKey(t *testing.T) {
	type args struct {
		key []byte
	}
	type want struct {
		key       crypto.Signer
		algorithm jose.SignatureAlgorithm
		err       error
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "PEMDecodeError",
			args: args{
				key: []byte("The non-PEM sequence"),
			},
			want: want{
				err: zcrypto.ErrPEMDecode,
			},
		},
		{
			name: "PKCS#1 RSA",
			args: args{
				key: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----`),
			},
			want: want{
				key:       &rsa.PrivateKey{},
				algorithm: jose.RS256,
				err:       nil,
			},
		},
		{
			name: "PKCS#8 RSA",
			args: args{
				key: []byte(`-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCfaDB7pK/fmP/I
7IusSK8lTCBnPZghqIbVLt2QHYAMoEF1CaF4F4rxo2vl1Mt8gwsq4T3osQFZMvnL
YHb7KNyUoJgTjLxJQADv2u4Q3U38heAzK5Tp4ry4MCnuyJIqAPK1GiruwEq4zQrx
+WzVix8otO37SuW9tzklqlNGMiAYBL0TBKHvS5XMbjP1idBMB8erMz29w/TVQnEB
Kj0vCdZjrbVPKygptt5kcSrL5f4xCZwU+ufz7cp0GLwpRMJ+shG9YJJFBxb0itPF
sy51vAyEtdBC7jgAU96ZVeQ06nryDq1D2EpoVMElqNyL46Jo3lnKbGquGKzXzQYU
BN32/scDAgMBAAECggEBAJE/mo3PLgILo2YtQ8ekIxNVHmF0Gl7w9IrjvTdH6hmX
HI3MTLjkmtI7GmG9V/0IWvCjdInGX3grnrjWGRQZ04QKIQgPQLFuBGyJjEsJm7nx
MqztlS7YTyV1nX/aenSTkJO8WEpcJLnm+4YoxCaAMdAhrIdBY71OamALpv1bRysa
FaiCGcemT2yqZn0GqIS8O26Tz5zIqrTN2G1eSmgh7DG+7FoddMz35cute8R10xUG
hF5YU+6fcXiRQ/Kh7nlxelPGqdZFPMk7LpVHzkQKwdJ+N0P23lPDIfNsvpG1n0OP
3g5km7gHSrSU2yZ3eFl6DB9x1IFNS9BaQQuSxYJtKwECgYEA1C8jjzpXZDLvlYsV
2jlMzkrbsIrX2dzblVrNsPs2jRbjYU8mg2DUDO6lOhtxHfqZG6sO+gmWi/zvoy9l
yolGbXe1Jqx66p9fznIcecSwar8+ACa356Wk74Nt1PlBOfCMqaJnYLOLaFJa29Vy
u5ClZVzKd5AVXl7yFVd4XfLv/WECgYEAwFMMtFoasdF92c0d31rZ1uoPOtFz6xq6
uQggdm5zzkhnfwUAGqppS/u1CHcJ7T/74++jLbFTsaohGr4jEzWSGvJpomEUChy3
r25YofMclUhJ5pCEStsLtqiCR1Am6LlI8HMdBEP1QDgEC5q8bQW4+UHuew1E1zxz
osZOhe09WuMCgYEA0G9aFCnwjUqIFjQiDFP7gi8BLqTFs4uE3Wvs4W11whV42i+B
ms90nxuTjchFT3jMDOT1+mOO0wdudLRr3xEI8SIF/u6ydGaJG+j21huEXehtxIJE
aDdNFcfbDbqo+3y1ATK7MMBPMvSrsoY0hdJq127WqasNgr3sO1DIuima3SECgYEA
nkM5TyhekzlbIOHD1UsDu/D7+2DkzPE/+oePfyXBMl0unb3VqhvVbmuBO6gJiSx/
8b//PdiQkMD5YPJaFrKcuoQFHVRZk0CyfzCEyzAts0K7XXpLAvZiGztriZeRjSz7
srJnjF0H8oKmAY6hw+1Tm/n/b08p+RyL48TgVSE2vhUCgYA3BWpkD4PlCcn/FZsq
OrLFyFXI6jIaxskFtsRW1IxxIlAdZmxfB26P/2gx6VjLdxJI/RRPkJyEN2dP7CbR
BDjb565dy1O9D6+UrY70Iuwjz+OcALRBBGTaiF2pLn6IhSzNI2sy/tXX8q8dBlg9
OFCrqT/emes3KytTPfa5NZtYeQ==
-----END PRIVATE KEY-----`),
			},
			want: want{
				key:       &rsa.PrivateKey{},
				algorithm: jose.RS256,
				err:       nil,
			},
		},
		{
			name: "PKCS#8 ECDSA",
			args: args{
				key: []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwwOZSU4GlP7ps/Wp
V6o0qRwxultdfYo/uUuj48QZjSuhRANCAATMiI2Han+ABKmrk5CNlxRAGC61w4d3
G4TAeuBpyzqJ7x/6NjCxoQzJzZHtNjIfjVATI59XFZWF59GhtSZbShAr
-----END PRIVATE KEY-----`),
			},
			want: want{
				key:       &ecdsa.PrivateKey{},
				algorithm: jose.ES256,
				err:       nil,
			},
		},
		{
			name: "PKCS#8 ED25519",
			args: args{
				key: []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHu6ZtDsjjauMasBxnS9Fg87UJwKfcT/oiq6S0ktbky8
-----END PRIVATE KEY-----`),
			},
			want: want{
				key:       ed25519.PrivateKey{},
				algorithm: jose.EdDSA,
				err:       nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, algorithm, err := zcrypto.BytesToPrivateKey(tt.args.key)
			assert.IsType(t, tt.want.key, key)
			assert.Equal(t, tt.want.algorithm, algorithm)
			assert.ErrorIs(t, tt.want.err, err)
		})

	}
}
