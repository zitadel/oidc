package rp

import (
	"testing"

	"github.com/caos/oidc/pkg/oidc"
)

func TestGenerateJWTProfileToken(t *testing.T) {
	type args struct {
		assertion *oidc.JWTProfileAssertion
	}
	type res struct {
		wantErr bool
		// token   string
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			name: "valid",
			args: args{
				assertion: oidc.NewJWTProfileAssertion("service-account-id", "key-id", []string{"http://localhost:50002/oauth/v2/"}, []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsqxKigKty6jBIuDtO9AIGdTNo0VMe/QoYlHPxDQtgKhdXjD7
GNVLlr4qy+28Slo/Nph5/UFIc6BhXUGCK0JSRDoXukB36UnZblT/xyjz9NLzAEsk
HKCBhkJL7uuSRDvj9L367/02QhSzYh00vi6sG+d4cUuD3n4oZwf0IifZy4OJBX2R
SX2sV8Lh3eR39UrnA2qiwRPQmToVPu1x18BphvE9kZtVzTvy/d0VXtEcNJDvYNuH
kYM3DLzzR0+DCDS8bo7IaX8i1TQoO8y5rXlZ5C7+FdAa15lt5N+A0Lfz7hu45s+r
OCcp2s6IvsRZKV4HWhEhnQuoRdXQmpnQGlFnFQIDAQABAoIBABY41YB6utDkqTjE
Tt0sj4Ve8UCIQu37vPYVhMi7UJl61zn6z5AUHzWda0c3xz5cIRaSOkHkV7WB0fo+
RolI02CG9SKGGCPcun09dx53GnhtsCluLwycbd+b6UPK6sMvy7dJ1ab5kEEBwBnI
1iF9Poyt6k30/W6ztCS0WYnR+QWVnhtMPBRtzeSAb8OdKRQsNRKWgN+BK7VzCFls
jr4tvwdq/5WWLmYYqeteVK8nt9muJGUdmqS8UBf0D1Qo2/Ob+UKIE3ff/VlaEW+g
YhVkKspUYkuOWERk4awEkExZ0zoTkEKv4BgL53a41KO3UV8GIkSW8W8SfIL1aIEt
aPvm6XUCgYEA57HtG2GWJIozBbBlxT1UC2I0hFW37+JETx7ingcsjNxobQZftWZc
36PwZ4kmLxLJIinuFdEK7ghfm4123PUaKxH4gNXMzO7rzF2pskD902uaDijpkd1c
asXSIzy7MnG2ipEmxbqD3wPa7Lm9RCwl1ldCfOkZpkilsgBEAkWGtosCgYEAxWp7
F4GlcI1S6/lUdxDeem5QTEYLuE45prQhT0jiFzxDT3kuX4mK/4A7wryPif+UCksf
U5cbo65l+IYc3JUx2DtZARHALdg7BHiaYqsx3qWVM0OokwEstbSrLT6+jSolegSf
+9LghTS5ZowkighyiW5OsJMIehuHowdSH9NZrN8CgYA6XHsZNo+XTKhlenVoJXaS
F36bBux6JEiIlYMHw07ZfHthWwWor8wdGTJpIgbYPKclT+KE5E8Yfkt25z9VkPey
eaha63/W7ye+JqmkGPLW2nfHsU6ES3oH+yRfc+DDaBlO9hkKHV0yQ8pVbsPZ9DTj
tL8ur5iiZhI2sBJxcAnq2QKBgQC4DnTBD8DdVQXQuF9Fu1aRszPuSQg4R8Z8ZEkC
EKOqoibne8X+kNAlMruE7iSttrmhdzS3zJSaYMj1kqRqDDeysHJlCtWwaH9txbu6
7n3KZXrbluMeW+QBbXaC8pLaLkdOoe0+7fciemu47kRK5WFUPKHlAtDOd8hX+UVa
IsTi5QKBgCCfYiuTdesjMKAc3UQ0zjVYAxS1HqJh7V5McqscFx3D3uxg1JJcojwc
QOsG4gLgcCbr3kBkQLDHC+ZTjKgJ7OTVUf6To5yz2WlrDL+0YN+TmA8fpQR/rL2y
VgGFLpjDn3JtxGFwhV2CCwrC/ZCSut2L8IGi5+KtwMUW8clN9skR
-----END RSA PRIVATE KEY-----
`)),
			},
			res: res{
				wantErr: false,
				// token:   "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS1pZCJ9.eyJpc3MiOiJzZXJ2aWNlLWFjY291bnQtaWQiLCJzdWIiOiJzZXJ2aWNlLWFjY291bnQtaWQiLCJhdWQiOlsiaHR0cDovL2xvY2FsaG9zdDo1MDAwMi9vYXV0aC92Mi8iXSwiZXhwIjoxNjAwMjYxNDQyLCJpYXQiOjE2MDAyNTc4NDIsInNjb3BlIjoib3BlbmlkIn0.c9w4al8NfWboMbp9U4j34SnMFei_RH7ajowE-B6GT0mTZRoSRR5lldti6aFObbyraYbpEbTmrH3LalSVTeQwkD0tRKMll3pNyHZ0OtsZQEVLKLtFZG5F3lmB5sbuRLkIRmh7lRad1o9NR2PVqCMJjbBqPRaUADhUaWnY5oTHt5xdt_T--VJfo871TG_Hcp8J-uAvyDqzccX6jrx4jG0t_q1ps1EUwkdzILb_ezv3PTb3YF9sj1lNuDs4dOJGKjBJNdHvhO_ofNMfb6wewmXF5hzZgO72PC7h1Pr__xRcuemO4VIpC1lb24lyYbM1Yg3m5z_e0ByU4dI0ePh-FPBsWQ",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := generateJWTProfileToken(tt.args.assertion)
			if (err != nil) != tt.res.wantErr {
				t.Errorf("generateJWTProfileToken() error = %v, wantErr %v", err, tt.res.wantErr)
				return
			}
			// if !reflect.DeepEqual(got, tt.res.token) {
			// 	t.Errorf("generateJWTProfileToken() = %q, want %q", got, tt.res.token)
			// }
		})
	}
}
