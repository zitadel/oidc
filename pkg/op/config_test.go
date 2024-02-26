package op

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateIssuer(t *testing.T) {
	type args struct {
		issuer        string
		allowInsecure bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"missing issuer fails",
			args{
				issuer: "",
			},
			true,
		},
		{
			"invalid url for issuer fails",
			args{
				issuer: ":issuer",
			},
			true,
		},
		{
			"host for issuer missing fails",
			args{
				issuer: "https:///issuer",
			},
			true,
		},
		{
			"host with fragment fails",
			args{
				issuer: "https://issuer.com/#issuer",
			},
			true,
		},
		{
			"host with query fails",
			args{
				issuer: "https://issuer.com?issuer=me",
			},
			true,
		},
		{
			"host with http fails",
			args{
				issuer: "http://issuer.com",
			},
			true,
		},
		{
			"host with https ok",
			args{
				issuer: "https://issuer.com",
			},
			false,
		},
		{
			"custom scheme fails",
			args{
				issuer: "custom://localhost:9999",
			},
			true,
		},
		{
			"http with allowInsecure ok",
			args{
				issuer:        "http://localhost:9999",
				allowInsecure: true,
			},
			false,
		},
		{
			"https with allowInsecure ok",
			args{
				issuer:        "https://localhost:9999",
				allowInsecure: true,
			},
			false,
		},
		{
			"custom scheme with allowInsecure fails",
			args{
				issuer:        "custom://localhost:9999",
				allowInsecure: true,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateIssuer(tt.args.issuer, tt.args.allowInsecure); (err != nil) != tt.wantErr {
				t.Errorf("ValidateIssuer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIssuerPath(t *testing.T) {
	type args struct {
		issuerPath *url.URL
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"empty ok",
			args{func() *url.URL {
				u, _ := url.Parse("")
				return u
			}()},
			false,
		},
		{
			"custom ok",
			args{func() *url.URL {
				u, _ := url.Parse("/custom")
				return u
			}()},
			false,
		},
		{
			"fragment fails",
			args{func() *url.URL {
				u, _ := url.Parse("#fragment")
				return u
			}()},
			true,
		},
		{
			"query fails",
			args{func() *url.URL {
				u, _ := url.Parse("?query=value")
				return u
			}()},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateIssuerPath(tt.args.issuerPath); (err != nil) != tt.wantErr {
				t.Errorf("ValidateIssuerPath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIssuerFromHost(t *testing.T) {
	type args struct {
		path          string
		allowInsecure bool
		target        string
	}
	type res struct {
		issuer string
		err    error
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"invalid issuer path",
			args{
				path:          "/#fragment",
				allowInsecure: false,
			},
			res{
				issuer: "",
				err:    ErrInvalidIssuerPath,
			},
		},
		{
			"empty path secure",
			args{
				path:          "",
				allowInsecure: false,
				target:        "https://issuer.com",
			},
			res{
				issuer: "https://issuer.com",
				err:    nil,
			},
		},
		{
			"custom path secure",
			args{
				path:          "/custom/",
				allowInsecure: false,
				target:        "https://issuer.com",
			},
			res{
				issuer: "https://issuer.com/custom/",
				err:    nil,
			},
		},
		{
			"custom path no leading slash",
			args{
				path:          "custom/",
				allowInsecure: false,
				target:        "https://issuer.com",
			},
			res{
				issuer: "https://issuer.com/custom/",
				err:    nil,
			},
		},
		{
			"empty path unsecure",
			args{
				path:          "",
				allowInsecure: true,
				target:        "http://issuer.com",
			},
			res{
				issuer: "http://issuer.com",
				err:    nil,
			},
		},
		{
			"custom path insecure",
			args{
				path:          "/custom/",
				allowInsecure: true,
				target:        "http://issuer.com",
			},
			res{
				issuer: "http://issuer.com/custom/",
				err:    nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer, err := IssuerFromHost(tt.args.path)(tt.args.allowInsecure)
			if tt.res.err == nil {
				assert.NoError(t, err)
				req := httptest.NewRequest("", tt.args.target, nil)
				assert.Equal(t, tt.res.issuer, issuer(req))
			}
			if tt.res.err != nil {
				assert.ErrorIs(t, err, tt.res.err)
			}
		})
	}
}

func TestIssuerFromForwardedOrHost(t *testing.T) {
	type args struct {
		path   string
		opts   []IssuerFromOption
		target string
		header map[string][]string
	}
	type res struct {
		issuer string
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"header parse error",
			args{
				path:   "/custom/",
				target: "https://issuer.com",
				header: map[string][]string{"Forwarded": {"~~~~"}},
			},
			res{
				issuer: "https://issuer.com/custom/",
			},
		},
		{
			"no forwarded header",
			args{
				path:   "/custom/",
				target: "https://issuer.com",
			},
			res{
				issuer: "https://issuer.com/custom/",
			},
		},
		// by=<identifier>;for=<identifier>;host=<host>;proto=<http|https>
		{
			"forwarded header without host",
			args{
				path:   "/custom/",
				target: "https://issuer.com",
				header: map[string][]string{"Forwarded": {
					`by=identifier;for=identifier;proto=https`,
				}},
			},
			res{
				issuer: "https://issuer.com/custom/",
			},
		},
		{
			"forwarded header with host",
			args{
				path:   "/custom/",
				target: "https://issuer.com",
				header: map[string][]string{"Forwarded": {
					`by=identifier;for=identifier;host=first.com;proto=https`,
				}},
			},
			res{
				issuer: "https://first.com/custom/",
			},
		},
		{
			"forwarded header with multiple hosts",
			args{
				path:   "/custom/",
				target: "https://issuer.com",
				header: map[string][]string{"Forwarded": {
					`by=identifier;for=identifier;host=first.com;proto=https,host=second.com`,
				}},
			},
			res{
				issuer: "https://first.com/custom/",
			},
		},
		{
			"multiple forwarded headers hosts",
			args{
				path:   "/custom/",
				target: "https://issuer.com",
				header: map[string][]string{"Forwarded": {
					`by=identifier;for=identifier;host=first.com;proto=https,host=second.com`,
					`by=identifier;for=identifier;host=third.com;proto=https`,
				}},
			},
			res{
				issuer: "https://first.com/custom/",
			},
		},
		{
			"custom header first",
			args{
				path:   "/custom/",
				target: "https://issuer.com",
				header: map[string][]string{
					"Forwarded": {
						`by=identifier;for=identifier;host=first.com;proto=https,host=second.com`,
						`by=identifier;for=identifier;host=third.com;proto=https`,
					},
					"X-Custom-Forwarded": {
						`by=identifier;for=identifier;host=custom.com;proto=https,host=custom2.com`,
					},
				},
				opts: []IssuerFromOption{
					WithIssuerFromCustomHeaders("x-custom-forwarded"),
				},
			},
			res{
				issuer: "https://custom.com/custom/",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer, err := IssuerFromForwardedOrHost(tt.args.path, tt.args.opts...)(false)
			require.NoError(t, err)
			req := httptest.NewRequest("", tt.args.target, nil)
			for k, v := range tt.args.header {
				req.Header[http.CanonicalHeaderKey(k)] = v
			}
			assert.Equal(t, tt.res.issuer, issuer(req))
		})
	}
}

func TestStaticIssuer(t *testing.T) {
	type args struct {
		issuer        string
		allowInsecure bool
	}
	type res struct {
		issuer string
		err    error
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"invalid issuer",
			args{
				issuer:        "",
				allowInsecure: false,
			},
			res{
				issuer: "",
				err:    ErrInvalidIssuerNoIssuer,
			},
		},
		{
			"empty path secure",
			args{
				issuer:        "https://issuer.com",
				allowInsecure: false,
			},
			res{
				issuer: "https://issuer.com",
				err:    nil,
			},
		},
		{
			"custom path secure",
			args{
				issuer:        "https://issuer.com/custom/",
				allowInsecure: false,
			},
			res{
				issuer: "https://issuer.com/custom/",
				err:    nil,
			},
		},
		{
			"unsecure",
			args{
				issuer:        "http://issuer.com",
				allowInsecure: true,
			},
			res{
				issuer: "http://issuer.com",
				err:    nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer, err := StaticIssuer(tt.args.issuer)(tt.args.allowInsecure)
			if tt.res.err == nil {
				assert.NoError(t, err)
				assert.Equal(t, tt.res.issuer, issuer(nil))
			}
			if tt.res.err != nil {
				assert.ErrorIs(t, err, tt.res.err)
			}
		})
	}
}
