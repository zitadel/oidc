package op

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetIssuerHost(t *testing.T) {
	type args struct {
		issuer string
	}
	type res struct {
		path string
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			name: "just domain, without trailing forward slash",
			args: args{
				issuer: "https://localhost",
			},
			res: res{
				path: "https://localhost",
			},
		},
		{
			name: "just domain, with trailing forward slash",
			args: args{
				issuer: "https://localhost/",
			},
			res: res{
				path: "https://localhost",
			},
		},
		{
			name: "domain with path 1",
			args: args{
				issuer: "https://localhost/custompath",
			},
			res: res{
				path: "https://localhost",
			},
		},
		{
			name: "domain with path 2",
			args: args{
				issuer: "https://localhost/custom/path",
			},
			res: res{
				path: "https://localhost",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath := getIssuerHost(tt.args.issuer)
			assert.Equal(t, tt.res.path, gotPath)
		})
	}
}

func TestGetIssuerPath(t *testing.T) {
	type args struct {
		issuer string
	}
	type res struct {
		path string
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			name: "just domain, without trailing forward slash",
			args: args{
				issuer: "https://localhost",
			},
			res: res{
				path: "",
			},
		},
		{
			name: "just domain, with trailing forward slash",
			args: args{
				issuer: "https://localhost/",
			},
			res: res{
				path: "",
			},
		},
		{
			name: "domain with path 1",
			args: args{
				issuer: "https://localhost/custompath",
			},
			res: res{
				path: "custompath",
			},
		},
		{
			name: "domain with path 2",
			args: args{
				issuer: "https://localhost/custom/path",
			},
			res: res{
				path: "custom/path",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath := getIssuerPath(tt.args.issuer)
			assert.Equal(t, tt.res.path, gotPath)
		})
	}
}
