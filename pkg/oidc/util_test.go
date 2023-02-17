package oidc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type jsonErrorTest struct{}

func (jsonErrorTest) MarshalJSON() ([]byte, error) {
	return nil, errors.New("test")
}

func Test_mergeAndMarshalClaims(t *testing.T) {
	type args struct {
		registered any
		claims     map[string]any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "encoder error",
			args: args{
				registered: jsonErrorTest{},
			},
			wantErr: true,
		},
		{
			name: "no claims",
			args: args{
				registered: struct {
					Foo string `json:"foo,omitempty"`
				}{
					Foo: "bar",
				},
			},
			want: "{\"foo\":\"bar\"}\n",
		},
		{
			name: "with claims",
			args: args{
				registered: struct {
					Foo string `json:"foo,omitempty"`
				}{
					Foo: "bar",
				},
				claims: map[string]any{
					"bar": "foo",
				},
			},
			want: "{\"bar\":\"foo\",\"foo\":\"bar\"}\n",
		},
		{
			name: "registered overwrites custom",
			args: args{
				registered: struct {
					Foo string `json:"foo,omitempty"`
				}{
					Foo: "bar",
				},
				claims: map[string]any{
					"foo": "Hello, World!",
				},
			},
			want: "{\"foo\":\"bar\"}\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mergeAndMarshalClaims(tt.args.registered, tt.args.claims)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func Test_unmarshalJSONMulti(t *testing.T) {
	type dst struct {
		Foo string `json:"foo,omitempty"`
	}

	type args struct {
		data         string
		destinations []any
	}
	tests := []struct {
		name    string
		args    args
		want    []any
		wantErr bool
	}{
		{
			name: "error",
			args: args{
				data: "~!~~",
				destinations: []any{
					&dst{},
					&map[string]any{},
				},
			},
			want: []any{
				&dst{},
				&map[string]any{},
			},
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				data: "{\"bar\":\"foo\",\"foo\":\"bar\"}\n",
				destinations: []any{
					&dst{},
					&map[string]any{},
				},
			},
			want: []any{
				&dst{Foo: "bar"},
				&map[string]any{
					"foo": "bar",
					"bar": "foo",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := unmarshalJSONMulti([]byte(tt.args.data), tt.args.destinations...)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, tt.args.destinations)
		})
	}
}
