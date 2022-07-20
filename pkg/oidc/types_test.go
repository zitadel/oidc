package oidc

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
)

func TestAudience_UnmarshalText(t *testing.T) {
	type args struct {
		text []byte
	}
	type res struct {
		audience Audience
	}
	tests := []struct {
		name    string
		args    args
		res     res
		wantErr bool
	}{
		{
			"invalid value",
			args{
				[]byte(`{"aud": {"a": }}}`),
			},
			res{},
			true,
		},
		{
			"single audience",
			args{
				[]byte(`{"aud": "single audience"}`),
			},
			res{
				[]string{"single audience"},
			},
			false,
		},
		{
			"multiple audience",
			args{
				[]byte(`{"aud": ["multiple", "audience"]}`),
			},
			res{
				[]string{"multiple", "audience"},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := new(struct {
				Audience Audience `json:"aud"`
			})
			if err := json.Unmarshal(tt.args.text, &a); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.ElementsMatch(t, a.Audience, tt.res.audience)
		})
	}
}

func TestDisplay_UnmarshalText(t *testing.T) {
	type args struct {
		text []byte
	}
	type res struct {
		display Display
	}
	tests := []struct {
		name    string
		args    args
		res     res
		wantErr bool
	}{
		{
			"unknown value",
			args{
				[]byte("unknown"),
			},
			res{},
			false,
		},
		{
			"page",
			args{
				[]byte("page"),
			},
			res{DisplayPage},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Display
			if err := d.UnmarshalText(tt.args.text); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			if d != tt.res.display {
				t.Errorf("Display is not correct is = %v, want %v", d, tt.res.display)
			}
		})
	}
}

func TestLocales_UnmarshalText(t *testing.T) {
	type args struct {
		text []byte
	}
	type res struct {
		tags []language.Tag
	}
	tests := []struct {
		name    string
		args    args
		res     res
		wantErr bool
	}{
		{
			"unknown value",
			args{
				[]byte("unknown"),
			},
			res{},
			false,
		},
		{
			"undefined",
			args{
				[]byte("und"),
			},
			res{},
			false,
		},
		{
			"single language",
			args{
				[]byte("de"),
			},
			res{[]language.Tag{language.German}},
			false,
		},
		{
			"multiple languages",
			args{
				[]byte("de en"),
			},
			res{[]language.Tag{language.German, language.English}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var locales Locales
			if err := locales.UnmarshalText(tt.args.text); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.ElementsMatch(t, locales, tt.res.tags)
		})
	}
}

func TestScopes_UnmarshalText(t *testing.T) {
	type args struct {
		text []byte
	}
	type res struct {
		scopes []string
	}
	tests := []struct {
		name    string
		args    args
		res     res
		wantErr bool
	}{
		{
			"unknown value",
			args{
				[]byte("unknown"),
			},
			res{
				[]string{"unknown"},
			},
			false,
		},
		{
			"struct",
			args{
				[]byte(`{"unknown":"value"}`),
			},
			res{
				[]string{`{"unknown":"value"}`},
			},
			false,
		},
		{
			"openid",
			args{
				[]byte("openid"),
			},
			res{
				[]string{"openid"},
			},
			false,
		},
		{
			"multiple scopes",
			args{
				[]byte("openid email custom:scope"),
			},
			res{
				[]string{"openid", "email", "custom:scope"},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scopes SpaceDelimitedArray
			if err := scopes.UnmarshalText(tt.args.text); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.ElementsMatch(t, scopes, tt.res.scopes)
		})
	}
}

func TestScopes_MarshalText(t *testing.T) {
	type args struct {
		scopes SpaceDelimitedArray
	}
	type res struct {
		scopes []byte
	}
	tests := []struct {
		name    string
		args    args
		res     res
		wantErr bool
	}{
		{
			"unknown value",
			args{
				SpaceDelimitedArray{"unknown"},
			},
			res{
				[]byte("unknown"),
			},
			false,
		},
		{
			"struct",
			args{
				SpaceDelimitedArray{`{"unknown":"value"}`},
			},
			res{
				[]byte(`{"unknown":"value"}`),
			},
			false,
		},
		{
			"openid",
			args{
				SpaceDelimitedArray{"openid"},
			},
			res{
				[]byte("openid"),
			},
			false,
		},
		{
			"multiple scopes",
			args{
				SpaceDelimitedArray{"openid", "email", "custom:scope"},
			},
			res{
				[]byte("openid email custom:scope"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, err := tt.args.scopes.MarshalText()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(text, tt.res.scopes) {
				t.Errorf("MarshalText() is = %q, want %q", text, tt.res.scopes)
			}
		})
	}
}

func TestSpaceDelimitatedArray_ValuerNotNil(t *testing.T) {
	inputs := [][]string{
		{"two", "elements"},
		{"one"},
		{ /*zero*/ },
	}
	for _, input := range inputs {
		t.Run(strconv.Itoa(len(input))+strings.Join(input, "_"), func(t *testing.T) {
			sda := SpaceDelimitedArray(input)
			dbValue, err := sda.Value()
			if !assert.NoError(t, err, "Value") {
				return
			}
			var reversed SpaceDelimitedArray
			err = reversed.Scan(dbValue)
			if assert.NoError(t, err, "Scan string") {
				assert.Equal(t, sda, reversed, "scan string")
			}
			reversed = nil
			dbValueString, ok := dbValue.(string)
			if assert.True(t, ok, "dbValue is string") {
				err = reversed.Scan([]byte(dbValueString))
				if assert.NoError(t, err, "Scan bytes") {
					assert.Equal(t, sda, reversed, "scan bytes")
				}
			}
		})
	}
}

func TestSpaceDelimitatedArray_ValuerNil(t *testing.T) {
	var reversed SpaceDelimitedArray
	err := reversed.Scan(nil)
	if assert.NoError(t, err, "Scan nil") {
		assert.Equal(t, SpaceDelimitedArray(nil), reversed, "scan nil")
	}
}
