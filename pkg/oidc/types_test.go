package oidc

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/schema"
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

func TestLocale_Tag(t *testing.T) {
	tests := []struct {
		name string
		l    *Locale
		want language.Tag
	}{
		{
			name: "nil",
			l:    nil,
			want: language.Und,
		},
		{
			name: "Und",
			l:    NewLocale(language.Und),
			want: language.Und,
		},
		{
			name: "language",
			l:    NewLocale(language.Afrikaans),
			want: language.Afrikaans,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.l.Tag())
		})
	}
}

func TestLocale_String(t *testing.T) {
	tests := []struct {
		name string
		l    *Locale
		want language.Tag
	}{
		{
			name: "nil",
			l:    nil,
			want: language.Und,
		},
		{
			name: "Und",
			l:    NewLocale(language.Und),
			want: language.Und,
		},
		{
			name: "language",
			l:    NewLocale(language.Afrikaans),
			want: language.Afrikaans,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want.String(), tt.l.String())
		})
	}
}

func TestLocale_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		l       *Locale
		want    string
		wantErr bool
	}{
		{
			name: "nil",
			l:    nil,
			want: "null",
		},
		{
			name: "und",
			l:    NewLocale(language.Und),
			want: "null",
		},
		{
			name: "language",
			l:    NewLocale(language.Afrikaans),
			want: `"af"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.l)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestLocale_UnmarshalJSON(t *testing.T) {
	type dst struct {
		Locale *Locale `json:"locale,omitempty"`
	}
	tests := []struct {
		name    string
		input   string
		want    dst
		wantErr bool
	}{
		{
			name:  "afrikaans, ok",
			input: `{"locale": "af"}`,
			want: dst{
				Locale: NewLocale(language.Afrikaans),
			},
		},
		{
			name:  "gb, ignored",
			input: `{"locale": "gb"}`,
			want: dst{
				Locale: &Locale{},
			},
		},
		{
			name:    "bad form, error",
			input:   `{"locale": "g!!!!!"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		var got dst
		err := json.Unmarshal([]byte(tt.input), &got)
		if tt.wantErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tt.want, got)
	}
}

func TestParseLocales(t *testing.T) {
	in := []string{language.Afrikaans.String(), language.Danish.String(), "foobar", language.Und.String()}
	want := Locales{language.Afrikaans, language.Danish}
	got := ParseLocales(in)
	assert.ElementsMatch(t, want, got)
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

func TestLocales_UnmarshalJSON(t *testing.T) {
	in := []string{language.Afrikaans.String(), language.Danish.String(), "foobar", language.Und.String()}
	spaceSepStr := strconv.Quote(strings.Join(in, " "))
	jsonArray, err := json.Marshal(in)
	require.NoError(t, err)

	out := Locales{language.Afrikaans, language.Danish}

	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    Locales
		wantErr bool
	}{
		{
			name: "invalid JSON",
			args: args{
				data: []byte("~~~"),
			},
			wantErr: true,
		},
		{
			name: "null",
			args: args{
				data: []byte("null"),
			},
			want: nil,
		},
		{
			name: "space seperated string",
			args: args{
				data: []byte(spaceSepStr),
			},
			want: out,
		},
		{
			name: "json string array",
			args: args{
				data: jsonArray,
			},
			want: out,
		},
		{
			name: "json invalid array",
			args: args{
				data: []byte(`[1,2,3]`),
			},
			wantErr: true,
		},
		{
			name: "invalid type (float64)",
			args: args{
				data: []byte("22"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Locales
			err := got.UnmarshalJSON([]byte(tt.args.data))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
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

func TestNewEncoder(t *testing.T) {
	type request struct {
		Scopes SpaceDelimitedArray `schema:"scope"`
	}
	a := request{
		Scopes: SpaceDelimitedArray{"foo", "bar"},
	}

	values := make(url.Values)
	NewEncoder().Encode(a, values)
	assert.Equal(t, url.Values{"scope": []string{"foo bar"}}, values)

	var b request
	schema.NewDecoder().Decode(&b, values)
	assert.Equal(t, a, b)
}

func TestTime_AsTime(t *testing.T) {
	tests := []struct {
		name string
		ts   Time
		want time.Time
	}{
		{
			name: "unset",
			ts:   0,
			want: time.Time{},
		},
		{
			name: "set",
			ts:   1,
			want: time.Unix(1, 0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ts.AsTime()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTime_FromTime(t *testing.T) {
	tests := []struct {
		name string
		tt   time.Time
		want Time
	}{
		{
			name: "zero",
			tt:   time.Time{},
			want: 0,
		},
		{
			name: "set",
			tt:   time.Unix(1, 0),
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromTime(tt.tt)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTime_UnmarshalJSON(t *testing.T) {
	type dst struct {
		UpdatedAt Time `json:"updated_at"`
	}
	tests := []struct {
		name    string
		json    string
		want    dst
		wantErr bool
	}{
		{
			name: "RFC3339", // https://github.com/zitadel/oidc/issues/292
			json: `{"updated_at": "2021-05-11T21:13:25.566Z"}`,
			want: dst{UpdatedAt: 1620767605},
		},
		{
			name: "int",
			json: `{"updated_at":1620767605}`,
			want: dst{UpdatedAt: 1620767605},
		},
		{
			name:    "time parse error",
			json:    `{"updated_at":"foo"}`,
			wantErr: true,
		},
		{
			name: "null",
			json: `{"updated_at":null}`,
		},
		{
			name:    "invalid type",
			json:    `{"updated_at":["foo","bar"]}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got dst
			err := json.Unmarshal([]byte(tt.json), &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
	t.Run("syntax error", func(t *testing.T) {
		var ts Time
		err := ts.UnmarshalJSON([]byte{'~'})
		assert.Error(t, err)
	})
}
