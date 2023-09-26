package http

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConcatenateJSON(t *testing.T) {
	type args struct {
		first  []byte
		second []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"invalid first part, error",
			args{
				[]byte(`invalid`),
				[]byte(`{"some": "thing"}`),
			},
			nil,
			true,
		},
		{
			"invalid second part, error",
			args{
				[]byte(`{"some": "thing"}`),
				[]byte(`invalid`),
			},
			nil,
			true,
		},
		{
			"both valid, merged",
			args{
				[]byte(`{"some": "thing"}`),
				[]byte(`{"another": "thing"}`),
			},

			[]byte(`{"some": "thing","another": "thing"}`),
			false,
		},
		{
			"first empty",
			args{
				[]byte(`{}`),
				[]byte(`{"some": "thing"}`),
			},

			[]byte(`{"some": "thing"}`),
			false,
		},
		{
			"second empty",
			args{
				[]byte(`{"some": "thing"}`),
				[]byte(`{}`),
			},

			[]byte(`{"some": "thing"}`),
			false,
		},
		{
			"both empty",
			args{
				[]byte(`{}`),
				[]byte(`{}`),
			},

			[]byte(`{}`),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConcatenateJSON(tt.args.first, tt.args.second)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConcatenateJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("ConcatenateJSON() got = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestMarshalJSONWithStatus(t *testing.T) {
	type args struct {
		i      any
		status int
	}
	type res struct {
		statusCode int
		body       string
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			"empty ok",
			args{
				nil,
				200,
			},
			res{
				200,
				"",
			},
		},
		{
			"string ok",
			args{
				"ok",
				200,
			},
			res{
				200,
				`"ok"
`,
			},
		},
		{
			"struct ok",
			args{
				struct {
					Test string `json:"test"`
				}{"ok"},
				200,
			},
			res{
				200,
				`{"test":"ok"}
`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			MarshalJSONWithStatus(w, tt.args.i, tt.args.status)
			assert.Equal(t, tt.res.statusCode, w.Result().StatusCode)
			assert.Equal(t, "application/json", w.Header().Get("content-type"))
			assert.Equal(t, tt.res.body, w.Body.String())
		})
	}
}
