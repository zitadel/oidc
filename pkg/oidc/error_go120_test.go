//go:build go1.20

package oidc

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slog"
)

func TestError_LogValue(t *testing.T) {
	type fields struct {
		Parent           error
		ErrorType        errorType
		Description      string
		State            string
		redirectDisabled bool
	}
	tests := []struct {
		name   string
		fields fields
		want   slog.Value
	}{
		{
			name: "parent",
			fields: fields{
				Parent: io.EOF,
			},
			want: slog.GroupValue(slog.Any("parent", io.EOF)),
		},
		{
			name: "description",
			fields: fields{
				Description: "oops",
			},
			want: slog.GroupValue(slog.String("description", "oops")),
		},
		{
			name: "errorType",
			fields: fields{
				ErrorType: ExpiredToken,
			},
			want: slog.GroupValue(slog.String("type", string(ExpiredToken))),
		},
		{
			name: "state",
			fields: fields{
				State: "123",
			},
			want: slog.GroupValue(slog.String("state", "123")),
		},
		{
			name: "all fields",
			fields: fields{
				Parent:      io.EOF,
				Description: "oops",
				ErrorType:   ExpiredToken,
				State:       "123",
			},
			want: slog.GroupValue(
				slog.Any("parent", io.EOF),
				slog.String("description", "oops"),
				slog.String("type", string(ExpiredToken)),
				slog.String("state", "123"),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Error{
				Parent:           tt.fields.Parent,
				ErrorType:        tt.fields.ErrorType,
				Description:      tt.fields.Description,
				State:            tt.fields.State,
				redirectDisabled: tt.fields.redirectDisabled,
			}
			got := e.LogValue()
			assert.Equal(t, tt.want, got)
		})
	}
}
