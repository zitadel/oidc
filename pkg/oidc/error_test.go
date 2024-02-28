package oidc

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultToServerError(t *testing.T) {
	type args struct {
		err         error
		description string
	}
	tests := []struct {
		name string
		args args
		want *Error
	}{
		{
			name: "default",
			args: args{
				err:         io.ErrClosedPipe,
				description: "oops",
			},
			want: &Error{
				ErrorType:   ServerError,
				Description: "oops",
				Parent:      io.ErrClosedPipe,
			},
		},
		{
			name: "our Error",
			args: args{
				err:         ErrAccessDenied(),
				description: "oops",
			},
			want: &Error{
				ErrorType:   AccessDenied,
				Description: "The authorization request was denied.",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DefaultToServerError(tt.args.err, tt.args.description)
			assert.ErrorIs(t, got, tt.want)
		})
	}
}

func TestError_LogLevel(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		want slog.Level
	}{
		{
			name: "server error",
			err:  ErrServerError(),
			want: slog.LevelError,
		},
		{
			name: "authorization pending",
			err:  ErrAuthorizationPending(),
			want: slog.LevelInfo,
		},
		{
			name: "some other error",
			err:  ErrAccessDenied(),
			want: slog.LevelWarn,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.LogLevel()
			assert.Equal(t, tt.want, got)
		})
	}
}

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
