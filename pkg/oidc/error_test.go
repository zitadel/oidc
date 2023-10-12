package oidc

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slog"
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
