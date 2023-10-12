package rp

import (
	"context"

	"github.com/zitadel/logging"
	"golang.org/x/exp/slog"
)

func logCtxWithRPData(ctx context.Context, rp RelyingParty, attrs ...any) context.Context {
	logger, ok := rp.Logger(ctx)
	if !ok {
		return ctx
	}
	logger = logger.With(slog.Group("rp", attrs...))
	return logging.ToContext(ctx, logger)
}
