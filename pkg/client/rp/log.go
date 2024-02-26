package rp

import (
	"context"
	"log/slog"

	"github.com/zitadel/logging"
)

func logCtxWithRPData(ctx context.Context, rp RelyingParty, attrs ...any) context.Context {
	logger, ok := rp.Logger(ctx)
	if !ok {
		return ctx
	}
	logger = logger.With(slog.Group("rp", attrs...))
	return logging.ToContext(ctx, logger)
}
