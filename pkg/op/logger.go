package op

import (
	"context"
	"net/http"
	"time"

	"github.com/rs/xid"
	"golang.org/x/exp/slog"
)

func newLogger(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	return slog.New(&logHandler{
		handler: logger.Handler(),
	})
}

type LogKey int

const (
	RequestID LogKey = iota

	maxLogKey
)

type logHandler struct {
	handler slog.Handler
}

func (h *logHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

type logAttributes []slog.Attr

func (attrs *logAttributes) appendFromContext(ctx context.Context, ctxKey any, logKey string) {
	v := ctx.Value(RequestID)
	if v == nil {
		return
	}
	*attrs = append(*attrs, slog.Group("request", slog.Attr{
		Key:   "id",
		Value: slog.AnyValue(v),
	}))
}

func (h *logHandler) Handle(ctx context.Context, record slog.Record) error {
	attrs := make(logAttributes, 0, maxLogKey)
	attrs.appendFromContext(ctx, RequestID, "id")

	handler := h.handler.WithAttrs(attrs)

	return handler.Handle(ctx, record)
}

func (h *logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &logHandler{
		handler: h.handler.WithAttrs(attrs),
	}
}

func (h *logHandler) WithGroup(name string) slog.Handler {
	return &logHandler{
		handler: h.handler.WithGroup(name),
	}
}

func (o *Provider) LogMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			r = r.WithContext(context.WithValue(r.Context(), RequestID, xid.New()))
			lw := &loggedWriter{
				ResponseWriter: w,
			}
			next.ServeHTTP(lw, r)
			logger := o.logger.With(
				slog.Group("request", "method", r.Method, "url", r.URL),
				slog.Group("response", "duration", time.Since(start), "status", lw.statusCode, "written", lw.written),
			)
			if lw.err != nil {
				logger.ErrorContext(r.Context(), "response writer", "error", lw.err)
				return
			}
			logger.InfoContext(r.Context(), "done")
		})
	}
}

type loggedWriter struct {
	http.ResponseWriter

	statusCode int
	written    int
	err        error
}

func (w *loggedWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *loggedWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += n
	w.err = err
	return n, err
}
