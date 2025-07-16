//go:build no_otel

package otel

import (
	"context"
)

type FakeTracer struct{}
type FakeSpan struct{}

func Tracer(name string) FakeTracer {
	return FakeTracer{}
}

func (t FakeTracer) Start(ctx context.Context, _ string) (context.Context, FakeSpan) {
	return ctx, FakeSpan{}
}

func (s FakeSpan) End() {

}
