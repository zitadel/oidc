//go:build !no_otel

package otel

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}
