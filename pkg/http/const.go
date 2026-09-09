package http

// MaxResponseBodySize limits the number of bytes read from HTTP response bodies.
// It defaults to 1 MiB.
var MaxResponseBodySize int64 = 1 << 20
