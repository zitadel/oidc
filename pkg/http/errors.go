package http

import "errors"

var (
	ErrResponseBodyTooLarge = errors.New("http response too large")
	ErrInvalidContentType   = errors.New("invalid response content type")
)
