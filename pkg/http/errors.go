package http

import "errors"

var ErrResponseBodyTooLarge = errors.New("http response too large")
