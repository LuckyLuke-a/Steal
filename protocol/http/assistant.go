package http

import (
	"strings"
)


func (h *HttpHandler) isConnectMethod() bool {
	return strings.EqualFold(h.httpMethod, "CONNECT")
}






