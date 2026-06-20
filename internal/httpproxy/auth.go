package httpproxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

func (h *handler) isAuthorized(responseWriter http.ResponseWriter, request *http.Request) (authorized bool) {
	if (h.username == "" && h.password == "") || (request.Method != http.MethodConnect && !request.URL.IsAbs()) {
		return true
	}
	basicAuth := request.Header.Get("Proxy-Authorization")
	if basicAuth == "" {
		responseWriter.Header().Set("Proxy-Authenticate", `Basic realm="Access to Gluetun over HTTP"`)
		responseWriter.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}
	b64UsernamePassword := strings.TrimPrefix(basicAuth, "Basic ")
	b, err := base64.StdEncoding.DecodeString(b64UsernamePassword)
	if err != nil {
		h.logger.Info("Cannot decode Proxy-Authorization header value from " +
			request.RemoteAddr + ": " + err.Error())
		responseWriter.WriteHeader(http.StatusUnauthorized)
		return false
	}
	const maxSplitFields = 2
	usernamePassword := strings.SplitN(string(b), ":", maxSplitFields)
	if len(usernamePassword) == 0 {
		responseWriter.WriteHeader(http.StatusBadRequest)
		return false
	}
	username := usernamePassword[0]
	password := ""
	if len(usernamePassword) >= maxSplitFields {
		password = usernamePassword[1]
	}
	if h.username != username {
		h.logger.Info(fmt.Sprintf("Username (%q) mismatch from %s",
			username, request.RemoteAddr))
		responseWriter.WriteHeader(http.StatusUnauthorized)
		return false
	}
	if h.password != "" && h.password != password {
		h.logger.Info(fmt.Sprintf("Password (%q) mismatch from %s",
			password, request.RemoteAddr))
		responseWriter.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}
