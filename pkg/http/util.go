package http

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"go.uber.org/zap"
)

// HandleHTTPError is a utility function which logs an error and then returns it back to the client
func HandleHTTPError(msg string, wrappedErr error, httpStatus int, logger *zap.Logger, w http.ResponseWriter) {
	logger.Error(msg, zap.Error(wrappedErr))
	if wrappedErr != nil {
		msg = fmt.Sprintf("%s: %s", msg, wrappedErr.Error())
	}
	http.Error(w, msg, httpStatus)
}

func CheckContentLengthHeader(r *http.Request, maxContentLength int) (int, error) {
	contentLengthStr := r.Header.Get(ContentLengthHeader)
	if contentLengthStr == "" {
		return 0, errors.New("header is not set")
	}

	contentLength, err := strconv.Atoi(contentLengthStr)
	if err != nil {
		return 0, fmt.Errorf("unable to parse: %w", err)
	}

	if contentLength > maxContentLength {
		return 0, fmt.Errorf("content length of %d exceeds maximum content length of %d", contentLength, maxContentLength)
	}

	return contentLength, nil
}

func ReadUserIP(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	return IPAddress
}
