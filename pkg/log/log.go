package log

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/google/uuid"
)

type LoggerContextKey struct{}

const (
	LogKeyUri              = "uri"
	LogKeyRemoteAddr       = "remote-addr"
	LogKeyMethod           = "method"
	LogKeyRequestId        = "request-id"
	LogKeyResponseCode     = "response-code"
	LogKeyDuration         = "duration"
	LogKeyResponseBodySize = "response-body-size"
)

type LoggingMiddleware struct {
	Logger *zap.Logger
}

func (l *LoggingMiddleware) PrepareLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		requestId := uuid.New()
		logger := l.Logger.With(zap.String(LogKeyRequestId, requestId.String()))
		ctx = context.WithValue(ctx, LoggerContextKey{}, logger)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (l *LoggingMiddleware) LogRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := GetLoggerFromContext(r.Context())

		logger.With(zap.String(LogKeyMethod, r.Method), zap.String(LogKeyUri, r.RequestURI), zap.String(LogKeyRemoteAddr, r.RemoteAddr)).Info("incoming request")

		rw := LogResponseWriter{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(&rw, r)
		end := time.Now()

		logger.With(zap.Int(LogKeyResponseCode, rw.statusCode), zap.Duration(LogKeyDuration, end.Sub(start)), zap.Int(LogKeyResponseBodySize, rw.size)).Info("finished request")
	})
}

func GetLoggerFromContext(ctx context.Context) *zap.Logger {
	logger := ctx.Value(LoggerContextKey{})
	return logger.(*zap.Logger)
}

type LogResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func NewLogResponseWriter(w http.ResponseWriter) *LogResponseWriter {
	return &LogResponseWriter{ResponseWriter: w}
}

func (w *LogResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *LogResponseWriter) Write(body []byte) (int, error) {
	w.size = len(body)
	return w.ResponseWriter.Write(body)
}
