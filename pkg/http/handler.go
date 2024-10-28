package http

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"net/http"

	"go.uber.org/zap"

	"github.com/open-component-model/signing-server/pkg/encoding"
	"github.com/open-component-model/signing-server/pkg/handler/sign"
	"github.com/open-component-model/signing-server/pkg/log"
)

func CreateDefaultSignHandler(signer sign.SignHandler, responseBuilders map[string]encoding.ResponseBuilder, maxContentLength int) http.Handler {
	return &DefaultHandler{
		responseBuilders: responseBuilders,
		maxContentLength: maxContentLength,
		signer:           signer,
	}
}

type DefaultHandler struct {
	responseBuilders map[string]encoding.ResponseBuilder
	maxContentLength int
	signer           sign.SignHandler
}

func (h *DefaultHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := log.GetLoggerFromContext(r.Context())

	fields := []zap.Field{
		zap.String("handler", h.signer.Name()),
		zap.String("client", ReadUserIP(r)),
		zap.String("query", r.URL.RawQuery),
	}
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
		var commonName = r.TLS.VerifiedChains[0][0].Subject.CommonName

		logger.Info("request", append(fields, zap.String("commonName", commonName))...)
	} else {
		logger.Info("request", append(fields, zap.String("handler", h.signer.Name()))...)
	}

	accept := r.Header.Get(AcceptHeader)
	logger.Info("accept", zap.String("type", accept))
	responseBodyBuilder, ok := h.responseBuilders[accept]
	if !ok {
		keys := []string{}
		for k := range h.responseBuilders {
			keys = append(keys, k)
		}
		HandleHTTPError(
			fmt.Sprintf("unknown %s header %q. possible values: %q", AcceptHeader, accept, keys),
			nil,
			http.StatusBadRequest,
			logger,
			w,
		)
		return
	}

	hashAlgorithm := r.URL.Query().Get(HashAlgorithmQuery)
	hashfunc, ok := sign.GetHashFunction(hashAlgorithm)
	if !ok || hashfunc == crypto.Hash(0) {
		HandleHTTPError(
			fmt.Sprintf("unknown hash algorithm %q. possible values: %q", hashAlgorithm, sign.GetRegisteredHashFunctions()),
			nil,
			http.StatusBadRequest,
			logger,
			w,
		)
		return
	}

	data, err := ContentFromRequest(r, h.maxContentLength)
	if err != nil {
		HandleHTTPError("invalid request content", err, http.StatusBadRequest, logger, w)
		return
	}
	logger.Info("data", zap.String("hex", hex.EncodeToString(data)), zap.String("hash", hashfunc.String()))
	signature, err := h.signer.Sign(hashfunc, data)
	if err != nil {
		HandleHTTPError("unable to sign", err, http.StatusInternalServerError, logger, w)
		return
	}

	annotations := map[string]string{
		encoding.SignatureAlgorithmHeader: h.signer.Name(),
	}
	logger.Info("signature", zap.String("hex", hex.EncodeToString(signature)))
	respBody, err := responseBodyBuilder.BuildResponse(signature, annotations)
	if err != nil {
		HandleHTTPError("unable to build response body", err, http.StatusInternalServerError, logger, w)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(respBody); err != nil {
		logger.Error("unable to write response body", zap.Error(err))
		return
	}
}
