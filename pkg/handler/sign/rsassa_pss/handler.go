package rsassa_pss

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http"

	"github.com/open-component-model/signing-server/pkg/encoding"
	"github.com/open-component-model/signing-server/pkg/handler/sign"
	signhttp "github.com/open-component-model/signing-server/pkg/http"
)

const (
	// Algorithm defines the type for the RSA PSS signature algorithm.
	Algorithm = "RSASSA-PSS"
)

func New(privateKey *rsa.PrivateKey) sign.SignHandler {
	return &Handler{privateKey}
}

type Handler struct {
	privateKey *rsa.PrivateKey
}

func (h *Handler) Name() string {
	return Algorithm
}

func (h *Handler) Sign(hashfunc crypto.Hash, data []byte) ([]byte, error) {
	return rsa.SignPSS(rand.Reader, h.privateKey, hashfunc, data, nil)
}

func (h *Handler) HTTPHandler(responseBuilders map[string]encoding.ResponseBuilder, maxContentLength int) http.Handler {
	return signhttp.CreateDefaultSignHandler(h, responseBuilders, maxContentLength)
}
