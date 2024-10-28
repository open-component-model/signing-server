package rsassa_pkcs1_1_5

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
	// Algorithm defines the type for the RSA PKCS #1 v1.5 signature algorithm
	Algorithm = "RSASSA-PKCS1-V1_5"
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
	return rsa.SignPKCS1v15(rand.Reader, h.privateKey, hashfunc, data)
}

func (h *Handler) HTTPHandler(responseBuilders map[string]encoding.ResponseBuilder, maxContentLength int) http.Handler {
	return signhttp.CreateDefaultSignHandler(h, responseBuilders, maxContentLength)
}
