// Package hsm_pkcs1_1_5 provides the HSM based signing method
// according to PKCS1.1.5.
package hsm_pkcs1_1_5

import (
	"crypto"
	"fmt"
	"net/http"

	"github.com/miekg/pkcs11"

	"github.com/open-component-model/signing-server/pkg/encoding"
	"github.com/open-component-model/signing-server/pkg/handler/sign"
	"github.com/open-component-model/signing-server/pkg/handler/sign/rsassa_pkcs1_1_5"
	signhttp "github.com/open-component-model/signing-server/pkg/http"
)

const (
	// Algorithm defines the type for the RSA PSS signature algorithm.
	Algorithm = rsassa_pkcs1_1_5.Algorithm
)

var mechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)

func New(opt *sign.HSMOptions) sign.SignHandler {
	return &Handler{options: opt}
}

type Handler struct {
	options *sign.HSMOptions
}

func (h *Handler) Name() string {
	return Algorithm
}

func (h *Handler) Sign(hashfunc crypto.Hash, data []byte) ([]byte, error) {
	if hashfunc.Size() != len(data) {
		return nil, fmt.Errorf("invalid hash size (found %d, but expected %d for %s", len(data), hashfunc.Size(), hashfunc.String())
	}
	return h.options.Session.SignPKCS1v15(h.options.Key, data, hashfunc)
}

func (h *Handler) HTTPHandler(responseBuilders map[string]encoding.ResponseBuilder, maxContentLength int) http.Handler {
	return signhttp.CreateDefaultSignHandler(h, responseBuilders, maxContentLength)
}
