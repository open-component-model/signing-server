// Package hsm_pss provides the HSM based signing method
// according PSS signing.
package hsm_pss

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/miekg/pkcs11"

	"github.com/open-component-model/signing-server/pkg/encoding"
	"github.com/open-component-model/signing-server/pkg/handler/sign"
	"github.com/open-component-model/signing-server/pkg/handler/sign/rsassa_pss"
	signhttp "github.com/open-component-model/signing-server/pkg/http"
)

const (
	// Algorithm defines the type for the RSA PSS signature algorithm.
	Algorithm = rsassa_pss.Algorithm
)

var mechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, nil)

func New(opt sign.HSMOptions) sign.SignHandler {
	return &Handler{opt}
}

type Handler struct {
	options sign.HSMOptions
}

func (h *Handler) Name() string {
	return Algorithm
}

func (h *Handler) Sign(hashfunc crypto.Hash, data []byte) ([]byte, error) {
	if hashfunc.Size() != len(data) {
		return nil, fmt.Errorf("invalid hash size (found %d, but expected %d for %s", len(data), hashfunc.Size(), hashfunc.String())
	}
	// SALT lengths larger than the digest size (suto mode) do not work together with cloud hsm.
	return h.options.Session.SignPSS(h.options.Key, data, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hashfunc})
}

func (h *Handler) HTTPHandler(responseBuilders map[string]encoding.ResponseBuilder, maxContentLength int) http.Handler {
	return signhttp.CreateDefaultSignHandler(h, responseBuilders, maxContentLength)
}
