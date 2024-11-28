package hsm_pss

import (
	"crypto"
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

func New(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, priv pkcs11.ObjectHandle) sign.SignHandler {
	return &Handler{ctx, session, priv}
}

type Handler struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	priv    pkcs11.ObjectHandle
}

func (h *Handler) Name() string {
	return Algorithm
}

func (h *Handler) Sign(hashfunc crypto.Hash, data []byte) ([]byte, error) {
	if hashfunc.Size() != len(data) {
		return nil, fmt.Errorf("invalid hash size (found %d, but expected %d for %s", len(data), hashfunc.Size(), hashfunc.String())
	}
	err := h.ctx.SignInit(h.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, nil)}, h.priv)
	if err != nil {
		return nil, err
	}
	return h.ctx.Sign(h.session, data)
}

func (h *Handler) HTTPHandler(responseBuilders map[string]encoding.ResponseBuilder, maxContentLength int) http.Handler {
	return signhttp.CreateDefaultSignHandler(h, responseBuilders, maxContentLength)
}
