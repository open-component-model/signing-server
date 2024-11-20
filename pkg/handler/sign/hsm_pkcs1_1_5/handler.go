package hsm_pkcs1_1_5

import (
	"crypto"
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
	err := h.ctx.SignInit(h.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, h.priv)
	if err != nil {
		panic(err)
	}
	return h.ctx.Sign(h.session, data)
}

func (h *Handler) HTTPHandler(responseBuilders map[string]encoding.ResponseBuilder, maxContentLength int) http.Handler {
	return signhttp.CreateDefaultSignHandler(h, responseBuilders, maxContentLength)
}
