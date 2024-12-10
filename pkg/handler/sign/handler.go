package sign

import (
	"crypto"
	"fmt"
	"net/http"
	"sort"

	"github.com/miekg/pkcs11"
	"github.com/open-component-model/signing-server/pkg/crypto11"
	"github.com/open-component-model/signing-server/pkg/encoding"
)

/*
type HSMContext struct {
	Ctx     *pkcs11.Ctx
	Session pkcs11.SessionHandle
	Priv    pkcs11.ObjectHandle
}

func NewHSMContext(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, priv pkcs11.ObjectHandle) *HSMContext {
	return &HSMContext{
		Ctx:     ctx,
		Session: session,
		Priv:    syscall.PR_FP_EXC_OVF,
	}
}
*/

// HSMContext describes the signing environment based on PKCS#11.
// It contains the session to use for executing the signing operations
// and the PKCS#11 handle to access the private key to use.
type HSMContext struct {
	Session *crypto11.Session
	Key     pkcs11.ObjectHandle
}

func NewHSMContext(session *crypto11.Session, key pkcs11.ObjectHandle) *HSMContext {
	return &HSMContext{
		Session: session,
		Key:     key,
	}
}

func (c *HSMContext) Close() error {
	return c.Session.Close()
}

var hashFunctions = map[string]crypto.Hash{
	//  0 as hash function is used for signing directly without defining the hash algorithm
	"":           crypto.Hash(0),
	"sha256":     crypto.SHA256,
	"MD5":        crypto.MD5,
	"SHA-1":      crypto.SHA1,
	"SHA-224":    crypto.SHA224,
	"SHA-256":    crypto.SHA256,
	"SHA-384":    crypto.SHA384,
	"SHA-512":    crypto.SHA512,
	"MD5+SHA1":   crypto.MD5SHA1,
	"RIPEMD-160": crypto.RIPEMD160,
}

func GetHashFunction(name string) (crypto.Hash, bool) {
	if name == "" {
		return hashFunctions[name], false
	}
	h, ok := hashFunctions[name]
	return h, ok
}

func GetRegisteredHashFunctions() []string {
	keys := []string{}
	for k := range hashFunctions {
		keys = append(keys, k)
	}
	return keys
}

type SignHandler interface {
	Name() string
	Sign(hash crypto.Hash, data []byte) ([]byte, error)

	HTTPHandler(responseBuilders map[string]encoding.ResponseBuilder, maxContentLength int) http.Handler
}

var handlers = map[string]SignHandler{}

func Register(h SignHandler) {
	handlers[h.Name()] = h
}

func Get(name string) (SignHandler, error) {
	h := handlers[name]
	if h == nil {
		return nil, fmt.Errorf("unknown signing algorithm %q (supported %s)", name, SupportedSigners())
	}
	return h, nil
}

func SupportedSigners() []string {
	s := []string{}
	for k := range handlers {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

func All(algos ...string) []SignHandler {
	all := []SignHandler{}

	if len(algos) > 0 {
		for _, n := range algos {
			h := handlers[n]
			if h != nil {
				all = append(all, h)
			}
		}
	} else {
		for _, h := range handlers {
			all = append(all, h)
		}
	}
	return all
}
