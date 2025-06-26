package crypto11

// inspired from https://github.com/thalesgroup/crypto11.

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// errTokenNotFound represents the failure to find the requested PKCS#11 token
var errTokenNotFound = errors.New("could not find PKCS#11 token")

// Session describes the PKCS##11 elements used to access the
// private key used for signing.
type Session struct {
	Ctx    *pkcs11.Ctx
	Handle pkcs11.SessionHandle

	mu         sync.Mutex // protects the session if serialized
	serialized bool
}

// Config describes the attributes required to access
// a dedicated HSM slot according to PKCS#11.
type Config struct {
	// Path is the OS filesystem path to the used HSM library.
	Path string
	// TokenLabel is an optional attribute to provide the label
	// of the slot token to use.
	TokenLabel string
	// Slot is an optional attribute to configure the slot number to use.
	// If neither a slot nor a token is specified, the first found slot
	// is used.
	Slot *int
	// Pin is the password used to access the described slot.
	Pin string

	// Logger is an optional logger to use for logging.
	Logger *zap.Logger
}

// NewSession provides a session object for working with HSM signing
// based on some HCM config provided by the Config type.
func NewSession(cfg *Config) (*Session, error) {
	p := pkcs11.New(cfg.Path)
	if p == nil {
		return nil, fmt.Errorf("cannot create HSM access for PKCS#11")
	}
	err := p.Initialize()
	if err != nil {
		return nil, fmt.Errorf("cannot initialize PKCS#11 session with %q: %w", cfg.Path, err)
	}

	slots, err := lookupSlots(p)
	if err != nil {
		p.Destroy()
		return nil, fmt.Errorf("lookup HSM slots: %w", err)
	}

	slot, err := findSlot(cfg, p, slots)
	if err != nil {
		p.Destroy()
		return nil, fmt.Errorf("lookup HSM slots: %w", err)
	}

	var serializedSession bool
	session, err := p.OpenSession(slot, 0)
	if err != nil && strings.Contains(err.Error(), fmt.Sprintf("0x%X", pkcs11.CKR_SESSION_PARALLEL_NOT_SUPPORTED)) {
		session, err = p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		serializedSession = true
		cfg.Logger.Warn("opening session in serialized mode as parallel sessions are unsupported", zap.Error(err))
	}
	if err != nil {
		return nil, fmt.Errorf("open HSM session: %w", err)
	}

	err = p.Login(session, pkcs11.CKU_USER, cfg.Pin)
	if err != nil {
		p.CloseSession(session)
		p.Destroy()
		return nil, fmt.Errorf("HSM login: %w", err)
	}

	return &Session{
		Ctx:        p,
		Handle:     session,
		serialized: serializedSession,
	}, nil
}

func findSlot(cfg *Config, p *pkcs11.Ctx, slots []uint) (uint, error) {
	if len(slots) == 0 {
		return 0, errTokenNotFound
	}
	if cfg.TokenLabel == "" {
		return slots[0], nil
	}
	for _, slot := range slots {
		tokenInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			p.Destroy()
			return 0, err
		}

		if (cfg.Slot != nil && uint(*cfg.Slot) == slot) ||
			(tokenInfo.Label != "" && tokenInfo.Label == cfg.TokenLabel) {
			return slot, nil
		}
	}
	return 0, errTokenNotFound
}

func lookupSlots(p *pkcs11.Ctx) ([]uint, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("cannot get slot list: %w", err)
	}
	if len(slots) == 0 {
		return nil, fmt.Errorf("no slot found")
	}
	return slots, nil
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	err := s.Ctx.CloseSession(s.Handle)
	s.Ctx.Destroy()
	return err
}

func (s *Session) FindPrivateKey(keyId, keyLabel string) (pkcs11.ObjectHandle, error) {
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	if keyLabel != "" {
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel))
	}
	if keyId != "" {
		id, err := hex.DecodeString(keyId)
		if err != nil {
			return 0, fmt.Errorf("invalid key id %+v: %w", id, err)
		}
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if s.serialized {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	if err := s.Ctx.FindObjectsInit(s.Handle, attrs); err != nil {
		return 0, fmt.Errorf("HSM get private key handle %q: %w", keyId, err)
	}

	objs, _, err := s.Ctx.FindObjects(s.Handle, 1)
	if err != nil {
		return 0, fmt.Errorf("find key failed: %w", err)
	}
	s.Ctx.FindObjectsFinal(s.Handle)
	if len(objs) != 1 {
		return 0, fmt.Errorf("key not found (%d)", len(objs))
	}
	return objs[0], nil
}
