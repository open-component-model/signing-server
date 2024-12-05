package crypto11

import (
	"encoding/hex"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// errTokenNotFound represents the failure to find the requested PKCS#11 token
var errTokenNotFound = errors.New("could not find PKCS#11 token")

type Session struct {
	Ctx    *pkcs11.Ctx
	Handle pkcs11.SessionHandle
}

type Config struct {
	Path       string
	TokenLabel string
	Slot       *int
	Pin        string
}

func NewSession(cfg *Config) (*Session, error) {
	p := pkcs11.New(cfg.Path)
	if p == nil {
		return nil, fmt.Errorf("cannot create HSM access for PKCS#11")
	}
	err := p.Initialize()
	if err != nil {
		return nil, err
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

	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
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
		Ctx:    p,
		Handle: session,
	}, nil
}

func findSlot(cfg *Config, p *pkcs11.Ctx, slots []uint) (uint, error) {
	if cfg.Slot == nil && cfg.TokenLabel == "" {
		slots, err := lookupSlots(p)
		if err != nil {
			return 0, fmt.Errorf("lookup HSM slots: %w", err)
		}
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
