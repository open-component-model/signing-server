// Copyright 2024 Thales Group
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// partly copied from https://github.com/thalesgroup/crypto11.

package crypto11

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"math/big"

	"github.com/miekg/pkcs11"
)

// errMalformedRSAPublicKey is returned when an RSA public key is not in a suitable form.
//
// Currently this means that the public exponent is either bigger than
// 32 bits, or less than 2.
var errMalformedRSAPublicKey = errors.New("malformed RSA public key")

// errUnsupportedRSAOptions is returned when an unsupported RSA option is requested.
//
// Currently this means a nontrivial SessionKeyLen when decrypting; or
// an unsupported hash function; or crypto.rsa.PSSSaltLengthAuto was
// requested.
var errUnsupportedRSAOptions = errors.New("unsupported RSA option value")

// Export the public key corresponding to a private RSA key.
func exportRSAPublicKey(session *Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	exported, err := session.Ctx.GetAttributeValue(session.Handle, pubHandle, template)
	if err != nil {
		return nil, err
	}
	var modulus = new(big.Int)
	modulus.SetBytes(exported[0].Value)
	var bigExponent = new(big.Int)
	bigExponent.SetBytes(exported[1].Value)
	if bigExponent.BitLen() > 32 {
		return nil, errMalformedRSAPublicKey
	}
	if bigExponent.Sign() < 1 {
		return nil, errMalformedRSAPublicKey
	}
	exponent := int(bigExponent.Uint64())
	result := rsa.PublicKey{
		N: modulus,
		E: exponent,
	}
	if result.E < 2 {
		return nil, errMalformedRSAPublicKey
	}
	return &result, nil
}

func HashToPKCS11(hashFunction crypto.Hash) (hashAlg uint, mgfAlg uint, hashLen uint, err error) {
	switch hashFunction {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, 20, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, 28, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64, nil
	default:
		return 0, 0, 0, errUnsupportedRSAOptions
	}
}

func (s *Session) SignPSS(key pkcs11.ObjectHandle, digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	var hMech, mgf, hLen, sLen uint
	var err error
	if hMech, mgf, hLen, err = HashToPKCS11(opts.Hash); err != nil {
		return nil, err
	}
	switch opts.SaltLength {
	case rsa.PSSSaltLengthAuto:
		pubKey, err := exportRSAPublicKey(s, key)
		if err != nil {
			return nil, err
		}
		if k, ok := pubKey.(*rsa.PublicKey); ok {
			sLen = uint(k.N.BitLen()-1+7)/8 - 2 - hLen
		} else {
			return nil, errUnsupportedRSAOptions
		}
	case rsa.PSSSaltLengthEqualsHash:
		sLen = hLen
	default:
		sLen = uint(opts.SaltLength)
	}
	// TODO this is pretty horrible, maybe the PKCS#11 wrapper
	// could be improved to help us out here
	parameters := concat(ulongToBytes(hMech),
		ulongToBytes(mgf),
		ulongToBytes(sLen))
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, parameters)}
	if s.serialized {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	if err = s.Ctx.SignInit(s.Handle, mech, key); err != nil {
		return nil, err
	}
	return s.Ctx.Sign(s.Handle, digest)
}

var pkcs1Prefix = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func (s *Session) SignPKCS1v15(key pkcs11.ObjectHandle, digest []byte, hash crypto.Hash) (signature []byte, err error) {
	/* Calculate T for EMSA-PKCS1-v1_5. */
	oid := pkcs1Prefix[hash]
	T := make([]byte, len(oid)+len(digest))
	copy(T[0:len(oid)], oid)
	copy(T[len(oid):], digest)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	if s.serialized {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	err = s.Ctx.SignInit(s.Handle, mech, key)
	if err == nil {
		signature, err = s.Ctx.Sign(s.Handle, T)
	}
	return
}
