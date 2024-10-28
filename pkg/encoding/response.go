package encoding

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

type ResponseBuilder interface {
	BuildResponse(signature []byte, annotations map[string]string) ([]byte, error)
}

func CreateResponseBuilders(certs []*pem.Block) map[string]ResponseBuilder {
	responseBuilders := map[string]ResponseBuilder{}

	responseBuilders[MediaTypeOctetStream] = &RawResponseBuilder{}
	responseBuilders[MediaTypeOctetStreamBase64] = &Base64ResponseBuilder{}
	responseBuilders[MediaTypeOctetStreamHex] = &HEXResponseBuilder{}
	responseBuilders[MediaTypePEM] = &PEMResponseBuilder{
		certs: certs,
	}

	return responseBuilders
}

////////////////////////////////////////////////////////////////////////////////

type RawResponseBuilder struct {
}

func (b *RawResponseBuilder) BuildResponse(signature []byte, annotations map[string]string) ([]byte, error) {
	return signature, nil
}

////////////////////////////////////////////////////////////////////////////////

type HEXResponseBuilder struct {
}

func (b *HEXResponseBuilder) BuildResponse(signature []byte, annotations map[string]string) ([]byte, error) {
	return []byte(hex.EncodeToString(signature)), nil
}

////////////////////////////////////////////////////////////////////////////////

type Base64ResponseBuilder struct {
}

func (b *Base64ResponseBuilder) BuildResponse(signature []byte, annotations map[string]string) ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(signature)), nil
}

////////////////////////////////////////////////////////////////////////////////

type PEMResponseBuilder struct {
	certs []*pem.Block
}

func (b *PEMResponseBuilder) BuildResponse(signature []byte, annotations map[string]string) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{})

	for _, cert := range b.certs {
		if err := pem.Encode(buf, cert); err != nil {
			return nil, fmt.Errorf("unable to pem encode certificate: %w", err)
		}
	}

	signatureBlock := &pem.Block{
		Type:    SignaturePEMBlockType,
		Headers: annotations,
		Bytes:   signature,
	}

	if err := pem.Encode(buf, signatureBlock); err != nil {
		return nil, fmt.Errorf("unable to pem encode signature: %w", err)
	}

	return buf.Bytes(), nil
}
