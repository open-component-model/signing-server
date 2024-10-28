package encoding

import (
	"encoding/base64"
)

func init() {
	RegisterDecoder(Base64, base64Decoder{})
}

type base64Decoder struct{}

func (d base64Decoder) Decode(data []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(data))
}
