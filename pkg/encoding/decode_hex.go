package encoding

import (
	"encoding/hex"
)

func init() {
	RegisterDecoder(Hex, hexDecoder{})
}

type hexDecoder struct{}

func (d hexDecoder) Decode(data []byte) ([]byte, error) {
	return hex.DecodeString(string(data))
}
