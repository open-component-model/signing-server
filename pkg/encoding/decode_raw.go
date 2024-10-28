package encoding

func init() {
	RegisterDecoder(Raw, rawDecoder{})
}

type rawDecoder struct{}

func (d rawDecoder) Decode(data []byte) ([]byte, error) {
	return data, nil
}
