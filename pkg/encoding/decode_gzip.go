package encoding

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

func init() {
	RegisterDecoder(Gzip, gzipDecoder{})
}

type gzipDecoder struct{}

func (d gzipDecoder) Decode(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	data, err = io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	return data, nil
}
