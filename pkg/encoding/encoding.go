package encoding

import (
	"fmt"
	"sort"
	"strings"
)

type Decoder interface {
	Decode(bytes []byte) ([]byte, error)
}

var decoders = map[string]Decoder{}

func RegisterDecoder(name string, d Decoder) {
	decoders[name] = d
}

func SupportedDecoders() []string {
	s := []string{}
	for k := range decoders {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

func GetDecoder(name string) (Decoder, error) {
	decoder := decoders[name]
	if decoder == nil {
		return nil, fmt.Errorf("unknown encoding %q (supported %s)", name, strings.Join(SupportedDecoders(), ","))
	}
	return decoder, nil
}
