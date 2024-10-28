package http

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/open-component-model/signing-server/pkg/encoding"
)

func DecoderFromRequest(r *http.Request) (encoding.Decoder, error) {
	enc := r.Header.Get(ContentEncoding)
	if enc == "" {
		t := r.Header.Get(ContentType)
		if i := strings.LastIndex(t, "+"); i > 0 {
			enc = t[i+1:]
		}
	}
	if enc == "" {
		enc = encoding.Raw
	}
	return encoding.GetDecoder(enc)
}

func ContentFromRequest(r *http.Request, maxContentLength int) ([]byte, error) {

	decoder, err := DecoderFromRequest(r)
	if err != nil {
		return nil, err
	}

	contentLength, err := CheckContentLengthHeader(r, maxContentLength)
	if err != nil {
		return nil, fmt.Errorf("invalid %q header: %w", ContentLengthHeader, err)
	}

	requestBody := make([]byte, contentLength)

	// if contentLength > actual body size: the server will get stuck waiting for the remaining body
	// if contentLength < actual body size: body will get cut off after contentLength reached
	read := 0
	for read < contentLength {
		if n, err := r.Body.Read(requestBody[read:]); err != nil {
			if err != io.EOF {
				return nil, fmt.Errorf("unable to read request body: %w", err)
			}
			read += n
			break
		} else {
			read += n
		}
	}
	if read != contentLength {
		return nil, fmt.Errorf("corrupted request body: expected %d bytes, but got only %d", contentLength, read)
	}
	return decoder.Decode(requestBody)
}
