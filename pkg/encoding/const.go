package encoding

const (
	// Supported Encodings
	Gzip   = "gzip"
	Base64 = "base64"
	Hex    = "hex"
	Raw    = "raw"

	// SignaturePEMBlockType defines the type of a signature pem block.
	SignaturePEMBlockType = "SIGNATURE"

	// MediaType
	//PEM defines the media type for pem formatted data.
	MediaTypePEM = "application/x-pem-file"
	// MediaTypeOctetStream provides plain signature in various encodings.
	MediaTypeOctetStream       = "application/octet-stream"
	MediaTypeOctetStreamHex    = "application/octet-stream+hex"
	MediaTypeOctetStreamBase64 = "application/octet-stream+base64"

	// SignatureAlgorithmHeader defines a pem header where the signature algorithm is defined.
	SignatureAlgorithmHeader = "Signature Algorithm"
)
