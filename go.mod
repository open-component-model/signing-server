module github.com/open-component-model/signing-server

go 1.23.2

replace github.com/ThalesGroup/crypto11 => github.com/mandelsoft/crypto11 v0.0.0-20241130184205-2da96e5e8173

require (
	github.com/ThalesGroup/crypto11 v1.2.6
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/miekg/pkcs11 v1.1.1
	github.com/spf13/pflag v1.0.5
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.30.0
)

require go.uber.org/multierr v1.10.0 // indirect

require (
	github.com/pkg/errors v0.9.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
)
