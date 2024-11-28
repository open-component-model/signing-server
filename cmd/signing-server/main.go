package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/miekg/pkcs11"
	"github.com/open-component-model/signing-server/pkg/handler/sign/hsm_pkcs1_1_5"
	"github.com/open-component-model/signing-server/pkg/handler/sign/hsm_pss"
	"github.com/open-component-model/signing-server/pkg/handler/sign/rsassa_pss"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/pkcs12"

	"github.com/open-component-model/signing-server/pkg/encoding"
	"github.com/open-component-model/signing-server/pkg/handler/sign"
	"github.com/open-component-model/signing-server/pkg/handler/sign/rsassa_pkcs1_1_5"
	logutil "github.com/open-component-model/signing-server/pkg/log"
	"github.com/open-component-model/signing-server/pkg/sys"
)

var stdOut = os.Stdout
var stdErr = os.Stderr

type Config struct {
	// cli args
	RunServer           bool
	Daemon              bool
	SupportedAlgorithms []string

	StdOut string

	SigningCaCertsPath    string
	SigningCertPath       string
	SigningPrivateKeyPath string

	// Signing command args
	Encoding  string
	Hash      string
	Algorithm string
	Data      string
	OutFormat string
	OutFile   string

	// Server args
	GracefulTimeout time.Duration
	ServerKeyPath   string
	CaCertsPath     string
	ClientCAPath    string

	CertPath string
	Host     string
	Port     string

	DevelopmentLogging bool
	MaxBodySizeBytes   int
	DisableAuth        bool
	DisableHTTPS       bool

	HSMModule   string
	HSMSlot     int
	HSMPass     string
	HSMKeyLabel string
	HSMKeyId    string

	HSMContext   *pkcs11.Ctx
	HSMSession   pkcs11.SessionHandle
	HSMKeyHandle pkcs11.ObjectHandle

	// calculated by program
	Logger *zap.Logger
}

func (c *Config) SetupHSM() error {
	c.Logger.Info("setup HSM signing", zap.String("module", c.HSMModule))
	p := pkcs11.New(c.HSMModule)
	if p == nil {
		return fmt.Errorf("cannot create HSM access for PKCS#11")
	}
	err := p.Initialize()
	if err != nil {
		return err
	}

	slotreason := "by option"
	if c.HSMSlot < 0 {
		slots, err := p.GetSlotList(true)
		if err != nil {
			return fmt.Errorf("lookup HSM slots: %w", err)
		}
		if len(slots) == 0 {
			return fmt.Errorf("no slot found in HSM")
		}
		slotreason = fmt.Sprintf("first slot from %d available slots", len(slots))
		c.HSMSlot = int(slots[0])
	}
	c.Logger.Info("using slot", zap.Int("slot", c.HSMSlot), zap.String("reason", slotreason))

	session, err := p.OpenSession(uint(c.HSMSlot), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("open HSM session: %w", err)
	}

	// c.Logger.Info("using pin", zap.String("pin", c.HSMPass))
	err = p.Login(session, pkcs11.CKU_USER, c.HSMPass)
	if err != nil {
		p.CloseSession(session)
		return fmt.Errorf("HSM login: %w", err)
	}

	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	if c.HSMKeyLabel != "" {
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_LABEL, c.HSMKeyLabel))
		c.Logger.Info("selecting key label", zap.String("label", c.HSMKeyLabel))
	}
	if c.HSMKeyId != "" {
		id, err := hex.DecodeString(c.HSMKeyId)
		if err != nil {
			p.CloseSession(session)
			p.Destroy()
			return fmt.Errorf("invalid key id %+v: %w", id, err)
		}
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
		c.Logger.Info("selecting key id", zap.String("id", c.HSMKeyId))
	}
	if err := p.FindObjectsInit(session, attrs); err != nil {
		p.CloseSession(session)
		p.Destroy()
		return fmt.Errorf("HSM get private key handle %q: %w", c.HSMKeyId, err)
	}

	objs, _, err := p.FindObjects(session, 1)
	if err != nil {
		p.CloseSession(session)
		p.Destroy()
		return fmt.Errorf("find key failed: %w", err)
	}
	if len(objs) != 1 {
		p.CloseSession(session)
		p.Destroy()
		return fmt.Errorf("key not found (%d)", len(objs))
	}
	p.FindObjectsFinal(session)

	c.Logger.Info("key handle", zap.Uint("handle", uint(objs[0])))

	c.HSMSession = session
	c.HSMContext = p
	c.HSMKeyHandle = objs[0]
	return nil
}

func (c *Config) Validate(args []string) error {
	if c.SigningPrivateKeyPath == "" && c.HSMModule == "" {
		return errors.New("path to private key file or HSM module must be set")
	}

	if c.HSMModule != "" {
		if c.HSMPass == "" {
			return errors.New("HSM passphrase required")
		}
		switch {
		case strings.HasPrefix(c.HSMPass, "@"):
			pass, err := os.ReadFile(c.HSMPass[1:])
			if err != nil {
				return fmt.Errorf("cannot read passphrase from %q: %w", c.HSMPass[1:], err)
			}
			c.HSMPass = string(pass)

		case strings.HasPrefix(c.HSMPass, "="):
			c.HSMPass = c.HSMPass[1:]
		}

		if (c.HSMKeyId == "" && c.HSMKeyLabel == "") || (c.HSMKeyId != "" && c.HSMKeyLabel != "") {
			return errors.New("one of HSM key id or HSM key label required")
		}
		if c.HSMKeyId != "" {
			_, err := hex.DecodeString(c.HSMKeyId)
			if err != nil {
				return fmt.Errorf("HSM key id %q: %w", c.HSMKeyId, err)
			}
		}
	}

	if c.MaxBodySizeBytes <= 0 {
		return errors.New("max body size must be > 0")
	}
	if c.Logger == nil {
		return errors.New("logger must be set")
	}

	if c.RunServer {
		if !c.DisableHTTPS {
			if c.ServerKeyPath == "" {
				return errors.New("path to private server key file must be set")
			}
			if c.CertPath == "" && !strings.HasSuffix(c.ServerKeyPath, ".pfx") {
				return errors.New("path to cert file must be set")
			}
			if c.Host == "" {
				return errors.New("host must be set if https is enabled")
			}
		}
		if c.Port == "" {
			return errors.New("port must be set")
		}
		if c.DisableAuth {
			c.Logger.Warn("running server with disabled authentication. should only be used for development")
		} else {
			if c.ClientCAPath == "" {
				return errors.New("client CA must be set")
			}
		}
	} else {
		if c.Data != "" && len(args) > 0 {
			return errors.New("either input by argument or by file possible")
		}
		if len(args) > 1 {
			return errors.New("only one input file possible")
		}
	}

	return nil
}

func createTLSConfig(host string, disableAuth bool, caCertsPath string, certPath string, privateKeyPath string, clientCaCertsPath string, logger *zap.Logger) (*tls.Config, error) {
	var caCertPool *x509.CertPool
	var caRootCertPool *x509.CertPool
	var clientAuthType tls.ClientAuthType

	privateKey, _, cert, err := parseRSAPrivateKey("server", privateKeyPath)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		_, cert, err = parsePublicKeyCert("server", certPath)
		if err != nil {
			return nil, err
		}
	}

	if caCertsPath != "" {
		caRootCertPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		caCert, err := ioutil.ReadFile(caCertsPath)
		if err != nil {
			return nil, fmt.Errorf("unable to open ca certs file: %w", err)
		}

		if ok := caRootCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf("unable to append ca certs to cert pool")
		}

		chain, err := cert.Verify(x509.VerifyOptions{Roots: caRootCertPool})
		if err != nil {
			return nil, fmt.Errorf("cannot verify server certificate: %w", err)
		}
		logger.Info("issuing server chain", zap.String("issuer chain", chains(chain)))
	}

	if disableAuth {
		clientAuthType = tls.NoClientCert
	} else {
		clientAuthType = tls.RequireAndVerifyClientCert
		caCertPool = x509.NewCertPool()
		caCerts, err := ioutil.ReadFile(clientCaCertsPath)
		if err != nil {
			return nil, fmt.Errorf("unable to open client ca certs file: %w", err)
		}
		if ok := caCertPool.AppendCertsFromPEM(caCerts); !ok {
			return nil, fmt.Errorf("unable to append client ca certs to cert pool")
		}
	}

	pair := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
	}

	return &tls.Config{
		ServerName:   host,
		ClientAuth:   clientAuthType,
		ClientCAs:    caCertPool,
		Certificates: []tls.Certificate{pair},
		RootCAs:      caRootCertPool,
		MinVersion:   tls.VersionTLS12, // TLS versions below 1.2 are considered insecure - see https://www.rfc-editor.org/rfc/rfc7525.txt for details
	}, nil
}

func parseCertificate(name string, certPath string) ([]byte, *pem.Block, *x509.Certificate, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to read %s cert file %q: %w", name, certPath, err)
	}

	certBlock, rest := pem.Decode(certBytes)
	if certBlock == nil && len(rest) > 0 {
		return nil, nil, nil, fmt.Errorf("unable to parse %s cert file %q: unable to pem decode %s", name, certPath, string(rest))
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse %s certificate from %q: %w", name, certPath, err)
	}
	return certBytes, certBlock, cert, err
}

func parseCertificates(name string, caCertsPath string, logger *zap.Logger) ([]*pem.Block, *x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, nil, err
	}

	var caCertBlocks []*pem.Block
	if caCertsPath != "" {
		caCertsBytes, err := os.ReadFile(caCertsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read %s ca certs file %q: %w", name, caCertsPath, err)
		}
		roots.AppendCertsFromPEM(caCertsBytes)
		for {
			var certBlock *pem.Block
			certBlock, caCertsBytes = pem.Decode(caCertsBytes)
			if certBlock == nil && len(caCertsBytes) > 0 {
				return nil, nil, fmt.Errorf("unable to parse %s ca certs file %q: unable to pem decode %s", name, caCertsPath, string(caCertsBytes))
			}

			caCertBlocks = append(caCertBlocks, certBlock)
			if len(caCertsBytes) == 0 {
				break
			}
		}
	}

	return caCertBlocks, roots, err
}

func chains(chains [][]*x509.Certificate) string {
	r := ""
	for _, ch := range chains {
		if r != "" {
			r += "; "
		}
		sep := ""
		for _, c := range ch {
			r += sep + c.Issuer.String()
			sep = "->"
		}
	}
	return r
}

func parsePublicKeyCert(name string, certPath string) (*pem.Block, *x509.Certificate, error) {

	if certPath != "" {
		_, block, cert, err := parseCertificate(name, certPath)
		if err == nil {
			return block, cert, nil
		}
	}
	return nil, nil, nil
}

func parseRSAPrivateKey(name string, privateKeyPath string) (*rsa.PrivateKey, *pem.Block, *x509.Certificate, error) {
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to read %s private key file: %w", name, err)
	}
	if strings.HasSuffix(privateKeyPath, ".pfx") {
		ename := fmt.Sprintf("%s_PFX_PASSWORD", strings.ToUpper(name))
		pw, ok := os.LookupEnv(ename)
		if !ok {
			return nil, nil, nil, fmt.Errorf("password for %s pfx file required in environment (%s)", name, ename)
		}
		if pw == "" {
			return nil, nil, nil, fmt.Errorf("non-empty password for %s pfx file required in environment (%s)", name, ename)
		}
		key, cert, err := pkcs12.Decode(privateKeyBytes, pw)
		if err != nil {
			return nil, nil, nil, err
		}
		var block *pem.Block
		if cert != nil {
			block = &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
		}
		if k, ok := key.(*rsa.PrivateKey); ok {
			return k, block, cert, err
		}
		return nil, nil, nil, fmt.Errorf("no rsa key found in %q", privateKeyPath)
	}

	privateKeyBlock, rest := pem.Decode(privateKeyBytes)
	if privateKeyBlock != nil && len(rest) > 0 {
		return nil, nil, nil, fmt.Errorf("private key file contains undecodable data besides pem block: %s", string(rest))
	}

	if privateKeyBlock == nil && len(rest) == len(privateKeyBytes) {
		// found no pem data in private key file
		// try parsing with PKCS #1, ASN.1 DER form (binary)
		rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to parse pkcs1 private key: %w", err)
		}
		return rsaPrivateKey, nil, nil, nil
	} else if strings.ToLower(strings.Trim(privateKeyBlock.Type, "- ")) == "rsa private key" {
		// found pem encoded PKCS #1, ASN.1 DER form
		rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to parse pkcs1 private key: %w", err)
		}
		return rsaPrivateKey, nil, nil, nil
	} else {
		// try parsing with PKCS #8, ASN.1 DER form in rest of cases
		untypedPrivateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to parse pkcs8 private key: %w", err)
		}

		rsaPrivateKey, ok := untypedPrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, nil, fmt.Errorf("parsed pkcs8 private key is not of type *rsa.PrivateKey: actual type is %T", untypedPrivateKey)
		}

		return rsaPrivateKey, nil, nil, nil
	}
}

func run(cfg *Config) error {

	err := cfg.Validate(pflag.CommandLine.Args())
	if err != nil {
		return fmt.Errorf("unable to validate config: %w", err)
	}

	var block *pem.Block
	var cert *x509.Certificate
	var rsaPrivateKey *rsa.PrivateKey

	// setup signing handlers
	if cfg.HSMModule == "" {
		rsaPrivateKey, block, cert, err = parseRSAPrivateKey("signing", cfg.SigningPrivateKeyPath)
		if err != nil {
			return fmt.Errorf("unable to parse rsa private key: %w", err)
		}
	}
	if cert == nil {
		block, cert, err = parsePublicKeyCert("signing", cfg.SigningCertPath)
		if err != nil {
			return err
		}
	}
	var allCerts []*pem.Block
	caBlocks, pool, err := parseCertificates("signing", cfg.SigningCaCertsPath, cfg.Logger)
	if err != nil {
		return err
	}
	if cert != nil {
		chain, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
		if err != nil {
			return fmt.Errorf("cannot verify signing certificate: %w", err)
		}
		cfg.Logger.Info("issuing signing chain", zap.String("issuer chain", chains(chain)))
		allCerts = append(allCerts, block)
	}
	if len(caBlocks) > 0 {
		allCerts = append(allCerts, caBlocks...)
	}

	if cfg.HSMModule != "" {
		err := cfg.SetupHSM()
		if err != nil {
			return fmt.Errorf("cannot setup HSM signing: %w", err)
		}
		sign.Register(hsm_pkcs1_1_5.New(cfg.HSMContext, cfg.HSMSession, cfg.HSMKeyHandle))
		sign.Register(hsm_pss.New(cfg.HSMContext, cfg.HSMSession, cfg.HSMKeyHandle))
	} else {
		sign.Register(rsassa_pkcs1_1_5.New(rsaPrivateKey))
		sign.Register(rsassa_pss.New(rsaPrivateKey))
	}

	for _, n := range cfg.SupportedAlgorithms {
		if _, err := sign.Get(n); err != nil {
			return err
		}
	}

	cfg.Logger.Info(fmt.Sprintf("found signing %d certs", len(allCerts)))
	responseBuilders := encoding.CreateResponseBuilders(allCerts)

	if cfg.RunServer {
		if cfg.Daemon {
			cfg.Logger.Info("detaching processs")
			err := sys.Detach()
			if err != nil {
				return err
			}
		}
		return RunServer(cfg, allCerts, responseBuilders)
	} else {
		return RunSigner(cfg, pflag.CommandLine.Args(), responseBuilders)
	}
}

func RunSigner(cfg *Config, args []string, responseBuilders map[string]encoding.ResponseBuilder) error {
	builder := responseBuilders[cfg.OutFormat]
	if builder == nil {
		return fmt.Errorf("unknown output format %q", cfg.OutFormat)
	}
	decode, err := encoding.GetDecoder(cfg.Encoding)
	if err != nil {
		return err
	}
	signer, err := sign.Get(cfg.Algorithm)
	if err != nil {
		return err
	}

	hashfunc, ok := sign.GetHashFunction(cfg.Hash)
	if !ok {
		return fmt.Errorf("unknown hash algorith %q", cfg.Hash)
	}

	var data []byte
	if cfg.Data != "" {
		data = []byte(cfg.Data)
	} else {
		if len(args) > 1 {
			return fmt.Errorf("only one input file possible")
		}
		if len(args) == 1 && args[0] != "-" {
			data, err = os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("cannot read input file %q: %w", args[0], err)
			}
		} else {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("cannot read data from stdin: %w", err)
			}
		}
	}
	data, err = decode.Decode(data)
	if err != nil {
		return fmt.Errorf("cannot decode input: %w", err)
	}
	cfg.Logger.Info("sign", zap.String("digest", hex.EncodeToString(data)), zap.String("signer", fmt.Sprintf("%v", signer)))
	signature, err := signer.Sign(hashfunc, data)
	if err != nil {
		return err
	}

	annotations := map[string]string{
		encoding.SignatureAlgorithmHeader: signer.Name(),
	}
	out, err := builder.BuildResponse(signature, annotations)
	if err != nil {
		return err
	}
	if cfg.OutFile == "" {
		_, err = stdOut.Write(out)
	} else {
		err = os.WriteFile(cfg.OutFile, out, 0600)
	}
	return err
}

func RunServer(cfg *Config, allCerts []*pem.Block, responseBuilders map[string]encoding.ResponseBuilder) error {
	var err error

	addr := ":" + cfg.Port

	r := mux.NewRouter()
	for _, h := range sign.All(cfg.SupportedAlgorithms...) {
		route := fmt.Sprintf("/sign/%s", strings.ToLower(h.Name()))
		cfg.Logger.Info("register route", zap.String("route", route))
		r.Methods(http.MethodPost).Path(route).Handler(h.HTTPHandler(responseBuilders, cfg.MaxBodySizeBytes))
	}
	lm := logutil.LoggingMiddleware{
		Logger: cfg.Logger,
	}

	r.Use(lm.PrepareLogger)
	r.Use(lm.LogRequests)

	var tlsConfig *tls.Config
	if !cfg.DisableHTTPS {
		tlsConfig, err = createTLSConfig(cfg.Host, cfg.DisableAuth, cfg.CaCertsPath, cfg.CertPath, cfg.ServerKeyPath, cfg.ClientCAPath, cfg.Logger)
		if err != nil {
			return fmt.Errorf("unable to create tls config: %w", err)
		}
	}

	srv := &http.Server{
		Addr:         addr,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Minute * 15,
		IdleTimeout:  time.Second * 15,
		Handler:      r,
		TLSConfig:    tlsConfig,
	}

	var startServer func() error
	if cfg.DisableHTTPS {
		startServer = func() error {
			return srv.ListenAndServe()
		}
	} else {
		startServer = func() error {
			return srv.ListenAndServeTLS("", "")
		}
	}

	stop := make(chan struct{})
	go func() {
		cfg.Logger.Info("starting server", zap.String("address", addr))
		if err := startServer(); err != nil {
			cfg.Logger.Error("server stopped with error", zap.Error(err))
		}
		stop <- struct{}{}
	}()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	select {
	case <-c:
	case <-stop:
	}

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.GracefulTimeout)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("unable to shutdown server: %w", err)
	}
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	cfg.Logger.Info("shutting down server")
	return nil
}

func main() {
	cfg := Config{}

	pflag.StringVar(&cfg.StdOut, "stdout", "", "[OPTIONAL] log file for stderr, stdout and logging")

	pflag.BoolVar(&cfg.RunServer, "server", false, "[OPTIONAL] run signing server")
	pflag.BoolVar(&cfg.Daemon, "daemon", false, "[OPTIONAL] run signing server in detached mode")
	pflag.StringSliceVar(&cfg.SupportedAlgorithms, "supportedAlgorithms", nil, "[OPTIONAL] supported algorithms for signing server")
	pflag.StringVar(&cfg.Encoding, "encoding", encoding.Raw, "[OPTIONAL] encoding for data")
	pflag.StringVar(&cfg.OutFormat, "format", encoding.MediaTypePEM, "[OPTIONAL] output format")
	pflag.StringVar(&cfg.Hash, "hash", "", "[OPTIONAL] hash function")
	pflag.StringVar(&cfg.Data, "data", "", "[OPTIONAL] input data as argument")
	pflag.StringVar(&cfg.Algorithm, "algorithm", rsassa_pkcs1_1_5.Algorithm, "[OPTIONAL] signing algorithm")
	pflag.StringVar(&cfg.OutFile, "out", "", "[OPTIONAL] output file")

	pflag.StringVar(&cfg.SigningPrivateKeyPath, "private-key", "", `(non-hsm) path to a file which contains the private signing key.
supported formats are:
- PKCS#1 (.der, .pem)
- PKCS#8 (.pem)
- PKCS#12 (.pfx)`)
	pflag.StringVar(&cfg.SigningCertPath, "signing-cert", "", "[OPTIONAL] path to a file which contains the signing certificate")
	pflag.StringVar(&cfg.SigningCaCertsPath, "signing-ca-certs", "", "[OPTIONAL] path to a file which contains the signing ca certificates")

	pflag.StringVar(&cfg.HSMModule, "hsm-module", "", "[OPTIONAL] path to HSM library")
	pflag.StringVar(&cfg.HSMPass, "hsm-pass", "", "[OPTIONAL] HSM passphrase (@... from file, =... from arg)")
	pflag.StringVar(&cfg.HSMKeyId, "hsm-keyid", "", "[OPTIONAL] hsm key id")
	pflag.StringVar(&cfg.HSMKeyLabel, "hsm-keylabel", "", "[OPTIONAL] hsm key label")
	pflag.IntVar(&cfg.HSMSlot, "hsm-slot", -1, "[OPTIONAL] hsm slot")

	pflag.StringVar(&cfg.ServerKeyPath, "server-key", "", "path to a file which contains the server private key")
	pflag.StringVar(&cfg.CertPath, "cert", "", "path to a file which contains the server certificate in pem format")
	pflag.StringVar(&cfg.CaCertsPath, "ca-certs", "", "[OPTIONAL] path to a file which contains the concatenation of any intermediate and ca certificate in pem format")
	pflag.StringVar(&cfg.ClientCAPath, "client-ca-certs", "", "[OPTIONAL] CA used for client certificates")
	pflag.DurationVar(&cfg.GracefulTimeout, "graceful-timeout", time.Second*15, "[OPTIONAL] the duration for which the server gracefully wait for existing connections to finish - e.g. 15s or 1m")
	pflag.StringVar(&cfg.Host, "host", "localhost", "[OPTIONAL] hostname that is resolvable via dns")
	pflag.StringVar(&cfg.Port, "port", "8080", "[OPTIONAL] port where the server should listen")
	pflag.BoolVar(&cfg.DevelopmentLogging, "dev-logging", false, "[OPTIONAL] enable development logging")
	pflag.IntVar(&cfg.MaxBodySizeBytes, "max-body-size", 2048, "[OPTIONAL] maximum allowed size of the request body in bytes")
	pflag.BoolVar(&cfg.DisableAuth, "disable-auth", false, "[OPTIONAL] disable authentication. should only be used for development")
	pflag.BoolVar(&cfg.DisableHTTPS, "disable-https", false, "[OPTIONAL] disable https. runs the server with http")
	pflag.Parse()

	var err error
	var logger *zap.Logger

	stdOut = os.Stdout
	stdErr = os.Stderr
	if cfg.StdOut != "" {
		var out *os.File
		out, err = os.OpenFile(cfg.StdOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err == nil {
			fmt.Printf("redirecting all output to %s\n", cfg.StdOut)
			os.Stdout, os.Stderr = out, out
		} else {
			err = fmt.Errorf("cannot create output file %s: %w", cfg.StdOut, err)
		}
	}

	if err == nil {
		if cfg.DevelopmentLogging {
			logcfg := zap.NewDevelopmentConfig()
			logcfg.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
			logger, err = logcfg.Build()
		} else {
			if cfg.RunServer {
				logcfg := zap.NewProductionConfig()
				logcfg.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
				logger, err = logcfg.Build()
			} else {
				logger = zap.NewNop()
			}
		}
		cfg.Logger = logger
		if err == nil {
			err = run(&cfg)
		} else {
			err = fmt.Errorf("unable to create logger: %w", err)
		}
	}

	if err != nil {
		fmt.Fprintf(stdErr, "%s\n", err)
		os.Exit(1)
	}
}
