# Signing Tool/Server

[![REUSE status](https://api.reuse.software/badge/github.com/open-component-model/signing-server)](https://api.reuse.software/info/github.com/open-component-model/signing-server)

This repository contains the implementation of a signing tool/server which can be used for signing arbitrary content. See the [API documentation](./api.md) for more information on the server's capabilities.

The content is not hashed, so the intention is to
sign short data or hashes of resources. The hash algorithm used to generate the hash can be passed along with the (hash) data.

It uses separate certificates/ certificate authorities
for

- the signing process
- for the client authorization
- for the web server

If a PKCS#12 key file (signing key or server key) is specified, the certificate is also taken from this file. The required passwords are given by environment variables:

- `SIGNING_PFX_PASSWORD`: for the signing key
- `SERVER_PFX_PASSWORD`: for the web server

## Synopsis

Common Signing Options:

```text
  --dev-logging
        [OPTIONAL] enable development logging
  --encoding string
        [OPTIONAL] encoding for data (default "raw")
  --format string
        [OPTIONAL] output format (default "application/x-pem-file")
  --signing-ca-certs string
        [OPTIONAL] path to a file which contains the signing ca certificates
  --signing-cert string
        [OPTIONAL] path to a file which contains the signing certificate
  --private-key string
        path to a file which contains the private signing key.
        supported formats are:
        - PKCS#1 (.der, .pem)
        - PKCS#8 (.pem)
        - PKCS#12 (.pfx)
  --hsm-keyid string
        [OPTIONAL] hsm key id
  --hsm-keylabel string
        [OPTIONAL] hsm key label
  --hsm-module string
        [OPTIONAL] path to HSM library
  --hsm-pass string
        [OPTIONAL] HSM passphrase (@... from file, =... from arg)
  --hsm-slot int
        [OPTIONAL] hsm slot (default -1)

  --stdout string
        redirect log, regular output and error output to given file
  --supportedAlgorithms strings   [OPTIONAL] supported algorithms for signing server
```

Signing Tool Options:

```text
  --algorithm string
        [OPTIONAL] signing algorithm (default "RSASSA-PKCS1-V1_5")
  --data string
        [OPTIONAL] input data as argument
  --hash string
        [OPTIONAL] hash function
  --out string
        OPTIONAL] output file
```

Signing Server Options:

```text
  --ca-certs string
      [OPTIONAL] path to a file which contains the concatenation of any intermediate and ca certificate in pem format
  --cert string
      path to a file which contains the server certificate in pem format
  --client-ca-certs string
      [OPTIONAL] path to a file which contains the ca certificate in pem format used for the client authorization.
  --disable-auth
      [OPTIONAL] disable authentication. should only be used for development
  --disable-https
      [OPTIONAL] disable https. runs the server with http
  --graceful-timeout duration
      [OPTIONAL] the duration for which the server gracefully wait for existing connections to finish - e.g. 15s or 1m (default 15s)
  --host string
      [OPTIONAL] hostname that is resolvable via dns (default "localhost")
  --max-body-size int
      [OPTIONAL] maximum allowed size of the request body in bytes (default 2048)
  --port string
      [OPTIONAL] port where the server should listen (default "8080")
  --server
      [OPTIONAL] run signing server
  --server-key string
      path to a file which contains the server private key
```

## Signing tool

If called without the `--server` option it can be used as command line tool to sign hashes.
It accepts options for the content encoding (`--encoding`), the data (`--data`, *&lt;filename>* or *stdin*), the hash algorithm (`--hash`) and the desired output format (`--format`)

## Server

If called with option `--server` an http(s) server
is started able to serve signing requests.

For authorization a client certificate is required
signed by the server certificate.

It requires a server certificate with optional certificate authority certificate for the web server and a certificate authority certificate for the validation of client certificates if the client authorization is not disabled.

### HSM Signing

Using the `hsm` signing options signing is switched to hardware-based signing,
no private key is required anymore. The signing algorithms are the same.

With `--hsm-module` the path to the HSM shared library is specified. This
library is specific for your hardware signing module, which should be used for
signing. For testing, you can use the `softhcm` library (for Unix systems
this is typically `/usr/lib/softhsm/libsofthsm2.so`)

Additionally, the pass phrase and the id or label of the private key has to
be specified. The slot is optional, by default, the first reported slot is
used.

### Sign with RSASSA-PKCS1-V1_5

Sign an arbitrary bytestream that is sent via the request body with the [RSASSA-PKCS1-V1_5](https://datatracker.ietf.org/doc/html/rfc3447#section-8.2) signature algorithm.

- **URL**

  /sign/rsassa-pkcs1-v1_5

- **Method:**

  `POST`

- **Request Headers**

  *Required:*

  - `Accept`: Format of the response content.
    - `application/x-pem-file`: Return pem format. The response additionally contains the x509 certificate of the server and optionally intermediate and ca certificates.
    - `application/octet-stream`: Return binary signature
    - `application/octet-stream+hex`: Return hex-encoded signature
    - `application/octet-stream+base64`: Return base64-encoded signature

  - `Content-Length`: Size of the request body.

  *Optional:*
  - `Content-Encoding`: Encoding of the data byte-stream (default: raw)
    - `base64`: base64-encoded data
    - `hex`: hex-encoded data
    - `raw`: byte-stream

- **Query Parameters**

  *Optional:*

  - `hashAlgorithm`:  Hash algorithm which was used to hash the data in the request body.
    - `""`: If empty, the data is signed directly and no [EMSA-PKCS1-v1_5](https://datatracker.ietf.org/doc/html/rfc3447#section-9) encoding is applied to the data.
    - `MD5`
    - `SHA-1`
    - `SHA-224`
    - `SHA-256`
    - `sha256`: deprecated
    - `SHA-384`
    - `SHA-512`
    - `MD5+SHA1`
    - `RIPEMD-160`

- **Request Body**

  The data that should be signed.

- **Success Response:**

  - **Code:** 200 <br />
    **Content:**

    ```text
    // Response format depends on the chosen format in the Accept header
    ```

## Setup

### Generate Keys and Certificates

- Prerequisite: openssl cli >= 3.0
- Create a new empty directory and the skeleton files and directories
  
  ```text
  mkdir keys-and-certs && cd keys-and-certs
  mkdir certs private && echo 01 > serial && touch index.txt && cp /usr/local/etc/openssl/openssl.cnf .
  ```

- Generate the private key
  - `openssl genpkey -algorithm RSA -out private/key.pem`
- Generate the server certificate and sign with the private key. Beware to add all hostnames for which the certificate should be valid via the `-addext` option.
  - `openssl req -new -x509 -days 365 -config openssl.cnf -key private/key.pem -out certs/cert.pem -extensions v3_ca -addext "subjectAltName = DNS:localhost"`

To generate a client certificate perform the following steps. These steps are optional and are only needed if client certificate authentication should be enabled.

- Create a new empty directory and the skeleton files and directories
  - `mkdir client && mkdir client/private && mkdir client/certs && mkdir client/csr`
- Generate the client private key
  - `openssl genpkey -algorithm RSA -out client/private/key.pem`
- Generate the client certificate signing request
  - `openssl req -new -sha256 -config openssl.cnf -key client/private/key.pem -out client/csr/csr.pem`
- Sign the client certificate signing request with the private key of the server
  - `openssl x509 -req -in client/csr/csr.pem -CA certs/cert.pem -CAkey private/key.pem -out client/certs/cert.pem -CAcreateserial -days 365 -sha256`

### Run on Local Machine

- Run `make go-build` to build the server executable
- Run `./signing-server --server` to locally run the server. Run `./signing-server --help` to get help on the correct configuration
- Use `hack/run` to create necessary keys and certificates and run the server.

### Run in K8s Cluster

- Clone this repository to your local machine
- Checkout the desired tag/commit via `git checkout`
- For building/pushing the Docker image locally
  - Set the `REGISTRY` variable in the Makefile to point to your desired OCI registry
  - Run `make docker-build` to build the image on your local machine. the ref of the built image will be printed out
  - Run `docker push <image-ref>` to push the locally built image to the remote registry
- Create a private key file and certificates file via `openssl`
- Create a K8s secret on the current kubectl context cluster which contains the private key for signing
  - Run `make create-private-key-secret PRIVATE_KEY_FILE=<path-to-private-key>`
- Create a configmap on the current kubectl context cluster which contains the server certificate
  - Run `make create-cert-configmap CERT_FILE=<path-to-cert>`
- [OPTIONAL] Create configmap on the current kubectl context cluster which contains any intermediate and ca certificates
  - Run `make create-ca-certs-configmap CA_CERTS_FILE=<path-to-ca-certs>`
- Check `./chart/values.yaml` for help on any further configuration
- Run `helm upgrade <release-name> ./chart -f <values-file> --install` to install the Helm Chart

  
