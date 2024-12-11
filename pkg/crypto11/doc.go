// package crypto11 provides a wrapper arround the plain pkcs11 Go wrapper,
// which supports signing operations according to the crypto package for RSA
// based keys.
// It is extracted from https://github.com/thalesgroup/crypto11, which seems to
// be not maintained anymore.
// It enriches the low level signing operations offered by PKCS#11 to be compliant
// to the interface offered by the crypto rsa package offered by Go.
// The Go RSA interface internally handles defaults for the signing options
// required for the naked algorithm, which is not provided by the PKCS#11 functions.
// This is especially required for the PSS signing method to calculate the SALT.
package crypto11
