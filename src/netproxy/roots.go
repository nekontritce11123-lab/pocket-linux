package main

import (
	"crypto/x509"
	_ "embed"
	"errors"
)

// An explicit pool keeps Windows CryptoAPI from fetching AIA chains outside the proxy.
//
//go:embed certificates/cacert.pem
var rootCertificates []byte

func trustedRoots() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootCertificates) {
		return nil, errors.New("embedded CA bundle is invalid")
	}
	return pool, nil
}
