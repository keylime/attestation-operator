// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

type httpClientConfig struct {
	clientCertificates []tls.Certificate
	serverCAPool       *x509.CertPool
	insecureSkipVerify bool
}

type HTTPClientOption func(*httpClientConfig) error

func ClientCertificate(certFile, keyFile string) HTTPClientOption {
	return func(hcc *httpClientConfig) error {
		tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("client-certificate option: %w", err)
		}
		hcc.clientCertificates = append(hcc.clientCertificates, tlsCert)
		return nil
	}
}

func ServerCAFromDER(certFile string) HTTPClientOption {
	return func(hcc *httpClientConfig) error {
		f, err := os.Open(certFile)
		if err != nil {
			return fmt.Errorf("server-ca-der option: open %s: %w", certFile, err)
		}
		defer f.Close()

		certBytes, err := io.ReadAll(bufio.NewReader(f))
		if err != nil {
			return fmt.Errorf("server-ca-der option: reading %s: %w", certFile, err)
		}

		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("server-ca-der option: DER parsing %s: %w", certFile, err)
		}
		hcc.serverCAPool.AddCert(cert)
		return nil
	}
}

func ServerCAFromPEM(certFile string) HTTPClientOption {
	return func(hcc *httpClientConfig) error {
		f, err := os.Open(certFile)
		if err != nil {
			return fmt.Errorf("server-ca-pem option: open %s: %w", certFile, err)
		}
		defer f.Close()

		pemBytes, err := io.ReadAll(bufio.NewReader(f))
		if err != nil {
			return fmt.Errorf("server-ca-pem option: reading %s: %w", certFile, err)
		}

		var added bool
		p, rest := pem.Decode(pemBytes)
		for p != nil {
			if p.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(p.Bytes)
				if err != nil {
					return fmt.Errorf("server-ca-pem option: DER parsing: %w", err)
				}
				hcc.serverCAPool.AddCert(cert)
			}
			p, rest = pem.Decode(rest)
		}

		if !added {
			return fmt.Errorf("server-ca-pem option: no certificates found in PEM file %s", certFile)
		}
		return nil
	}
}

func InsecureSkipVerify() HTTPClientOption {
	return func(hcc *httpClientConfig) error {
		hcc.insecureSkipVerify = true
		return nil
	}
}

func SystemServerCA() HTTPClientOption {
	return func(hcc *httpClientConfig) error {
		scp, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("system-server-ca option: %w", err)
		}
		hcc.serverCAPool = scp
		return nil
	}
}

// NewKeylimeHTTPClient will create an HTTP client which can be used in interaction with the keylime services
func NewKeylimeHTTPClient(options ...HTTPClientOption) (*http.Client, error) {
	// process options
	cfg := &httpClientConfig{
		clientCertificates: nil,
		serverCAPool:       x509.NewCertPool(),
		insecureSkipVerify: false,
	}
	for _, opt := range options {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	// rand could get swapped out for the TPM rand
	rand := rand.Reader
	timeFunc := time.Now

	return &http.Client{
		Transport: &http.Transport{
			// take proxies from environment
			Proxy: http.ProxyFromEnvironment,

			// There are no connection timeouts
			// so we are doing pretty much exactly what
			// Go is doing itself
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				// increasing this from the default Go settings
				// as we can ensure that if there is IPv6 in our network
				// it actually *must* be configured correctly.
				FallbackDelay: 600 * time.Millisecond,
			}).DialContext,

			// These are HTTP keep alives (not TCP keepalives)
			// and their corresponding idle connection settings and timeouts
			DisableKeepAlives: false,
			MaxIdleConns:      10,
			MaxConnsPerHost:   1,
			IdleConnTimeout:   90 * time.Second,

			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,

			// as we are setting our own DialContext and TLSClientConfig
			// Go internally disables trying to use HTTP/2 (why?)
			// so we are reenabling this here
			ForceAttemptHTTP2: true,

			// Our TLS configuration that we prepped before
			TLSClientConfig: &tls.Config{
				Rand:               rand,
				Time:               timeFunc,
				RootCAs:            cfg.serverCAPool,
				Certificates:       cfg.clientCertificates,
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: cfg.insecureSkipVerify,
			},
		},
	}, nil
}
