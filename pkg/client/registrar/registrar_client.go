// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package registrar

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/keylime/attestation-operator/pkg/client"
)

const (
	apiVersion = "v2.1"
)

var (
	// ErrInvalidURL is returned from New if the provided URL is invalid
	ErrInvalidURL = errors.New("invalid registrar URL")
)

func invalidURL(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidURL, err)
}

type Client interface {
	ListAgents(ctx context.Context) ([]string, error)
	GetAgent(ctx context.Context, uuid string) (*Agent, error)
	DeleteAgent(ctx context.Context, uuid string) error
}

type registrarClient struct {
	http              *http.Client
	url               *url.URL
	internalCtx       context.Context
	internalCtxCancel context.CancelFunc
}

var _ Client = &registrarClient{}

func New(ctx context.Context, httpClient *http.Client, registrarURL string) (Client, error) {
	parsedURL, err := url.Parse(registrarURL)
	if err != nil {
		return nil, invalidURL(err)
	}

	internalCtx, internalCtxCancel := context.WithCancel(ctx)

	return &registrarClient{
		http:              httpClient,
		url:               parsedURL,
		internalCtx:       internalCtx,
		internalCtxCancel: internalCtxCancel,
	}, nil
}

// ListAgents implements https://keylime.readthedocs.io/en/latest/rest_apis.html#get--v2.1-agents-
func (c *registrarClient) ListAgents(ctx context.Context) ([]string, error) {
	type listResults struct {
		UUIDs []string `json:"uuids"`
	}
	type list struct {
		Code    int         `json:"code"`
		Status  string      `json:"status"`
		Results listResults `json:"results"`
	}

	u := client.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "agents/")
	if err != nil {
		return nil, err
	}
	u.Path = reqPath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	// parse response
	// if it was an error, return as such
	if httpResp.StatusCode != http.StatusOK {
		return nil, client.NewHTTPErrorFromBody(httpResp)
	}

	// otherwise we parse it as an IPAM response
	var resp list
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, err
	}

	return resp.Results.UUIDs, nil
}

type Agent struct {
	AIK      []byte
	EK       []byte
	EKCert   *x509.Certificate
	MTLSCert *x509.Certificate
	IPPort   netip.AddrPort
	RegCount uint
}

type getResults struct {
	AIK      []byte `json:"aik_tpm"`
	EK       []byte `json:"ek_tpm"`
	EKCert   []byte `json:"ekcert"`
	MTLSCert string `json:"mtls_cert"`
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`
	RegCount uint   `json:"regcount"`
}

type get struct {
	Code    int        `json:"code"`
	Status  string     `json:"status"`
	Results getResults `json:"results"`
}

// GetAgent implements https://keylime.readthedocs.io/en/latest/rest_apis.html#get--v2.1-agents-agent_id-UUID
func (c *registrarClient) GetAgent(ctx context.Context, uuid string) (*Agent, error) {
	u := client.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "agents", uuid)
	if err != nil {
		return nil, err
	}
	u.Path = reqPath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	// parse response
	// if it was an error, return as such
	if httpResp.StatusCode != http.StatusOK {
		return nil, client.NewHTTPErrorFromBody(httpResp)
	}

	// otherwise we parse it as an IPAM response
	var resp get
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, err
	}

	return parseAgent(resp)
}

func parseAgent(resp get) (*Agent, error) {
	ipAddr, err := netip.ParseAddr(resp.Results.IP)
	if err != nil {
		return nil, fmt.Errorf("IP is not valid: %w", err)
	}
	ipPort := netip.AddrPortFrom(ipAddr, resp.Results.Port)

	ekCert, err := x509.ParseCertificate(resp.Results.EKCert)
	if err != nil {
		return nil, fmt.Errorf("EK cert parsing: %w", err)
	}

	mtlsCertPEM, _ := pem.Decode([]byte(resp.Results.MTLSCert))
	if mtlsCertPEM == nil {
		return nil, fmt.Errorf("MTLS cert is not PEM encoded")
	}
	if mtlsCertPEM.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("MTLS cert PEM type is not a certificate, but %s", mtlsCertPEM.Type)
	}
	mtlsCert, err := x509.ParseCertificate(mtlsCertPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("MTLS cert parsing: %w", err)
	}

	return &Agent{
		AIK:      resp.Results.AIK,
		EK:       resp.Results.EK,
		EKCert:   ekCert,
		MTLSCert: mtlsCert,
		IPPort:   ipPort,
		RegCount: resp.Results.RegCount,
	}, nil
}

func (c *registrarClient) DeleteAgent(ctx context.Context, uuid string) error {
	u := client.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "agents", uuid)
	if err != nil {
		return err
	}
	u.Path = reqPath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	// parse response
	// if it was an error, return as such
	if httpResp.StatusCode != http.StatusOK {
		return client.NewHTTPErrorFromBody(httpResp)
	}

	return nil
}
