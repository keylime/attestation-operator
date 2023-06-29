// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/keylime/attestation-operator/pkg/client"
)

const (
	apiVersion = "v2.1"
)

// AgentState represents all known agent states according to: https://github.com/keylime/keylime/blob/master/keylime/common/states.py
type AgentState uint16

const (
	Registered AgentState = iota
	Start
	Saved
	GetQuote
	GetQuoteRetry
	ProvideV
	ProvideVRetry
	Failed
	Terminated
	InvalidQuote
	TenantFailed
)

var agentStateMap = map[AgentState]struct {
	str  string
	desc string
}{
	Registered:    {str: "REGISTERED", desc: "The agent is registered with registrar but not added to verifier yet"},
	Start:         {str: "START", desc: "The agent is added to verifier and will be moved to next state"},
	Saved:         {str: "SAVED", desc: "The agent was added in verifier and wait for requests"},
	GetQuote:      {str: "GET_QUOTE", desc: "The agent is under periodic integrity checking"},
	GetQuoteRetry: {str: "GET_QUOTE_RETRY", desc: "The agent is under periodic integrity checking but in a retry state due to connection issues"},
	ProvideV:      {str: "PROVIDE_V", desc: "The agent host failed to prove the integrity"},
	ProvideVRetry: {str: "PROVIDE_V_RETRY", desc: "The agent was terminated and will be removed from verifier"},
	Failed:        {str: "FAILED", desc: "The agent host failed to prove the integrity"},
	Terminated:    {str: "TERMINATED", desc: "The agent was terminated and will be removed from verifier"},
	InvalidQuote:  {str: "INVALID_QUOTE", desc: "The integrity report from agent is not trusted against whitelist"},
	TenantFailed:  {str: "TENANT_FAILED", desc: "The agent was terminated but failed to be removed form verifier"},
}

func (as AgentState) String() string {
	v, ok := agentStateMap[as]
	if !ok {
		return "UNKNOWN"
	}
	return v.str
}

func (as AgentState) Description() string {
	v, ok := agentStateMap[as]
	if !ok {
		return fmt.Sprintf("The agent state (%d) is unknown", as)
	}
	return v.desc
}

type getResults struct {
	OperationalState          uint16   `json:"operational_state"`
	V                         []byte   `json:"v"`
	IP                        string   `json:"ip"`
	Port                      uint16   `json:"port"`
	TPMPolicy                 string   `json:"tpm_policy"`
	VTPMPolicy                string   `json:"vtpm_policy"`
	MetaData                  string   `json:"meta_data"`
	HasMBRefState             int      `json:"has_mb_refstate"`
	HasRuntimePolicy          int      `json:"has_runtime_policy"`
	AcceptTPMHashAlgs         []string `json:"accept_tpm_hash_algs"`
	AcceptTPMEncryptionAlgs   []string `json:"accept_tpm_encryption_algs"`
	AcceptTPMSigningAlgs      []string `json:"accept_tpm_signing_algs"`
	HashAlg                   string   `json:"hash_alg"`
	EncryptionAlg             string   `json:"enc_alg"`
	SigningAlg                string   `json:"sign_alg"`
	VerifierID                string   `json:"verifier_id"`
	VerifierIP                string   `json:"verifier_ip"`
	VerifierPort              uint16   `json:"verifier_port"`
	SeverityLevel             *uint16  `json:"severity_level"`
	LastEventID               *string  `json:"last_event_id"`
	AttestationCount          uint     `json:"attestation_count"`
	LastReceivedQuote         *int64   `json:"last_received_quote"`
	LastSuccessfulAttestation *int64   `json:"last_successful_attestation"`
}

type get struct {
	Code    int        `json:"code"`
	Status  string     `json:"status"`
	Results getResults `json:"results"`
}

func parseAgent(r *getResults) (*VerifierAgent, error) {
	ipAddr, err := netip.ParseAddr(r.IP)
	if err != nil {
		return nil, fmt.Errorf("IP '%s' is not valid: %w", r.IP, err)
	}
	ipPort := netip.AddrPortFrom(ipAddr, r.Port)

	verifierIPAddr, err := netip.ParseAddr(r.VerifierIP)
	if err != nil {
		return nil, fmt.Errorf("verifier IP '%s' is not valid: %w", r.VerifierIP, err)
	}
	verifierIPPort := netip.AddrPortFrom(verifierIPAddr, r.VerifierPort)

	var tpmPolicy, vtpmPolicy *TPMPolicy
	if r.TPMPolicy != "" {
		var v TPMPolicy
		if err := json.Unmarshal([]byte(r.TPMPolicy), &v); err != nil {
			return nil, fmt.Errorf("failed to JSON decode TPM policy '%s': %w", r.TPMPolicy, err)
		}
		tpmPolicy = &v
	}
	if r.VTPMPolicy != "" {
		var v TPMPolicy
		if err := json.Unmarshal([]byte(r.VTPMPolicy), &v); err != nil {
			return nil, fmt.Errorf("failed to JSON decode vTPM policy '%s': %w", r.VTPMPolicy, err)
		}
		vtpmPolicy = &v
	}

	var lastReceivedQuote, lastSuccessfulAttestation *time.Time
	if r.LastReceivedQuote != nil && *r.LastReceivedQuote != 0 {
		v := time.Unix(*r.LastReceivedQuote, 0)
		lastReceivedQuote = &v
	}
	if r.LastSuccessfulAttestation != nil && *r.LastSuccessfulAttestation != 0 {
		v := time.Unix(*r.LastSuccessfulAttestation, 0)
		lastSuccessfulAttestation = &v
	}

	var acceptTPMHashAlgs []TPMHashAlg
	if len(r.AcceptTPMHashAlgs) > 0 {
		acceptTPMHashAlgs = make([]TPMHashAlg, 0, len(r.AcceptTPMHashAlgs))
		for _, alg := range r.AcceptTPMHashAlgs {
			acceptTPMHashAlgs = append(acceptTPMHashAlgs, TPMHashAlg(alg))
		}
	}
	var acceptTPMEncryptionAlgs []TPMEncryptionAlg
	if len(r.AcceptTPMEncryptionAlgs) > 0 {
		acceptTPMEncryptionAlgs = make([]TPMEncryptionAlg, 0, len(r.AcceptTPMEncryptionAlgs))
		for _, alg := range r.AcceptTPMEncryptionAlgs {
			acceptTPMEncryptionAlgs = append(acceptTPMEncryptionAlgs, TPMEncryptionAlg(alg))
		}
	}
	var acceptTPMSigningAlgs []TPMSigningAlg
	if len(r.AcceptTPMSigningAlgs) > 0 {
		acceptTPMSigningAlgs = make([]TPMSigningAlg, 0, len(r.AcceptTPMSigningAlgs))
		for _, alg := range r.AcceptTPMSigningAlgs {
			acceptTPMSigningAlgs = append(acceptTPMSigningAlgs, TPMSigningAlg(alg))
		}
	}

	var severityLevel uint16
	if r.SeverityLevel != nil {
		severityLevel = *r.SeverityLevel
	}

	var lastEventID string
	if r.LastEventID != nil {
		lastEventID = *r.LastEventID
	}

	return &VerifierAgent{
		OperationalState:          AgentState(r.OperationalState),
		V:                         r.V,
		IPPort:                    ipPort,
		TPMPolicy:                 tpmPolicy,
		VTPMPolicy:                vtpmPolicy,
		MetaData:                  r.MetaData,
		HasMBRefState:             r.HasMBRefState > 0,
		HasRuntimePolicy:          r.HasRuntimePolicy > 0,
		AcceptTPMHashAlgs:         acceptTPMHashAlgs,
		AcceptTPMEncryptionAlgs:   acceptTPMEncryptionAlgs,
		AcceptTPMSigningAlgs:      acceptTPMSigningAlgs,
		HashAlg:                   TPMHashAlg(r.HashAlg),
		EncryptionAlg:             TPMEncryptionAlg(r.EncryptionAlg),
		SigningAlg:                TPMSigningAlg(r.SigningAlg),
		VerifierID:                r.VerifierID,
		VerifierIPPort:            verifierIPPort,
		SeverityLevel:             severityLevel,
		LastEventID:               lastEventID,
		AttestationCount:          r.AttestationCount,
		LastReceivedQuote:         lastReceivedQuote,
		LastSuccessfulAttestation: lastSuccessfulAttestation,
	}, nil
}

/*
	{
	  "code": 200,
	  "status": "Success",
	  "results": {
	    "operational_state": 7,
	    "v": "yyNnlWwFRz1ZUzSe2YEpz9A5urtv6oywgttTF7VbBP4=",
	    "ip": "127.0.0.1",
	    "port": 9002,
	    "tpm_policy": "{\"22\": [\"0000000000000000000000000000000000000001\", \"0000000000000000000000000000000000000000000000000000000000000001\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001\", \"ffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"], \"15\": [\"0000000000000000000000000000000000000000\", \"0000000000000000000000000000000000000000000000000000000000000000\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"], \"mask\": \"0x408000\"}",
	    "vtpm_policy": "{\"23\": [\"ffffffffffffffffffffffffffffffffffffffff\", \"0000000000000000000000000000000000000000\"], \"15\": [\"0000000000000000000000000000000000000000\"], \"mask\": \"0x808000\"}",
	    "meta_data": "{}",
	    "has_mb_refstate": 0,
	    "has_runtime_policy": 0,
	    "accept_tpm_hash_algs": [
	      "sha512",
	      "sha384",
	      "sha256",
	      "sha1"
	    ],
	    "accept_tpm_encryption_algs": [
	      "ecc",
	      "rsa"
	    ],
	    "accept_tpm_signing_algs": [
	      "ecschnorr",
	      "rsassa"
	    ],
	    "hash_alg": "sha256",
	    "enc_alg": "rsa",
	    "sign_alg": "rsassa",
	    "verifier_id": "default",
	    "verifier_ip": "127.0.0.1",
	    "verifier_port": 8881,
	    "severity_level": 6,
	    "last_event_id": "qoute_validation.quote_validation",
	    "attestation_count": 240,
	    "last_received_quote": 1676644582,
	    "last_successful_attestation": 1676644462
	  }
	}
*/
type VerifierAgent struct {
	OperationalState          AgentState
	V                         []byte
	IPPort                    netip.AddrPort
	TPMPolicy                 *TPMPolicy
	VTPMPolicy                *TPMPolicy
	MetaData                  any
	HasMBRefState             bool
	HasRuntimePolicy          bool
	AcceptTPMHashAlgs         []TPMHashAlg
	AcceptTPMEncryptionAlgs   []TPMEncryptionAlg
	AcceptTPMSigningAlgs      []TPMSigningAlg
	HashAlg                   TPMHashAlg
	EncryptionAlg             TPMEncryptionAlg
	SigningAlg                TPMSigningAlg
	VerifierID                string
	VerifierIPPort            netip.AddrPort
	SeverityLevel             uint16
	LastEventID               string
	AttestationCount          uint
	LastReceivedQuote         *time.Time
	LastSuccessfulAttestation *time.Time
}

type TPMPolicy struct {
	PCR0  []string `json:"0,omitempty"`
	PCR1  []string `json:"1,omitempty"`
	PCR2  []string `json:"2,omitempty"`
	PCR3  []string `json:"3,omitempty"`
	PCR4  []string `json:"4,omitempty"`
	PCR5  []string `json:"5,omitempty"`
	PCR6  []string `json:"6,omitempty"`
	PCR7  []string `json:"7,omitempty"`
	PCR8  []string `json:"8,omitempty"`
	PCR9  []string `json:"9,omitempty"`
	PCR10 []string `json:"10,omitempty"`
	PCR11 []string `json:"11,omitempty"`
	PCR12 []string `json:"12,omitempty"`
	PCR13 []string `json:"13,omitempty"`
	PCR14 []string `json:"14,omitempty"`
	PCR15 []string `json:"15,omitempty"`
	PCR16 []string `json:"16,omitempty"`
	PCR17 []string `json:"17,omitempty"`
	PCR18 []string `json:"18,omitempty"`
	PCR19 []string `json:"19,omitempty"`
	PCR20 []string `json:"20,omitempty"`
	PCR21 []string `json:"21,omitempty"`
	PCR22 []string `json:"22,omitempty"`
	PCR23 []string `json:"23,omitempty"`
	Mask  string   `json:"mask,omitempty"`
}

type TPMHashAlg string
type TPMEncryptionAlg string
type TPMSigningAlg string

type AddAgentRequest struct{}

type Client interface {
	GetAgent(ctx context.Context, uuid string) (*VerifierAgent, error)
	AddAgent(ctx context.Context, uuid string, agentRequest *VerifierAgent) error
	DeleteAgent(ctx context.Context, uuid string) error
	StopAgent(ctx context.Context, uuid string) error
	ReactivateAgent(ctx context.Context, uuid string) error
}

type verifierClient struct {
	http              *http.Client
	url               *url.URL
	internalCtx       context.Context
	internalCtxCancel context.CancelFunc
}

var _ Client = &verifierClient{}

func New(ctx context.Context, httpClient *http.Client, verifierURL string) (Client, error) {
	parsedURL, err := url.Parse(verifierURL)
	if err != nil {
		return nil, client.InvalidURL(err)
	}

	internalCtx, internalCtxCancel := context.WithCancel(ctx)

	return &verifierClient{
		http:              httpClient,
		url:               parsedURL,
		internalCtx:       internalCtx,
		internalCtxCancel: internalCtxCancel,
	}, nil
}

// GetAgent implements Client.
func (c *verifierClient) GetAgent(ctx context.Context, uuid string) (*VerifierAgent, error) {
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

	return parseAgent(&resp.Results)
}

// AddAgent implements Client.
func (*verifierClient) AddAgent(ctx context.Context, uuid string, agentRequest *VerifierAgent) error {
	panic("unimplemented")
}

// DeleteAgent implements Client.
func (c *verifierClient) DeleteAgent(ctx context.Context, uuid string) error {
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

// ReactivateAgent implements Client.
func (c *verifierClient) ReactivateAgent(ctx context.Context, uuid string) error {
	u := client.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "agents", uuid, "reactivate")
	if err != nil {
		return err
	}
	u.Path = reqPath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), nil)
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

// StopAgent implements Client.
func (c *verifierClient) StopAgent(ctx context.Context, uuid string) error {
	u := client.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "agents", uuid, "stop")
	if err != nil {
		return err
	}
	u.Path = reqPath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), nil)
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
