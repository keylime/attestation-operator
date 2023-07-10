// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"time"

	khttp "github.com/keylime/attestation-operator/pkg/client/http"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
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

type getAgentResults struct {
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

type getAgent struct {
	Code    int             `json:"code"`
	Status  string          `json:"status"`
	Results getAgentResults `json:"results"`
}

func parseAgent(r *getAgentResults) (*Agent, error) {
	var tpmPolicy, vtpmPolicy *attestationv1alpha1.TPMPolicy
	if r.TPMPolicy != "" && r.TPMPolicy != "{}" && r.TPMPolicy != "null" {
		var v attestationv1alpha1.TPMPolicy
		if err := json.Unmarshal([]byte(r.TPMPolicy), &v); err != nil {
			return nil, fmt.Errorf("failed to JSON decode TPM policy '%s': %w", r.TPMPolicy, err)
		}
		tpmPolicy = &v
	}
	if r.VTPMPolicy != "" && r.VTPMPolicy != "{}" && r.VTPMPolicy != "null" {
		var v attestationv1alpha1.TPMPolicy
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

	var acceptTPMHashAlgs []attestationv1alpha1.TPMHashAlg
	if len(r.AcceptTPMHashAlgs) > 0 {
		acceptTPMHashAlgs = make([]attestationv1alpha1.TPMHashAlg, 0, len(r.AcceptTPMHashAlgs))
		for _, alg := range r.AcceptTPMHashAlgs {
			acceptTPMHashAlgs = append(acceptTPMHashAlgs, attestationv1alpha1.TPMHashAlg(alg))
		}
	}
	var acceptTPMEncryptionAlgs []attestationv1alpha1.TPMEncryptionAlg
	if len(r.AcceptTPMEncryptionAlgs) > 0 {
		acceptTPMEncryptionAlgs = make([]attestationv1alpha1.TPMEncryptionAlg, 0, len(r.AcceptTPMEncryptionAlgs))
		for _, alg := range r.AcceptTPMEncryptionAlgs {
			acceptTPMEncryptionAlgs = append(acceptTPMEncryptionAlgs, attestationv1alpha1.TPMEncryptionAlg(alg))
		}
	}
	var acceptTPMSigningAlgs []attestationv1alpha1.TPMSigningAlg
	if len(r.AcceptTPMSigningAlgs) > 0 {
		acceptTPMSigningAlgs = make([]attestationv1alpha1.TPMSigningAlg, 0, len(r.AcceptTPMSigningAlgs))
		for _, alg := range r.AcceptTPMSigningAlgs {
			acceptTPMSigningAlgs = append(acceptTPMSigningAlgs, attestationv1alpha1.TPMSigningAlg(alg))
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

	var metadata map[string]any
	if r.MetaData != "" && r.MetaData != "{}" && r.MetaData != "null" {
		metadata = make(map[string]any)
		if err := json.Unmarshal([]byte(r.MetaData), &metadata); err != nil {
			return nil, fmt.Errorf("failed to JSON decode metadata: %w", err)
		}
	}

	return &Agent{
		OperationalState:          AgentState(r.OperationalState),
		V:                         r.V,
		IP:                        r.IP,
		Port:                      r.Port,
		TPMPolicy:                 tpmPolicy,
		VTPMPolicy:                vtpmPolicy,
		MetaData:                  metadata,
		HasMBRefState:             r.HasMBRefState > 0,
		HasRuntimePolicy:          r.HasRuntimePolicy > 0,
		AcceptTPMHashAlgs:         acceptTPMHashAlgs,
		AcceptTPMEncryptionAlgs:   acceptTPMEncryptionAlgs,
		AcceptTPMSigningAlgs:      acceptTPMSigningAlgs,
		HashAlg:                   attestationv1alpha1.TPMHashAlg(r.HashAlg),
		EncryptionAlg:             attestationv1alpha1.TPMEncryptionAlg(r.EncryptionAlg),
		SigningAlg:                attestationv1alpha1.TPMSigningAlg(r.SigningAlg),
		VerifierID:                r.VerifierID,
		VerifierIP:                r.VerifierIP,
		VerifierPort:              r.VerifierPort,
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
type Agent struct {
	OperationalState          AgentState
	V                         []byte
	IP                        string
	Port                      uint16
	TPMPolicy                 *attestationv1alpha1.TPMPolicy
	VTPMPolicy                *attestationv1alpha1.TPMPolicy
	MetaData                  map[string]any
	HasMBRefState             bool
	HasRuntimePolicy          bool
	AcceptTPMHashAlgs         []attestationv1alpha1.TPMHashAlg
	AcceptTPMEncryptionAlgs   []attestationv1alpha1.TPMEncryptionAlg
	AcceptTPMSigningAlgs      []attestationv1alpha1.TPMSigningAlg
	HashAlg                   attestationv1alpha1.TPMHashAlg
	EncryptionAlg             attestationv1alpha1.TPMEncryptionAlg
	SigningAlg                attestationv1alpha1.TPMSigningAlg
	VerifierID                string
	VerifierIP                string
	VerifierPort              uint16
	SeverityLevel             uint16
	LastEventID               string
	AttestationCount          uint
	LastReceivedQuote         *time.Time
	LastSuccessfulAttestation *time.Time
}

/*
	{
	  "v": "3HZMmIEc6yyjfoxdCwcOgPk/6X1GuNG+tlCmNgqBM/I=",
	  "cloudagent_ip": "127.0.0.1",
	  "cloudagent_port": 9002,
	  "tpm_policy": "{\"22\": [\"0000000000000000000000000000000000000001\", \"0000000000000000000000000000000000000000000000000000000000000001\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001\", \"ffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"], \"15\": [\"0000000000000000000000000000000000000000\", \"0000000000000000000000000000000000000000000000000000000000000000\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"], \"mask\": \"0x408000\"}",
	  "vtpm_policy": "{\"23\": [\"ffffffffffffffffffffffffffffffffffffffff\", \"0000000000000000000000000000000000000000\"], \"15\": [\"0000000000000000000000000000000000000000\"], \"mask\": \"0x808000\"}",
	  "runtime_policy": "",
	  "runtime_policy_sig": "",
	  "runtime_policy_key": "",
	  "mb_refstate": "null",
	  "ima_sign_verification_keys": "[]",
	  "metadata": "{\"cert_serial\": 71906672046699268666356441515514540742724395900, \"subject\": \"/C=US/ST=MA/L=Lexington/O=MITLL/OU=53/CN=D432FBB3-D2F1-4A97-9EF7-75BD81C00000\"}",
	  "revocation_key": "-----BEGIN PRIVATE KEY----- (...) -----END PRIVATE KEY-----\n",
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
	  "supported_version": "2.0"
	}
*/
type postAgent struct {
	V                       []byte   `json:"v"`
	CloudAgentIP            string   `json:"cloudagent_ip"`
	CloudAgentPort          uint16   `json:"cloudagent_port"`
	TPMPolicy               string   `json:"tpm_policy"`
	VTPMPolicy              string   `json:"vtpm_policy"`
	RuntimePolicyName       string   `json:"runtime_policy_name"`
	RuntimePolicy           []byte   `json:"runtime_policy"`
	RuntimePolicySig        []byte   `json:"runtime_policy_sig"`
	RuntimePolicyKey        []byte   `json:"runtime_policy_key"`
	MBRefState              string   `json:"mb_refstate"`
	IMASignVerificationKeys string   `json:"ima_sign_verification_keys"`
	MetaData                string   `json:"metadata"`
	RevocationKey           string   `json:"revocation_key"`
	AcceptTPMHashAlgs       []string `json:"accept_tpm_hash_algs"`
	AcceptTPMEncryptionAlgs []string `json:"accept_tpm_encryption_algs"`
	AcceptTPMSigningAlgs    []string `json:"accept_tpm_signing_algs"`
	AK                      []byte   `json:"ak_tpm"`
	MTLSCert                string   `json:"mtls_cert"`
	SupportedVersion        string   `json:"supported_version"`
}

type AddAgentRequest struct {
	V                       []byte
	CloudAgentIP            string
	CloudAgentPort          uint16
	TPMPolicy               *attestationv1alpha1.TPMPolicy
	VTPMPolicy              *attestationv1alpha1.TPMPolicy
	RuntimePolicyName       string
	RuntimePolicy           []byte
	RuntimePolicySig        []byte
	RuntimePolicyKey        []byte
	MBRefState              map[string]any
	IMASignVerificationKeys []any
	MetaData                map[string]any
	RevocationKey           crypto.PrivateKey
	AcceptTPMHashAlgs       []attestationv1alpha1.TPMHashAlg
	AcceptTPMEncryptionAlgs []attestationv1alpha1.TPMEncryptionAlg
	AcceptTPMSigningAlgs    []attestationv1alpha1.TPMSigningAlg
	AK                      []byte
	MTLSCert                *x509.Certificate
	SupportedVersion        string
}

func toAgentRequestPostBody(r *AddAgentRequest) ([]byte, error) {
	var tpmPolicy, vtpmPolicy string
	if r.TPMPolicy != nil {
		val, err := json.Marshal(r.TPMPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to JSON encode TPM policy: %w", err)
		}
		tpmPolicy = string(val)
	}
	if r.VTPMPolicy != nil {
		val, err := json.Marshal(r.VTPMPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to JSON encode vTPM policy: %w", err)
		}
		vtpmPolicy = string(val)
	}
	mbRefState := "null"
	if r.MBRefState != nil {
		val, err := json.Marshal(r.MBRefState)
		if err != nil {
			return nil, fmt.Errorf("failed to JSON encode measured boot reference state: %w", err)
		}
		mbRefState = string(val)
	}
	imaSignVerificationKeys := "[]"
	if r.IMASignVerificationKeys != nil {
		val, err := json.Marshal(r.IMASignVerificationKeys)
		if err != nil {
			return nil, fmt.Errorf("failed to JSON encode IMA signing verification keys: %w", err)
		}
		imaSignVerificationKeys = string(val)
	}
	metadata := "{}"
	if r.MetaData != nil {
		val, err := json.Marshal(r.MetaData)
		if err != nil {
			return nil, fmt.Errorf("failed to JSON encode metadata: %w", err)
		}
		metadata = string(val)
	}

	var keyType string
	var keyBytes []byte
	switch key := r.RevocationKey.(type) {
	case *rsa.PrivateKey:
		keyType = "RSA PRIVATE KEY"
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		keyType = "EC PRIVATE KEY"
		var err error
		if keyBytes, err = x509.MarshalECPrivateKey(key); err != nil {
			return nil, fmt.Errorf("revocation key: failed to DER encode EC private key: %w", err)
		}
	default:
		return nil, fmt.Errorf("revocation key: unsupported key format %T", key)
	}
	revocationKey := pem.EncodeToMemory(&pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})

	var acceptTPMHashAlgs, acceptTPMEncryptionAlgs, acceptTPMSigningAlgs []string
	if len(r.AcceptTPMHashAlgs) > 0 {
		acceptTPMHashAlgs = make([]string, 0, len(r.AcceptTPMHashAlgs))
		for _, alg := range r.AcceptTPMHashAlgs {
			acceptTPMHashAlgs = append(acceptTPMHashAlgs, string(alg))
		}
	}
	if len(r.AcceptTPMEncryptionAlgs) > 0 {
		acceptTPMEncryptionAlgs = make([]string, 0, len(r.AcceptTPMEncryptionAlgs))
		for _, alg := range r.AcceptTPMEncryptionAlgs {
			acceptTPMEncryptionAlgs = append(acceptTPMEncryptionAlgs, string(alg))
		}
	}
	if len(r.AcceptTPMSigningAlgs) > 0 {
		acceptTPMSigningAlgs = make([]string, 0, len(r.AcceptTPMSigningAlgs))
		for _, alg := range r.AcceptTPMSigningAlgs {
			acceptTPMSigningAlgs = append(acceptTPMSigningAlgs, string(alg))
		}
	}

	var mtlsCert string
	if r.MTLSCert != nil {
		b := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: r.MTLSCert.Raw,
		}
		pemBytes := pem.EncodeToMemory(&b)
		if pemBytes == nil {
			return nil, fmt.Errorf("mtls_cert: failed to PEM encode agent server certificate")
		}
		mtlsCert = string(pemBytes)
	}

	obj := postAgent{
		V:                       r.V,
		CloudAgentIP:            r.CloudAgentIP,
		CloudAgentPort:          r.CloudAgentPort,
		TPMPolicy:               tpmPolicy,
		VTPMPolicy:              vtpmPolicy,
		RuntimePolicyName:       r.RuntimePolicyName,
		RuntimePolicy:           r.RuntimePolicy,
		RuntimePolicySig:        r.RuntimePolicySig,
		RuntimePolicyKey:        r.RuntimePolicyKey,
		MBRefState:              mbRefState,
		IMASignVerificationKeys: imaSignVerificationKeys,
		MetaData:                metadata,
		RevocationKey:           string(revocationKey),
		AcceptTPMHashAlgs:       acceptTPMHashAlgs,
		AcceptTPMEncryptionAlgs: acceptTPMEncryptionAlgs,
		AcceptTPMSigningAlgs:    acceptTPMSigningAlgs,
		AK:                      r.AK,
		MTLSCert:                mtlsCert,
		SupportedVersion:        r.SupportedVersion,
	}

	return json.Marshal(&obj)
}

type Client interface {
	GetAgent(ctx context.Context, uuid string) (*Agent, error)
	AddAgent(ctx context.Context, uuid string, agentRequest *AddAgentRequest) error
	DeleteAgent(ctx context.Context, uuid string) error
	StopAgent(ctx context.Context, uuid string) error
	ReactivateAgent(ctx context.Context, uuid string) error
	AddRuntimePolicy(ctx context.Context, name string, runtimePolicyRequest *AddRuntimePolicyRequest) error
	GetRuntimePolicy(ctx context.Context, name string) (*RuntimePolicy, error)
	DeleteRuntimePolicy(ctx context.Context, name string) error
}

type verifierClient struct {
	http              *http.Client
	url               *url.URL
	internalCtx       context.Context
	internalCtxCancel context.CancelFunc
}

var _ Client = &verifierClient{}

func New(ctx context.Context, httpClient *http.Client, verifierURL string) (Client, string, error) {
	parsedURL, err := url.Parse(verifierURL)
	if err != nil {
		return nil, "", khttp.InvalidURL(err)
	}

	internalCtx, internalCtxCancel := context.WithCancel(ctx)

	return &verifierClient{
		http:              httpClient,
		url:               parsedURL,
		internalCtx:       internalCtx,
		internalCtxCancel: internalCtxCancel,
	}, parsedURL.Host, nil
}

// GetAgent implements https://keylime.readthedocs.io/en/latest/rest_apis.html#get--v2.1-agents-agent_id-UUID
// GET /v2.1/agents/{agent_id:UUID}
func (c *verifierClient) GetAgent(ctx context.Context, uuid string) (*Agent, error) {
	u := khttp.CloneURL(c.url)
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
		return nil, khttp.NewHTTPErrorFromBody(httpResp)
	}

	// otherwise we parse it as an IPAM response
	var resp getAgent
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, err
	}

	return parseAgent(&resp.Results)
}

// DeleteAgent implements https://keylime.readthedocs.io/en/latest/rest_apis.html#delete--v2.1-agents-agent_id-UUID
// DELETE /v2.1/agents/{agent_id:UUID}
func (c *verifierClient) DeleteAgent(ctx context.Context, uuid string) error {
	u := khttp.CloneURL(c.url)
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
		return khttp.NewHTTPErrorFromBody(httpResp)
	}

	return nil
}

// ReactivateAgent implements https://keylime.readthedocs.io/en/latest/rest_apis.html#put--v2.1-agents-agent_id-UUID-reactivate
// PUT /v2.1/agents/{agent_id:UUID}/reactivate
func (c *verifierClient) ReactivateAgent(ctx context.Context, uuid string) error {
	u := khttp.CloneURL(c.url)
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
		return khttp.NewHTTPErrorFromBody(httpResp)
	}

	return nil
}

// StopAgent implements https://keylime.readthedocs.io/en/latest/rest_apis.html#put--v2.1-agents-agent_id-UUID-stop
// PUT /v2.1/agents/{agent_id:UUID}/stop
func (c *verifierClient) StopAgent(ctx context.Context, uuid string) error {
	u := khttp.CloneURL(c.url)
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
		return khttp.NewHTTPErrorFromBody(httpResp)
	}

	return nil
}

// AddAgent implements https://keylime.readthedocs.io/en/latest/rest_apis.html#post--v2.1-agents-agent_id-UUID
// POST /v2.1/agents/{agent_id:UUID}
func (c *verifierClient) AddAgent(ctx context.Context, uuid string, agentRequest *AddAgentRequest) error {
	u := khttp.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "agents", uuid)
	if err != nil {
		return err
	}
	u.Path = reqPath

	postBodyBytes, err := toAgentRequestPostBody(agentRequest)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewBuffer(postBodyBytes))
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
		return khttp.NewHTTPErrorFromBody(httpResp)
	}

	return nil
}

/*
	{
	  "tpm_policy": "{\"22\": [\"0000000000000000000000000000000000000001\", \"0000000000000000000000000000000000000000000000000000000000000001\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001\", \"ffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"], \"15\": [\"0000000000000000000000000000000000000000\", \"0000000000000000000000000000000000000000000000000000000000000000\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"], \"mask\": \"0x408000\"}",
	  "runtime_policy": "",
	  "runtime_policy_sig": "",
	  "runtime_policy_key": ""
	}
*/
type postRuntimePolicy struct {
	TPMPolicy        string `json:"tpm_policy"`
	RuntimePolicy    []byte `json:"runtime_policy"`
	RuntimePolicySig []byte `json:"runtime_policy_sig"`
	RuntimePolicyKey []byte `json:"runtime_policy_key"`
}

type AddRuntimePolicyRequest struct {
	TPMPolicy        *attestationv1alpha1.TPMPolicy
	RuntimePolicy    []byte
	RuntimePolicySig []byte
	RuntimePolicyKey []byte
}

func toRuntimePolicyRequestBody(r *AddRuntimePolicyRequest) ([]byte, error) {
	tpmPolicy := "{}"
	if r.TPMPolicy != nil {
		val, err := json.Marshal(r.TPMPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to JSON encode TPM policy: %w", err)
		}
		tpmPolicy = string(val)
	}

	obj := postRuntimePolicy{
		TPMPolicy:        tpmPolicy,
		RuntimePolicy:    r.RuntimePolicy,
		RuntimePolicySig: r.RuntimePolicySig,
		RuntimePolicyKey: r.RuntimePolicyKey,
	}

	return json.Marshal(&obj)
}

/*
	{
	  "code": 200,
	  "status": "Success",
	  "results": {
	    "name": "",
	    "tpm_policy": "{\"22\": [\"0000000000000000000000000000000000000001\", \"0000000000000000000000000000000000000000000000000000000000000001\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001\", \"ffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"], \"15\": [\"0000000000000000000000000000000000000000\", \"0000000000000000000000000000000000000000000000000000000000000000\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"], \"mask\": \"0x408000\"}",
	    "runtime_policy": ""
	  }
	}
*/
type getRuntimePolicy struct {
	Code    int                     `json:"code"`
	Status  string                  `json:"status"`
	Results getRuntimePolicyResults `json:"results"`
}

type getRuntimePolicyResults struct {
	Name          string `json:"name"`
	TPMPolicy     string `json:"tpm_policy"`
	RuntimePolicy []byte `json:"runtime_policy"`
}

type RuntimePolicy struct {
	Name          string
	TPMPolicy     *attestationv1alpha1.TPMPolicy
	RuntimePolicy []byte
}

func parseRuntimePolicy(r *getRuntimePolicyResults) (*RuntimePolicy, error) {
	var tpmPolicy *attestationv1alpha1.TPMPolicy
	if r.TPMPolicy != "" && r.TPMPolicy != "{}" && r.TPMPolicy != "null" {
		var v attestationv1alpha1.TPMPolicy
		if err := json.Unmarshal([]byte(r.TPMPolicy), &v); err != nil {
			return nil, fmt.Errorf("failed to JSON decode TPM policy '%s': %w", r.TPMPolicy, err)
		}
		tpmPolicy = &v
	}

	return &RuntimePolicy{
		Name:          r.Name,
		TPMPolicy:     tpmPolicy,
		RuntimePolicy: r.RuntimePolicy,
	}, nil
}

// AddRuntimePolicy implements https://keylime.readthedocs.io/en/latest/rest_apis.html#post--v2.1-allowlists-runtime_policy_name-string
// POST /v2.1/allowlists/{runtime_policy_name:string}
func (c *verifierClient) AddRuntimePolicy(ctx context.Context, name string, runtimePolicyRequest *AddRuntimePolicyRequest) error {
	u := khttp.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "allowlists", name)
	if err != nil {
		return err
	}
	u.Path = reqPath

	postBodyBytes, err := toRuntimePolicyRequestBody(runtimePolicyRequest)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewBuffer(postBodyBytes))
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
		return khttp.NewHTTPErrorFromBody(httpResp)
	}

	return nil
}

// DeleteRuntimePolicy implements https://keylime.readthedocs.io/en/latest/rest_apis.html#delete--v2.1-allowlist-runtime_policy_name-string
// DELETE /v2.1/allowlist/{runtime_policy_name:string}
func (c *verifierClient) DeleteRuntimePolicy(ctx context.Context, name string) error {
	u := khttp.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "allowlists", name)
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
		return khttp.NewHTTPErrorFromBody(httpResp)
	}

	return nil
}

// GetRuntimePolicy implements https://keylime.readthedocs.io/en/latest/rest_apis.html#get--v2.1-allowlists-runtime_policy_name-string
// GET /v2.1/allowlists/{runtime_policy_name:string}
func (c *verifierClient) GetRuntimePolicy(ctx context.Context, name string) (*RuntimePolicy, error) {
	u := khttp.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "allowlists", name)
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
		return nil, khttp.NewHTTPErrorFromBody(httpResp)
	}

	// otherwise we parse it as an IPAM response
	var resp getRuntimePolicy
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, err
	}

	return parseRuntimePolicy(&resp.Results)
}
