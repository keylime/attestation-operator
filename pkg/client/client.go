package client

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
	"github.com/keylime/attestation-operator/pkg/client/agent"
	"github.com/keylime/attestation-operator/pkg/client/registrar"
	"github.com/keylime/attestation-operator/pkg/client/verifier"
)

const (
	defaultTPMCertStore = "/var/lib/keylime/tpm_cert_store"
)

type Keylime interface {
	Registrar() registrar.Client
	Verifier(name string) (verifier.Client, bool)
	VerifierNames() []string
	RandomVerifier() string
	AddAgentToVerifier(ctx context.Context, agent *registrar.Agent, vc verifier.Client) error
	VerifyEK(ekCert *x509.Certificate) bool
}

type Client struct {
	http              *http.Client
	registrar         registrar.Client
	verifier          map[string]verifier.Client
	internalCtx       context.Context
	internalCtxCancel context.CancelFunc
	ekRootCAPool      *x509.CertPool
	acceptedHashAlgs  attestationv1alpha1.TPMHashAlgs
	acceptedEncAlgs   attestationv1alpha1.TPMEncryptionAlgs
	acceptedSignAlgs  attestationv1alpha1.TPMSigningAlgs
}

// New returns a new Keylime client which has (sort of) equivalent functionality to the Keylime tenant CLI
func New(ctx context.Context, httpClient *http.Client, registrarURL string, verifierURLs []string, tpmCertStore string) (Keylime, error) {
	internalCtx, internalCtxCancel := context.WithCancel(ctx)

	registrar, err := registrar.New(internalCtx, httpClient, registrarURL)
	if err != nil {
		internalCtxCancel()
		return nil, err
	}

	if len(verifierURLs) == 0 {
		internalCtxCancel()
		return nil, fmt.Errorf("no verifier URLs provided")
	}
	vm := make(map[string]verifier.Client, len(verifierURLs))
	for _, verifierURL := range verifierURLs {
		verifier, host, err := verifier.New(internalCtx, httpClient, verifierURL)
		if err != nil {
			internalCtxCancel()
			return nil, err
		}
		vm[host] = verifier
	}

	certStore := defaultTPMCertStore
	if tpmCertStore != "" {
		certStore = tpmCertStore
	}
	ekRootCAPool, err := readTPMCertStore(certStore)
	if err != nil {
		internalCtxCancel()
		return nil, fmt.Errorf("reading TPM cert store: %w", err)
	}

	return &Client{
		http:              httpClient,
		internalCtx:       internalCtx,
		internalCtxCancel: internalCtxCancel,
		registrar:         registrar,
		verifier:          vm,
		ekRootCAPool:      ekRootCAPool,

		// TODO: make all of these configurable
		acceptedHashAlgs: []attestationv1alpha1.TPMHashAlg{
			attestationv1alpha1.HashAlgSHA512,
			attestationv1alpha1.HashAlgSHA384,
			attestationv1alpha1.HashAlgSHA256,
		},
		acceptedEncAlgs: []attestationv1alpha1.TPMEncryptionAlg{
			attestationv1alpha1.EncAlgECC,
			attestationv1alpha1.EncAlgRSA,
		},
		acceptedSignAlgs: []attestationv1alpha1.TPMSigningAlg{
			attestationv1alpha1.SignAlgECSCHNORR,
			attestationv1alpha1.SignAlgRSASSA,
		},
	}, nil
}

func (c *Client) Registrar() registrar.Client {
	return c.registrar
}

func (c *Client) Verifier(name string) (verifier.Client, bool) {
	v, ok := c.verifier[name]
	return v, ok
}

func (c *Client) VerifierNames() []string {
	ret := make([]string, 0, len(c.verifier))
	for name := range c.verifier {
		ret = append(ret, name)
	}
	sort.Strings(ret)
	return ret
}

func (c *Client) RandomVerifier() string {
	names := c.VerifierNames()
	n := len(names) - 1
	if n == 0 {
		return names[0]
	}
	return names[rand.Intn(n)]
}

func (c *Client) AddAgentToVerifier(ctx context.Context, ragent *registrar.Agent, vc verifier.Client) error {
	// check regcount first: if this is > 1 we can abort right here
	if ragent.RegCount > 1 {
		return fmt.Errorf("this agent has been registered more than once! This might indicate that your system is misconfigured or a malicious host is present")
	}

	// create agent client
	// TODO: create new HTTP client which has the right CAs etc for the agent set up
	ac, err := agent.New(ctx, c.http, fmt.Sprintf("https://%s:%d/", ragent.IP, ragent.Port))
	if err != nil {
		return fmt.Errorf("creating client for agent: %w", err)
	}

	// get agent version
	agentVersion, err := ac.GetVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get agent version: %w", err)
	}
	if agentVersion.SupportedVersion != "2.1" {
		return fmt.Errorf("unsupported agent version %s. Supported version: 2.1", agentVersion.SupportedVersion)
	}

	// get agent quote
	nonce := make([]byte, 20)
	if _, err := crand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	quote, err := ac.GetIdentityQuote(ctx, string(nonce))
	if err != nil {
		return fmt.Errorf("failed to get identity quote from agent: %w", err)
	}

	// check hash, encryption and signing algorithms against a list of accepted algorithms
	if !c.acceptedHashAlgs.Contains(quote.HashAlg) {
		return fmt.Errorf("unsupported hash algorithm: %s. Supported algorithms: %s", quote.HashAlg, c.acceptedHashAlgs)
	}
	if !c.acceptedEncAlgs.Contains(quote.EncryptionAlg) {
		return fmt.Errorf("unsupported encryption algorithm: %s. Supported algorithms: %s", quote.EncryptionAlg, c.acceptedEncAlgs)
	}
	if !c.acceptedSignAlgs.Contains(quote.SigningAlg) {
		return fmt.Errorf("unsupported signing algorithm: %s. Supported algorithms: %s", quote.SigningAlg, c.acceptedSignAlgs)
	}

	// verify quote

	// verify EK
	// TODO: this is such a random place to perform this check. This should probably just be part of the agent status itself.
	if !c.VerifyEK(ragent.EKCert) {
		return fmt.Errorf("failed to verify EK certificate")
	}

	// encrypt U with agent pubkey and post it to agent

	// TODO: select policies
	tpmPolicy := &attestationv1alpha1.TPMPolicy{
		Mask: "0x0",
	}

	// add agent to verifier now
	req := &verifier.AddAgentRequest{
		V:                       nil,
		CloudAgentIP:            ragent.IP,
		CloudAgentPort:          ragent.Port,
		TPMPolicy:               tpmPolicy,
		VTPMPolicy:              nil,
		RuntimePolicy:           nil,
		RuntimePolicySig:        nil,
		RuntimePolicyKey:        nil,
		MBRefState:              nil,
		IMASignVerificationKeys: nil,
		MetaData:                nil,
		RevocationKey:           nil,
		AcceptTPMHashAlgs:       c.acceptedHashAlgs,
		AcceptTPMEncryptionAlgs: c.acceptedEncAlgs,
		AcceptTPMSigningAlgs:    c.acceptedSignAlgs,
		SupportedVersion:        agentVersion.SupportedVersion,
	}
	vc.AddAgent(ctx, ragent.UUID, req)

	return nil
}

func readTPMCertStore(tpmCertStore string) (*x509.CertPool, error) {
	p := x509.NewCertPool()
	dir, err := os.Open(tpmCertStore)
	if err != nil {
		return nil, fmt.Errorf("failed to open directory %s: %w", tpmCertStore, err)
	}
	defer dir.Close()
	dirEntries, err := dir.Readdirnames(0)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory entries %s: %w", tpmCertStore, err)
	}
	for _, dirEntry := range dirEntries {
		if err := func(dirEntry string) error {
			filePath := filepath.Join(tpmCertStore, dirEntry)
			f, err := os.Open(filePath)
			if err != nil {
				return fmt.Errorf("failed to open file %s: %w", filePath, err)
			}
			defer f.Close()
			pemCerts, err := io.ReadAll(bufio.NewReader(f))
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", filePath, err)
			}
			p.AppendCertsFromPEM(pemCerts)
			return nil
		}(dirEntry); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (c *Client) VerifyEK(ekCert *x509.Certificate) bool {
	_, err := ekCert.Verify(x509.VerifyOptions{
		Roots: c.ekRootCAPool,
	})
	return err == nil
}
