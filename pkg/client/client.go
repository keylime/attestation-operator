package client

import (
	"bufio"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
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
	AddAgentToVerifier(ctx context.Context, agent *registrar.Agent, vc verifier.Client, payload []byte) error
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
	// if this fails, then we'll just pick always 0
	r, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if r == nil {
		r = big.NewInt(0)
	}
	return names[r.Int64()]
}

func (c *Client) AddAgentToVerifier(ctx context.Context, ragent *registrar.Agent, vc verifier.Client, payload []byte) error {
	// check regcount first: if this is > 1 we can abort right here
	if ragent.RegCount > 1 {
		return fmt.Errorf("this agent has been registered more than once! This might indicate that your system is misconfigured or a malicious host is present")
	}

	// generate K,V,U
	kvu, err := generateKVU(payload)
	if err != nil {
		return fmt.Errorf("failed to generate KVU: %w", err)
	}
	authTag, err := doHMAC(kvu.K, ragent.UUID)
	if err != nil {
		return fmt.Errorf("failed to generate auth_tag using K: %w", err)
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
	// NOTE: the nonce here should be just from a select set of characters as the python implementation does it
	nonce := randomString(20)
	quote, err := ac.GetIdentityQuote(ctx, nonce)
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
	// TODO: implement

	// verify EK
	// TODO: this is such a random place to perform this check. This should probably just be part of the agent status itself.
	if !c.VerifyEK(ragent.EKCert) {
		return fmt.Errorf("failed to verify EK certificate")
	}

	// encrypt U with agent pubkey and post it to agent
	encryptedU, err := encryptU(kvu.U, quote.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt U using agent public key: %w", err)
	}
	if err := ac.SendUKey(ctx, &agent.SendUKeyRequest{
		AuthTag:      authTag,
		EncryptedKey: encryptedU,
		Payload:      kvu.Ciphertext,
	}); err != nil {
		return fmt.Errorf("failed to send U and payload to agent: %w", err)
	}

	// TODO: select policies
	tpmPolicy := &attestationv1alpha1.TPMPolicy{
		Mask: "0x0",
	}

	// add agent to verifier now
	if err := vc.AddAgent(ctx, ragent.UUID, &verifier.AddAgentRequest{
		V:                       kvu.V,
		CloudAgentIP:            ragent.IP,
		CloudAgentPort:          ragent.Port,
		TPMPolicy:               tpmPolicy,
		VTPMPolicy:              nil,
		RuntimePolicyName:       "",
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
		AK:                      ragent.AIK,
		MTLSCert:                ragent.MTLSCert,
		SupportedVersion:        agentVersion.SupportedVersion,
	}); err != nil {
		return fmt.Errorf("failed to add agent to verifier: %w", err)
	}

	// call agent verify
	// NOTE: the challenge here should be a "random" string and only contain the same set of characters that the python implementation uses
	challenge := randomString(20)
	expectedHMAC, err := doHMAC(kvu.K, challenge)
	if err != nil {
		return fmt.Errorf("failed to generate expected HMAC for agent challenge: %w", err)
	}
	agentHMAC, err := ac.Verify(ctx, challenge)
	if err != nil {
		return fmt.Errorf("failed to call agent verify: %w", err)
	}
	if expectedHMAC != agentHMAC {
		return fmt.Errorf("failed to verify agent: expected HMAC '%s' != agent HMAC '%s'", expectedHMAC, agentHMAC)
	}

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

type kvu struct {
	K          []byte
	V          []byte
	U          []byte
	Ciphertext []byte
}

func generateKVU(payload []byte) (*kvu, error) {
	k := make([]byte, 32)
	v := make([]byte, 32)
	u := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("failed to generate K: %w", err)
	}
	if _, err := rand.Read(v); err != nil {
		return nil, fmt.Errorf("failed to generate V: %w", err)
	}
	for i := range k {
		u[i] = k[i] ^ v[i]
	}
	var ciphertext []byte
	if payload != nil {
		// the IV / nonce is being set to 16 bytes on the python implementation side
		// however, it's 12 bytes in Golang by default, so we need to create a new cipher with a fixed 16 byte nonce size
		iv := make([]byte, 16)
		if _, err := rand.Read(iv); err != nil {
			return nil, fmt.Errorf("failed to generate IV for K: %w", err)
		}
		kCipherBlock, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES block cipher for K: %w", err)
		}
		aesgcm, err := cipher.NewGCMWithNonceSize(kCipherBlock, 16)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM cipher for K: %w", err)
		}
		enc := aesgcm.Seal(nil, iv, payload, nil)

		// now combine the IV, ciphertext and tag as it is done in the Python implementation
		ciphertext = make([]byte, 0, len(iv)+len(enc))
		ciphertext = append(ciphertext, iv...)
		ciphertext = append(ciphertext, enc...)
		// NOTE: in Go the Seal() function returns ciphertext with the tag appended
	}
	return &kvu{
		K:          k,
		V:          v,
		U:          u,
		Ciphertext: ciphertext,
	}, nil
}

// doHMAC generates an HMAC using K and SHA-384 and returns it as a hex string like the Python implementation
func doHMAC(k []byte, agentUUID string) (string, error) {
	mac := hmac.New(sha512.New384, k)
	if _, err := mac.Write([]byte(agentUUID)); err != nil {
		return "", fmt.Errorf("failed to write agent UUID to HMAC: %w", err)
	}
	hash := mac.Sum(nil)
	return hex.EncodeToString(hash), nil
}

// encryptU is for using the agent's public key (which must be an RSA public key for the time being) to encrypt the U key.
// The python implementation is using RSA-OAEP with SHA-1 which we need to use here as well.
func encryptU(u []byte, agentPubKey crypto.PublicKey) ([]byte, error) {
	switch pubkey := agentPubKey.(type) {
	case *rsa.PublicKey:
		// the python implementation is using RSA-OAEP and SHA-1
		// NOTE: we need to use the same here
		return rsa.EncryptOAEP(sha1.New(), rand.Reader, pubkey, u, nil)
	default:
		return nil, fmt.Errorf("public key of agent is of unsupported type %T", pubkey)
	}
}

// randomString generates a random string from the character sets of a-z, A-Z and 0-9
func randomString(length int) string {
	characters := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charactersLength := big.NewInt(int64(len(characters)))
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		randomIndex, _ := rand.Int(rand.Reader, charactersLength)
		result[i] = characters[randomIndex.Int64()]
	}

	return string(result)
}
