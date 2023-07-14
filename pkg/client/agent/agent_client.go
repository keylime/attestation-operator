package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	khttp "github.com/keylime/attestation-operator/pkg/client/http"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
)

const (
	apiVersion = "v2.1"
)

type getVersion struct {
	Code    int     `json:"code"`
	Status  string  `json:"status"`
	Results Version `json:"results"`
}

type Version struct {
	SupportedVersion string `json:"supported_version"`
}

type getPublicKey struct {
	Code    int                 `json:"code"`
	Status  string              `json:"status"`
	Results getPublicKeyResults `json:"results"`
}

type getPublicKeyResults struct {
	PublicKey string `json:"pubkey"`
}

func parsePublicKey(r *getPublicKeyResults) (crypto.PublicKey, error) {
	var pubKey crypto.PublicKey
	if r.PublicKey != "" {
		p, _ := pem.Decode([]byte(r.PublicKey))
		if p == nil {
			return nil, fmt.Errorf("no PEM encoded data found for public key")
		}
		if p.Type != "PUBLIC KEY" && p.Type != "RSA PUBLIC KEY" {
			return nil, fmt.Errorf("unexpted PEM data type '%s' found for public key", p.Type)
		}
		// let's try this format first because it is more common these days
		// the type indicator doesn't really mean much unfortunately, we'll just try either variant
		pubKeyAny, err1 := x509.ParsePKIXPublicKey(p.Bytes)
		if err1 != nil {
			pubKeyRSA, err2 := x509.ParsePKCS1PublicKey(p.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("failed to parse public key as PKIX public key (%w) or PKCS1 public key (%w)", err1, err2)
			}
			pubKey = pubKeyRSA
		} else {
			switch key := pubKeyAny.(type) {
			case *rsa.PublicKey:
				pubKey = key
			case *ecdsa.PublicKey:
				pubKey = key
			default:
				return nil, fmt.Errorf("unsupported public key format %T", key)
			}
		}
	}

	return pubKey, nil
}

type SendVKeyRequest struct {
	EncryptedKey []byte `json:"encrypted_key"`
}

func toSendVKeyRequestBody(r *SendVKeyRequest) ([]byte, error) {
	return json.Marshal(r)
}

type SendUKeyRequest struct {
	AuthTag      string `json:"auth_tag"`
	EncryptedKey []byte `json:"encrypted_key"`
	Payload      []byte `json:"payload"`
}

func toSendUKeyRequestBody(r *SendUKeyRequest) ([]byte, error) {
	return json.Marshal(r)
}

type getVerify struct {
	Code    int              `json:"code"`
	Status  string           `json:"status"`
	Results getVerifyResults `json:"results"`
}

type getVerifyResults struct {
	HMAC string `json:"hmac"`
}

/*
	{
	  "code": 200,
	  "status": "Success",
	  "results": {
	    "quote": "r/1RDR4AYABYABPihP2yz+HcGF0vD0c4qiKt4nvSOAARURVNUAAAAAAAyQ9AAAAAAAAAAAAEgGRAjABY2NgAAAAEABAMAAAEAFCkk4YmhQECgWR+MnHqT9zftc3J8:ABQABAEAQ8IwX6Ak83zGhF6w8vOKOxsyTbxACQakYWGJaan3ewf+2O9TtiH5TLB1PXrPdhknsR/yx6OVUze9jTDvML9xkkK1ghXObCJ5gH+QX0udKfrLacm/iMds28SBtVO0rjqDIoYqGgXhH2ZhwGNDwjRCp6HquvtBe7pGEgtZlxf7Hr3wQRLO3FtliBPBR6gjOo7NC/uGsuPjdPU7c9ls29NgYSqdwShuNdRzwmZrF57umuUgF6GREFlxqLkGcbDIT1itV4zJZtI1caLVxqiH0Qv3sNqlNLsSHggkgc5S2EvNqwv/TsEZOq/leCoLtyVGYghPeGwg0RJfbe8cdyBWCQ6nOA==:AQAAAAQAAwAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAUABdJ/ntmsqy2aDi6NhKnLKz4k4uEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	    "hash_alg": "sha256",
	    "enc_alg": "rsa",
	    "sign_alg": "rsassa",
	    "pubkey": "-----BEGIN PUBLIC KEY----- (...) -----END PUBLIC KEY-----\n"
	    "boottime": 123456,
	    "ima_measurement_list": "10 367a111b682553da5340f977001689db8366056a ima-ng sha256:94c0ac6d0ff747d8f1ca7fac89101a141f3e8f6a2c710717b477a026422766d6 boot_aggregate\n",
	    "ima_measurement_list_entry": 0,
	    "mb_measurement_list": "AAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACEAAABTcGVjIElEIEV2ZW50MDMAAAAAAAACAAIBAAAACwAgAAAAAAAACAAAAAEAAAALAJailtIk8oXGe [....]"
	  }
	}
*/
type getIntegrity struct {
	Code    int                 `json:"code"`
	Status  string              `json:"status"`
	Results getIntegrityResults `json:"results"`
}

type getIntegrityResults struct {
	Quote                   string `json:"quote"`
	HashAlg                 string `json:"hash_alg"`
	EncryptionAlg           string `json:"enc_alg"`
	SigningAlg              string `json:"sign_alg"`
	PublicKey               string `json:"pubkey"`
	BootTime                uint   `json:"boottime"`
	IMAMeasurementList      string `json:"ima_measurement_list"`
	IMAMeasurementListEntry uint   `json:"ima_measurement_list_entry"`
	MBMeasurementList       []byte `json:"mb_measurement_list"`
}

type IntegrityQuote struct {
	Quote                   *Quote
	HashAlg                 attestationv1alpha1.TPMHashAlg
	EncryptionAlg           attestationv1alpha1.TPMEncryptionAlg
	SigningAlg              attestationv1alpha1.TPMSigningAlg
	PublicKey               crypto.PublicKey
	BootTime                uint
	IMAMeasurementList      string
	IMAMeasurementListEntry uint
	MBMeasurementList       []byte
}

/*
	{
	  "code": 200,
	  "status": "Success",
	  "results": {
	    "quote": "r/1RDR4AYABYABPihP2yz+HcGF0vD0c4qiKt4nvSOAARURVNUAAAAAAAyQ9AAAAAAAAAAAAEgGRAjABY2NgAAAAEABAMAAAEAFCkk4YmhQECgWR+MnHqT9zftc3J8:ABQABAEAQ8IwX6Ak83zGhF6w8vOKOxsyTbxACQakYWGJaan3ewf+2O9TtiH5TLB1PXrPdhknsR/yx6OVUze9jTDvML9xkkK1ghXObCJ5gH+QX0udKfrLacm/iMds28SBtVO0rjqDIoYqGgXhH2ZhwGNDwjRCp6HquvtBe7pGEgtZlxf7Hr3wQRLO3FtliBPBR6gjOo7NC/uGsuPjdPU7c9ls29NgYSqdwShuNdRzwmZrF57umuUgF6GREFlxqLkGcbDIT1itV4zJZtI1caLVxqiH0Qv3sNqlNLsSHggkgc5S2EvNqwv/TsEZOq/leCoLtyVGYghPeGwg0RJfbe8cdyBWCQ6nOA==:AQAAAAQAAwAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAUABdJ/ntmsqy2aDi6NhKnLKz4k4uEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	    "hash_alg": "sha256",
	    "enc_alg": "rsa",
	    "sign_alg": "rsassa",
	    "pubkey": "-----BEGIN PUBLIC KEY----- (...) -----END PUBLIC KEY-----\n"
	    "boottime": 123456
	  }
	}
*/
type getIdentity struct {
	Code    int                `json:"code"`
	Status  string             `json:"status"`
	Results getIdentityResults `json:"results"`
}

type getIdentityResults struct {
	Quote         string `json:"quote"`
	HashAlg       string `json:"hash_alg"`
	EncryptionAlg string `json:"enc_alg"`
	SigningAlg    string `json:"sign_alg"`
	PublicKey     string `json:"pubkey"`
	BootTime      uint   `json:"boottime"`
}

type IdentityQuote struct {
	Quote         *Quote
	HashAlg       attestationv1alpha1.TPMHashAlg
	EncryptionAlg attestationv1alpha1.TPMEncryptionAlg
	SigningAlg    attestationv1alpha1.TPMSigningAlg
	PublicKey     crypto.PublicKey
	BootTime      uint
}

type Quote struct {
	// TPMQuote holds TPMS_ATTEST data
	TPMQuote []byte
	// TPMSig holds TPMT_SIGNATURE data
	TPMSig []byte
	// TPMPCRs holds the TPM PCR data, can be more than just 8 PCRs. This is a data structure generated by tpm2_quote.
	TPMPCRs []byte
}

func parseIntegrityQuote(r *getIntegrityResults) (*IntegrityQuote, error) {
	var pubKey crypto.PublicKey
	if r.PublicKey != "" {
		p, _ := pem.Decode([]byte(r.PublicKey))
		if p == nil {
			return nil, fmt.Errorf("no PEM encoded data found for public key")
		}
		if p.Type != "PUBLIC KEY" && p.Type != "RSA PUBLIC KEY" {
			return nil, fmt.Errorf("unexpted PEM data type '%s' found for public key", p.Type)
		}
		// let's try this format first because it is more common these days
		// the type indicator doesn't really mean much unfortunately, we'll just try either variant
		pubKeyAny, err1 := x509.ParsePKIXPublicKey(p.Bytes)
		if err1 != nil {
			pubKeyRSA, err2 := x509.ParsePKCS1PublicKey(p.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("failed to parse public key as PKIX public key (%w) or PKCS1 public key (%w)", err1, err2)
			}
			pubKey = pubKeyRSA
		} else {
			switch key := pubKeyAny.(type) {
			case *rsa.PublicKey:
				pubKey = key
			case *ecdsa.PublicKey:
				pubKey = key
			default:
				return nil, fmt.Errorf("unsupported public key format %T", key)
			}
		}
	}

	quote, err := parseQuote(r.Quote)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TPM2 quote: %w", err)
	}

	return &IntegrityQuote{
		Quote:                   quote,
		HashAlg:                 attestationv1alpha1.TPMHashAlg(r.HashAlg),
		EncryptionAlg:           attestationv1alpha1.TPMEncryptionAlg(r.EncryptionAlg),
		SigningAlg:              attestationv1alpha1.TPMSigningAlg(r.SigningAlg),
		PublicKey:               pubKey,
		BootTime:                r.BootTime,
		IMAMeasurementList:      r.IMAMeasurementList,
		IMAMeasurementListEntry: r.IMAMeasurementListEntry,
		MBMeasurementList:       r.MBMeasurementList,
	}, nil
}

func parseIdentityQuote(r *getIdentityResults) (*IdentityQuote, error) {
	var pubKey crypto.PublicKey
	if r.PublicKey != "" {
		p, _ := pem.Decode([]byte(r.PublicKey))
		if p == nil {
			return nil, fmt.Errorf("no PEM encoded data found for public key")
		}
		if p.Type != "PUBLIC KEY" && p.Type != "RSA PUBLIC KEY" {
			return nil, fmt.Errorf("unexpted PEM data type '%s' found for public key", p.Type)
		}
		// let's try this format first because it is more common these days
		// the type indicator doesn't really mean much unfortunately, we'll just try either variant
		pubKeyAny, err1 := x509.ParsePKIXPublicKey(p.Bytes)
		if err1 != nil {
			pubKeyRSA, err2 := x509.ParsePKCS1PublicKey(p.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("failed to parse public key as PKIX public key (%w) or PKCS1 public key (%w)", err1, err2)
			}
			pubKey = pubKeyRSA
		} else {
			switch key := pubKeyAny.(type) {
			case *rsa.PublicKey:
				pubKey = key
			case *ecdsa.PublicKey:
				pubKey = key
			default:
				return nil, fmt.Errorf("unsupported public key format %T", key)
			}
		}
	}

	quote, err := parseQuote(r.Quote)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TPM2 quote: %w", err)
	}

	return &IdentityQuote{
		Quote:         quote,
		HashAlg:       attestationv1alpha1.TPMHashAlg(r.HashAlg),
		EncryptionAlg: attestationv1alpha1.TPMEncryptionAlg(r.EncryptionAlg),
		SigningAlg:    attestationv1alpha1.TPMSigningAlg(r.SigningAlg),
		PublicKey:     pubKey,
		BootTime:      r.BootTime,
	}, nil
}

// quoteRegex separates the quote fields. This is sort of just looking for base64 characters between the separators.
// NOTE: it doesn't need to be more complex, we are trying to base64 decode directly afterwards anyways which will fail if this does not work
var quoteRegex = regexp.MustCompile(`^r([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$`)

func parseQuote(str string) (*Quote, error) {
	v := quoteRegex.FindStringSubmatch(str)
	if len(v) != 4 {
		return nil, fmt.Errorf("quote regex was tampered with, it must return 3 submatches")
	}
	tpmQuote, err := base64.StdEncoding.DecodeString(v[1])
	if err != nil {
		return nil, fmt.Errorf("TPM_QUOTE field is not valid base64 data: %w", err)
	}
	tpmSig, err := base64.StdEncoding.DecodeString(v[2])
	if err != nil {
		return nil, fmt.Errorf("TPM_SIG field is not valid bas64 data: %w", err)
	}
	tpmPCRs, err := base64.StdEncoding.DecodeString(v[3])
	if err != nil {
		return nil, fmt.Errorf("TPM_PCRS field is not valid base64 data: %w", err)
	}
	return &Quote{
		TPMQuote: tpmQuote,
		TPMSig:   tpmSig,
		TPMPCRs:  tpmPCRs,
	}, nil
}

type Client interface {
	GetPublicKey(ctx context.Context) (crypto.PublicKey, error)
	GetVersion(ctx context.Context) (*Version, error)
	SendVKey(ctx context.Context, req *SendVKeyRequest) error
	SendUKey(ctx context.Context, req *SendUKeyRequest) error
	Verify(ctx context.Context, challenge string) (string, error)
	GetIntegrityQuote(ctx context.Context, nonce, mask string, partial bool, IMAMeasurmentListEntry uint) (*IntegrityQuote, error)
	GetIdentityQuote(ctx context.Context, nonce string) (*IdentityQuote, error)
}

type agentClient struct {
	http              *http.Client
	url               *url.URL
	internalCtx       context.Context
	internalCtxCancel context.CancelFunc
}

var _ Client = &agentClient{}

func New(ctx context.Context, httpClient *http.Client, agentURL string) (Client, error) {
	parsedURL, err := url.Parse(agentURL)
	if err != nil {
		return nil, khttp.InvalidURL(err)
	}

	internalCtx, internalCtxCancel := context.WithCancel(ctx)

	return &agentClient{
		http:              httpClient,
		url:               parsedURL,
		internalCtx:       internalCtx,
		internalCtxCancel: internalCtxCancel,
	}, nil
}

// GetPublicKey implements https://keylime.readthedocs.io/en/latest/rest_apis.html#get--v2.1-keys-pubkey
// GET /v2.1/keys/pubkey
func (c *agentClient) GetPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	u := khttp.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "keys", "pubkey")
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
	var resp getPublicKey
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, err
	}

	return parsePublicKey(&resp.Results)
}

// GetVersion implements https://keylime.readthedocs.io/en/latest/rest_apis.html#get--version
// GET /version
func (c *agentClient) GetVersion(ctx context.Context) (*Version, error) {
	u := khttp.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, "version")
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
	var resp getVersion
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, err
	}

	return &Version{
		SupportedVersion: resp.Results.SupportedVersion,
	}, nil
}

// SendVKey implements https://keylime.readthedocs.io/en/latest/rest_apis.html#post--v2.1-keys-vkey
// POST /v2.1/keys/vkey
func (c *agentClient) SendVKey(ctx context.Context, req *SendVKeyRequest) error {
	u := khttp.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "keys", "vkey")
	if err != nil {
		return err
	}
	u.Path = reqPath

	postBodyBytes, err := toSendVKeyRequestBody(req)
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

// SendUKey implements https://keylime.readthedocs.io/en/latest/rest_apis.html#post--v2.1-keys-ukey
// POST /v2.1/keys/ukey
func (c *agentClient) SendUKey(ctx context.Context, req *SendUKeyRequest) error {
	u := khttp.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "keys", "ukey")
	if err != nil {
		return err
	}
	u.Path = reqPath

	postBodyBytes, err := toSendUKeyRequestBody(req)
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

// Verify implements https://keylime.readthedocs.io/en/latest/rest_apis.html#get--v2.1-keys-verify
// GET /v2.1/keys/verify
func (c *agentClient) Verify(ctx context.Context, challenge string) (string, error) {
	u := khttp.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "keys", "verify")
	if err != nil {
		return "", err
	}
	u.Path = reqPath
	q := u.Query()
	q.Add("challenge", challenge)
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")

	var httpResp *http.Response
	for i := 0; i < 5; i++ {
		var err error
		httpResp, err = c.http.Do(httpReq)
		if err != nil {
			httpResp.Body.Close()
			return "", fmt.Errorf("http request retry %d: %w", i+1, err)
		}
		if httpResp.StatusCode >= 200 && httpResp.StatusCode < 299 {
			// success, break here
			break
		} else if httpResp.StatusCode == 400 {
			herr := khttp.NewHTTPErrorFromBody(httpResp).(*khttp.HTTPError)
			if herr.Err == "Bootstrap key not yet available." {
				// great, do another round
			} else {
				httpResp.Body.Close()
				return "", herr
			}
		} else {
			httpResp.Body.Close()
			return "", khttp.NewHTTPErrorFromBody(httpResp)
		}
		httpResp.Body.Close()

		// wait for 5 seconds and retry
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Second * 5):
		}
	}
	defer httpResp.Body.Close()

	// parse response
	// if it was an error, return as such
	if httpResp.StatusCode != http.StatusOK {
		return "", khttp.NewHTTPErrorFromBody(httpResp)
	}

	// otherwise we parse it as an IPAM response
	var resp getVerify
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return "", err
	}

	return resp.Results.HMAC, nil
}

// GetIntegrityQuote implements https://keylime.readthedocs.io/en/latest/rest_apis.html#get--v2.1-quotes-integrity
// GET /v2.1/quotes/integrity
func (c *agentClient) GetIntegrityQuote(ctx context.Context, nonce string, mask string, partial bool, IMAMeasurmentListEntry uint) (*IntegrityQuote, error) {
	u := khttp.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "quotes", "integrity")
	if err != nil {
		return nil, err
	}
	u.Path = reqPath
	q := u.Query()
	q.Add("nonce", nonce)
	q.Add("mask", mask)
	partialStr := "0"
	if partial {
		partialStr = "1"
	}
	q.Add("partial", partialStr)
	q.Add("ima_ml_entry", fmt.Sprintf("%d", IMAMeasurmentListEntry))
	u.RawQuery = q.Encode()

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
	var resp getIntegrity
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, err
	}

	return parseIntegrityQuote(&resp.Results)
}

// GetIntegrityQuote implements https://keylime.readthedocs.io/en/latest/rest_apis.html#get--v2.1-quotes-integrity
// GET /v2.1/quotes/integrity
func (c *agentClient) GetIdentityQuote(ctx context.Context, nonce string) (*IdentityQuote, error) {
	u := khttp.CloneURL(c.url)
	reqPath, err := url.JoinPath(u.Path, apiVersion, "quotes", "identity")
	if err != nil {
		return nil, err
	}
	u.Path = reqPath
	q := u.Query()
	q.Add("nonce", nonce)
	u.RawQuery = q.Encode()

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
	var resp getIdentity
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, err
	}

	return parseIdentityQuote(&resp.Results)
}
