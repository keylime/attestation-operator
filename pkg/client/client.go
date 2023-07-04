package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/keylime/attestation-operator/pkg/client/registrar"
	"github.com/keylime/attestation-operator/pkg/client/verifier"
)

type Client struct {
	http              *http.Client
	registrar         registrar.Client
	verifier          map[string]verifier.Client
	internalCtx       context.Context
	internalCtxCancel context.CancelFunc
}

// New returns a new Keylime client which has (sort of) equivalent functionality to the Keylime tenant CLI
func New(ctx context.Context, httpClient *http.Client, registrarURL string, verifierURLs []string) (*Client, error) {
	internalCtx, internalCtxCancel := context.WithCancel(ctx)

	registrar, err := registrar.New(internalCtx, httpClient, registrarURL)
	if err != nil {
		return nil, err
	}

	if len(verifierURLs) == 0 {
		return nil, fmt.Errorf("no verifier URLs provided")
	}
	vm := make(map[string]verifier.Client, len(verifierURLs))
	for _, verifierURL := range verifierURLs {
		verifier, host, err := verifier.New(internalCtx, httpClient, verifierURL)
		if err != nil {
			return nil, err
		}
		vm[host] = verifier
	}

	return &Client{
		http:              httpClient,
		internalCtx:       internalCtx,
		internalCtxCancel: internalCtxCancel,
		registrar:         registrar,
		verifier:          vm,
	}, nil
}
