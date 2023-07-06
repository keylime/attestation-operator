package client

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"sort"

	"github.com/keylime/attestation-operator/pkg/client/registrar"
	"github.com/keylime/attestation-operator/pkg/client/verifier"
)

type Keylime interface {
	Registrar() registrar.Client
	Verifier(name string) (verifier.Client, bool)
	VerifierNames() []string
	RandomVerifier() string
}

type Client struct {
	http              *http.Client
	registrar         registrar.Client
	verifier          map[string]verifier.Client
	internalCtx       context.Context
	internalCtxCancel context.CancelFunc
}

// New returns a new Keylime client which has (sort of) equivalent functionality to the Keylime tenant CLI
func New(ctx context.Context, httpClient *http.Client, registrarURL string, verifierURLs []string) (Keylime, error) {
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

	return &Client{
		http:              httpClient,
		internalCtx:       internalCtx,
		internalCtxCancel: internalCtxCancel,
		registrar:         registrar,
		verifier:          vm,
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
