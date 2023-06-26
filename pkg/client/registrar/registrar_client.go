package registrar

import (
	"context"
	"errors"
	"fmt"
	"net/url"
)

var (
	// ErrInvalidURL is returned from New if the provided URL is invalid
	ErrInvalidURL = errors.New("invalid registrar URL")
)

func invalidURL(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidURL, err)
}

type Client interface{}

type registrarClient struct {
	url               *url.URL
	internalCtx       context.Context
	internalCtxCancel context.CancelFunc
}

var _ Client = &registrarClient{}

func New(ctx context.Context, registrarURL string) (Client, error) {
	parsedURL, err := url.Parse(registrarURL)
	if err != nil {
		return nil, invalidURL(err)
	}

	internalCtx, internalCtxCancel := context.WithCancel(ctx)

	return &registrarClient{
		url:               parsedURL,
		internalCtx:       internalCtx,
		internalCtxCancel: internalCtxCancel,
	}, nil
}
