package verifier

import (
	"context"
	"errors"
	"fmt"
	"net/url"
)

var (
	// ErrInvalidURL is returned from New if the provided URL is invalid
	ErrInvalidURL = errors.New("invalid verifier URL")
)

func invalidURL(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidURL, err)
}

type Client interface{}

type verifierClient struct {
	url               *url.URL
	internalCtx       context.Context
	internalCtxCancel context.CancelFunc
}

var _ Client = &verifierClient{}

func New(ctx context.Context, verifierURL string) (Client, error) {
	parsedURL, err := url.Parse(verifierURL)
	if err != nil {
		return nil, invalidURL(err)
	}

	internalCtx, internalCtxCancel := context.WithCancel(ctx)

	return &verifierClient{
		url:               parsedURL,
		internalCtx:       internalCtx,
		internalCtxCancel: internalCtxCancel,
	}, nil
}
