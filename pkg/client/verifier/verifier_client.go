// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	http              *http.Client
	url               *url.URL
	internalCtx       context.Context
	internalCtxCancel context.CancelFunc
}

var _ Client = &verifierClient{}

func New(ctx context.Context, httpClient *http.Client, verifierURL string) (Client, error) {
	parsedURL, err := url.Parse(verifierURL)
	if err != nil {
		return nil, invalidURL(err)
	}

	internalCtx, internalCtxCancel := context.WithCancel(ctx)

	return &verifierClient{
		http:              httpClient,
		url:               parsedURL,
		internalCtx:       internalCtx,
		internalCtxCancel: internalCtxCancel,
	}, nil
}
