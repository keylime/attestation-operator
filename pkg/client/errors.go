package client

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidURL is returned from New if the provided URL is invalid
	ErrInvalidURL = errors.New("invalid registrar URL")
)

func InvalidURL(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidURL, err)
}
