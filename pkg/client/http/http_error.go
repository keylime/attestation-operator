// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// HTTPError is the error structure as it is always being returned for any unsuccessful HTTP requests
// by the seeder. Let's define it once here, and reuse it where we need it.
type HTTPError struct {
	StatusCode int    `json:"-"`
	ReqID      string `json:"request_id,omitempty"`
	Err        string `json:"status"`
}

// Error implements error
func (e *HTTPError) Error() string {
	reqID := ""
	if e.ReqID != "" {
		reqID = fmt.Sprintf(" (ReqID: %s)", e.ReqID)
	}
	return fmt.Sprintf("HTTP %d%s: %s", e.StatusCode, reqID, e.Err)
}

func (e *HTTPError) Is(target error) bool {
	_, ok := target.(*HTTPError) //nolint: errorlint
	return ok
}

func NewHTTPErrorFromBody(resp *http.Response) error {
	var v HTTPError
	reqID := "<unknown>"
	if headerReqID := resp.Header.Get("Request-ID"); headerReqID != "" {
		reqID = headerReqID
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return &HTTPError{
			StatusCode: resp.StatusCode,
			ReqID:      reqID,
			Err:        fmt.Sprintf("failed to parse HTTP error from body: %s", err),
		}
	}
	if v.ReqID == "" {
		v.ReqID = reqID
	}
	v.StatusCode = resp.StatusCode
	return &v
}

func NewHTTPErrorf(resp *http.Response, format string, args ...any) error {
	reqID := "<unknown>"
	if headerReqID := resp.Header.Get("Request-ID"); headerReqID != "" {
		reqID = headerReqID
	}
	return &HTTPError{
		StatusCode: resp.StatusCode,
		ReqID:      reqID,
		Err:        fmt.Sprintf(format, args...),
	}
}

func IsNotFoundError(err error) bool {
	var httpErr *HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == 404
}
