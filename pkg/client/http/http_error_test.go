// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"net/http"
	"testing"
)

func TestIsNotFoundError(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "not found error",
			args: args{
				err: &HTTPError{
					StatusCode: http.StatusNotFound,
				},
			},
			want: true,
		},
		{
			name: "internal server error",
			args: args{
				err: &HTTPError{
					StatusCode: http.StatusInternalServerError,
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFoundError(tt.args.err); got != tt.want {
				t.Errorf("IsNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}
