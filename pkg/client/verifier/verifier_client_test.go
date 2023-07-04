// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"reflect"
	"testing"

	khttp "github.com/keylime/attestation-operator/pkg/client/http"
)

func Test_verifierClient_GetAgent(t *testing.T) {
	type args struct {
		uuid string
	}
	tests := []struct {
		name    string
		args    args
		want    *Agent
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				uuid: "81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc, err := khttp.NewKeylimeHTTPClient(
				khttp.ClientCertificate("/home/mheese/src/keylime-attestation-operator/hack/client-cert.crt", "/home/mheese/src/keylime-attestation-operator/hack/client-private.pem"),
				khttp.InsecureSkipVerify(),
			)
			if err != nil {
				panic(err)
			}
			c, _, err := New(ctx, hc, "https://127.0.0.1:8881")
			if err != nil {
				panic(err)
			}
			got, err := c.GetAgent(ctx, tt.args.uuid)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifierClient.GetAgent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("verifierClient.GetAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_verifierClient_StopAgent(t *testing.T) {
	type args struct {
		uuid string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				uuid: "81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc, err := khttp.NewKeylimeHTTPClient(
				khttp.ClientCertificate("/home/mheese/src/keylime-attestation-operator/hack/client-cert.crt", "/home/mheese/src/keylime-attestation-operator/hack/client-private.pem"),
				khttp.InsecureSkipVerify(),
			)
			if err != nil {
				panic(err)
			}
			c, _, err := New(ctx, hc, "https://127.0.0.1:8881")
			if err != nil {
				panic(err)
			}
			if err := c.StopAgent(ctx, tt.args.uuid); (err != nil) != tt.wantErr {
				t.Errorf("verifierClient.StopAgent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_verifierClient_ReactivateAgent(t *testing.T) {
	type args struct {
		uuid string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				uuid: "81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc, err := khttp.NewKeylimeHTTPClient(
				khttp.ClientCertificate("/home/mheese/src/keylime-attestation-operator/hack/client-cert.crt", "/home/mheese/src/keylime-attestation-operator/hack/client-private.pem"),
				khttp.InsecureSkipVerify(),
			)
			if err != nil {
				panic(err)
			}
			c, _, err := New(ctx, hc, "https://127.0.0.1:8881")
			if err != nil {
				panic(err)
			}
			if err := c.ReactivateAgent(ctx, tt.args.uuid); (err != nil) != tt.wantErr {
				t.Errorf("verifierClient.ReactivateAgent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_verifierClient_DeleteAgent(t *testing.T) {
	type args struct {
		uuid string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				uuid: "81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc, err := khttp.NewKeylimeHTTPClient(
				khttp.ClientCertificate("/home/mheese/src/keylime-attestation-operator/hack/client-cert.crt", "/home/mheese/src/keylime-attestation-operator/hack/client-private.pem"),
				khttp.InsecureSkipVerify(),
			)
			if err != nil {
				panic(err)
			}
			c, _, err := New(ctx, hc, "https://127.0.0.1:8881")
			if err != nil {
				panic(err)
			}
			if err := c.DeleteAgent(ctx, tt.args.uuid); (err != nil) != tt.wantErr {
				t.Errorf("verifierClient.DeleteAgent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
