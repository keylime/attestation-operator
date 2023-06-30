// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package registrar

import (
	"context"
	"reflect"
	"testing"

	"github.com/keylime/attestation-operator/pkg/client"
)

func Test_registrarClient_ListAgents(t *testing.T) {
	tests := []struct {
		name    string
		want    []string
		wantErr bool
	}{
		{
			name: "success",
			want: []string{"81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c", "a25bd3603bd6d838824fcb9c7ba835bf4f7604609b4d5019bba6d7628cebf6c8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc, err := client.NewKeylimeHTTPClient(
				client.ClientCertificate("/home/mheese/src/keylime-attestation-operator/hack/client-cert.crt", "/home/mheese/src/keylime-attestation-operator/hack/client-private.pem"),
				client.InsecureSkipVerify(),
			)
			if err != nil {
				panic(err)
			}
			c, err := New(ctx, hc, "https://127.0.0.1:8891")
			if err != nil {
				panic(err)
			}
			got, err := c.ListAgents(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("registrarClient.ListAgents() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("registrarClient.ListAgents() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_registrarClient_GetAgent(t *testing.T) {
	type args struct {
		uuid string
	}
	tests := []struct {
		name    string
		args    args
		want    *RegistrarAgent
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				uuid: "a25bd3603bd6d838824fcb9c7ba835bf4f7604609b4d5019bba6d7628cebf6c8",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc, err := client.NewKeylimeHTTPClient(
				client.ClientCertificate("/home/mheese/src/keylime-attestation-operator/hack/client-cert.crt", "/home/mheese/src/keylime-attestation-operator/hack/client-private.pem"),
				client.InsecureSkipVerify(),
			)
			if err != nil {
				panic(err)
			}
			c, err := New(ctx, hc, "https://127.0.0.1:8891")
			if err != nil {
				panic(err)
			}
			got, err := c.GetAgent(ctx, tt.args.uuid)
			if (err != nil) != tt.wantErr {
				t.Errorf("registrarClient.GetAgent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("registrarClient.GetAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_registrarClient_DeleteAgent(t *testing.T) {
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
				uuid: "a25bd3603bd6d838824fcb9c7ba835bf4f7604609b4d5019bba6d7628cebf6c8",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc, err := client.NewKeylimeHTTPClient(
				client.ClientCertificate("/home/mheese/src/keylime-attestation-operator/hack/client-cert.crt", "/home/mheese/src/keylime-attestation-operator/hack/client-private.pem"),
				client.InsecureSkipVerify(),
			)
			if err != nil {
				panic(err)
			}
			c, err := New(ctx, hc, "https://127.0.0.1:8891")
			if err != nil {
				panic(err)
			}
			if err := c.DeleteAgent(ctx, tt.args.uuid); (err != nil) != tt.wantErr {
				t.Errorf("registrarClient.DeleteAgent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
