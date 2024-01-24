// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package registrar

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	khttp "github.com/keylime/attestation-operator/pkg/client/http"
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
			hc, err := khttp.NewKeylimeHTTPClient(
				khttp.ClientCertificate("/home/mheese/src/keylime-attestation-operator/hack/client-cert.crt", "/home/mheese/src/keylime-attestation-operator/hack/client-private.pem"),
				khttp.InsecureSkipVerify(),
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
		wantErr bool
	}{
		{
			name: "success1",
			args: args{
				uuid: "a25bd3603bd6d838824fcb9c7ba835bf4f7604609b4d5019bba6d7628cebf6c8",
			},
		},
		{
			name: "success2",
			args: args{
				uuid: "81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.EscapedPath() {
				case "/v2.1/agents/81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c":
					fmt.Fprint(w, `{"code": 200, "status": "Success", "results": {"aik_tpm": "ARgAAQALAAUAcgAAABAAFAALCAAAAAAAAQDKGVbTwoknCTFvEuDWQJ2w7AhHzXXjn0AKntOsfc8KR9Rp2b6Oh0AY0HxULflEWdxqgST7P3CvyQVuP43dd7nxnyPI68oG3ujhcLiL/ZjrAux7R6Q7IXoEjryq+TjrxZf10i0RO84GOkv3A3vmt4gszB6MrWa47ekttP1Ay0XC8Ll90EouGJ+kktLw6gectq2g0ajSM2BLUtjGM0LTIb6b/47d3SoqCkQqloJqhYCl1VC299P7d6UZXLFluvZ4SCPBzDXnu2qAqEFaufJUzfO+glwdn/07LzFwPe4tFA6YDQ3HhnIGzdqBoxtEGwlCKCZKLBqcyRCA2Mv784aPjtE5", "ek_tpm": "AToAAQALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAEMAEAgAAAAAAAEAtykvbMNtD1zxIb7jm07auN2Sq7/beLRgKrV27rThhlnE0IiEeQEycmsq6Yqr/iL/IFOb44JhB2k1aKeKS1fpY4DU+vQ6uBDsz0KUDda8vvTpmzodjcuaenI8lIGAs71zq06BFpLdK8DzmQb4ZkivllzkrlAbIHbD5r50MTQlUiWXmdEQK62DUZ3Pgvk6sWSN5cVNyoyxd6BhpAy4XzBjZ4cI/v3XPULdGqdM4mofJ1LCSOjVz016aSrTvJJSYi2Lpi+nbJ7ITCLmUWzl/cB3qm0CQIg3XKe9ZTGLVt/AkFGK6P2hQGMgNyopVRhqvVvcMA/6dXpDuSGnFaO+3XNNaw==", "ekcert": "MIID8jCCAlqgAwIBAgICAKQwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAxMNc3d0cG0tbG9jYWxjYTAgFw0yMzA2MDgyMjUxMjRaGA85OTk5MTIzMTIzNTk1OVowDzENMAsGA1UEAxMEazhzMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALcpL2zDbQ9c8SG+45tO2rjdkqu/23i0YCq1du604YZZxNCIhHkBMnJrKumKq/4i/yBTm+OCYQdpNWiniktX6WOA1Pr0OrgQ7M9ClA3WvL706Zs6HY3LmnpyPJSBgLO9c6tOgRaS3SvA85kG+GZIr5Zc5K5QGyB2w+a+dDE0JVIll5nRECutg1Gdz4L5OrFkjeXFTcqMsXegYaQMuF8wY2eHCP791z1C3RqnTOJqHydSwkjo1c9Nemkq07ySUmIti6Yvp2yeyEwi5lFs5f3Ad6ptAkCIN1ynvWUxi1bfwJBRiuj9oUBjIDcqKVUYar1b3DAP+nV6Q7khpxWjvt1zTWsCAwEAAaOBzDCByTAQBgNVHSUECTAHBgVngQUIATBSBgNVHREBAf8ESDBGpEQwQjEWMBQGBWeBBQIBDAtpZDowMDAwMTAxNDEQMA4GBWeBBQICDAVzd3RwbTEWMBQGBWeBBQIDDAtpZDoyMDE5MTAyMzAMBgNVHRMBAf8EAjAAMCIGA1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgCkMB8GA1UdIwQYMBaAFDZWef5azYB/0OS2WHtfAVdvQOjIMA4GA1UdDwEB/wQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAYEAk9T+VsixngyuMr31SRxKESSw66I7/YR4oy016q313mc4k21MPfOW1nVRaUJPVQbV/gFRUok3taQIokGGb0sSSPykgrkdPfm3GFim0rPICyzuK2js6yD/5FIwAGuCL4qwlbndvjd1Do4JQModZ9+nQ1CLpSITq5DpjumLzFeknIzaZWQVrz1oI69FvCfQXV4HicBFgymbP/WRR1mzs8mMi55w7gHA4iMxjG3NtdsMXEhwNB33j40KqshL1jpMXb/8CystW2eYTo3pWpQA+v7t/Jiq48VQ0d2UwxutBtn6TKMM3Rmuzjm42e1omkUcukrRjOt7yNR5KmfMhVFGO6sQRB6PWhr1g3cnIK15fbWGfjVgWB5FBfzbnPO61TPQkRRx90t9dE7p8nwo6z+wQXXaEfd4sCNp6/0B810J6q8WYVndlJG95AclZ1fRbWhHQKNQqqt29o+JnfSVuqQ5kCjPgxTpSkZG4835eGJA8YiGkI954zBAfwjI/P0JDvGSLcmV", "mtls_cert": "-----BEGIN CERTIFICATE-----\nMIIDrzCCApegAwIBAgIBBDANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJVUzEm\nMCQGA1UEAwwdS2V5bGltZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxCzAJBgNVBAgM\nAk1BMRIwEAYDVQQHDAlMZXhpbmd0b24xDjAMBgNVBAoMBU1JVExMMQswCQYDVQQL\nDAI1MzAeFw0yMzA3MTEyMDI4MDNaFw0yNDA3MTAyMDI4MDNaMGIxCzAJBgNVBAYT\nAlVTMRUwEwYDVQQDDAwxMC4yNDQuMC4xNjUxCzAJBgNVBAgMAk1BMRIwEAYDVQQH\nDAlMZXhpbmd0b24xDjAMBgNVBAoMBU1JVExMMQswCQYDVQQLDAI1MzCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMjy8bbQkQ1RkNmv7NiYwqeYnXa57EuJ\nnjaUomSQ6e5Wr0uKe35gL3D02RaWMmxLZXAyBX05IhOzNIvGttkh85Gp/gRcQ8OG\nba0VIBy71lRX3mgMxuwtI2absL6WQe7jVh/lN9OWTU/syV/5qZP8AaUyW1v34JwA\nNDxHL3tNdbCurx/WAltrUI6wHU+hiHmAzb2o6ePhZbKVuO4LR+n+WUAZOfnHIlH3\nUW+OdajE/RFzZXWaiHEHwJhe8t9cOfQc/jlq3tJgQ2Zk70CYM0QMZXf23Tcz/CBG\nXGj++1TS08ELeqJgBOwBz7RusOHWGWsJf9RvV+wvIKPPgVaC7aLf8isCAwEAAaNf\nMF0wFwYJYIZIAYb4QgENBApTU0wgU2VydmVyMBcGA1UdEQQQMA6CDDEwLjI0NC4w\nLjE2NTApBgNVHR8EIjAgMB6gHKAahhhodHRwOi8vbG9jYWxob3N0L2NybC5wZW0w\nDQYJKoZIhvcNAQELBQADggEBAGelewucjNY0UkZUg4/uI2R6JHDCx1BgPE8bUvDO\nuCSSZUA1uJH6jwpazvjJ+37gC+2Ft+w8+Q2eYm0EYqJ9rcyspg3+d7gzkq0aTR4f\ncBpkiabDavnVmZymavXl/CN7kBxfE0SVlQLIIDoXu3xd8brurTJirop7GFCsEZgg\nmH6fTVmTmaejtaVhWpa5nzfOJfQRD8afVoFlSeEhmHU9A72QG/GUMBKgc/+HdCVT\nPH84SLua20jZCc91B6f/GvRoA16il31uphgP12iZ2mHYXuMIgF2/fAlSeAUuj44+\ngNZi77gtTs4f+zsX4PoZFRWaWcsBoiyH7yDU+jR28SmkwaM=\n-----END CERTIFICATE-----\n", "ip": "10.244.0.165", "port": 9002, "regcount": 1}}`)
				case "/v2.1/agents/a25bd3603bd6d838824fcb9c7ba835bf4f7604609b4d5019bba6d7628cebf6c8":
					fmt.Fprint(w, `{"code": 200, "status": "Success", "results": {"aik_tpm": "ARgAAQALAAUAcgAAABAAFAALCAAAAAAAAQDJoSPd1GznapXuI8snmNpEllOdt6B8gh9bfN39N3F9swQxCfLbh4yG0Hnvj+dWHru6wNrCnWoCnS5NyRWmCgkB3bo4feaUlL9D7UqENtr5+ho7/qIB+JVR7rtrOFKKhWcf6O7nhlhPYTg8SSow3ZO9LpEGkJ2LYQ0fsDxgxVfpiuJ/C/mGvhSQvesYjjE+k1rScwJzaMD/Ck1z8bT4C/KUo+aACGg5gdeVyCt4IFutsbsekL1XiSJxkTjYNtiz68dweUV5EIQyVl73LqVSsh3dIr9c8e+VzmtWnd4I8r6RC+BcH/M2PNp5vDhfQLDaE5SGwuaJ0hSocu/eDXhi/x/3", "ek_tpm": "AToAAQALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAEMAEAgAAAAAAAEAtlndod3psM8p/Yp56kQkf6pTJshygkhQt1hrTmFKF/QO9Fiy17N9+XfhI4k5doOT85OklJEZvWNLhSdV/ppCrbm/aMvCGpUScn3eFiQg2PB2LQsHZo/DlUjAxcCtAtcUVrG0lgP4qxrNNZDm5Hvr61XqkL0fXel57dWElPx99DJ54b3SBNa/QIIhOKcN+YeVH8XiWpd4rC6q3xq0DV/AkwSIHmYkYXyS1KBfjV+u7yBvraEZ8nXHlS4OSc7FMIHjW1amwjigqnrHsLQVD9eXkBMcPZK9nqaa3uRWgnbFcrTEX/3+TsURbqrlQ2lc9Vqfs+YZYEVzH1ZugXKKQ4LYOw==", "ekcert": "MIID8jCCAlqgAwIBAgICAKcwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAxMNc3d0cG0tbG9jYWxjYTAgFw0yMzA2MTUyMDM4NTBaGA85OTk5MTIzMTIzNTk1OVowDzENMAsGA1UEAxMEazhzMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALZZ3aHd6bDPKf2KeepEJH+qUybIcoJIULdYa05hShf0DvRYstezffl34SOJOXaDk/OTpJSRGb1jS4UnVf6aQq25v2jLwhqVEnJ93hYkINjwdi0LB2aPw5VIwMXArQLXFFaxtJYD+KsazTWQ5uR76+tV6pC9H13pee3VhJT8ffQyeeG90gTWv0CCITinDfmHlR/F4lqXeKwuqt8atA1fwJMEiB5mJGF8ktSgX41fru8gb62hGfJ1x5UuDknOxTCB41tWpsI4oKp6x7C0FQ/Xl5ATHD2SvZ6mmt7kVoJ2xXK0xF/9/k7FEW6q5UNpXPVan7PmGWBFcx9WboFyikOC2DsCAwEAAaOBzDCByTAQBgNVHSUECTAHBgVngQUIATBSBgNVHREBAf8ESDBGpEQwQjEWMBQGBWeBBQIBDAtpZDowMDAwMTAxNDEQMA4GBWeBBQICDAVzd3RwbTEWMBQGBWeBBQIDDAtpZDoyMDE5MTAyMzAMBgNVHRMBAf8EAjAAMCIGA1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgCkMB8GA1UdIwQYMBaAFDZWef5azYB/0OS2WHtfAVdvQOjIMA4GA1UdDwEB/wQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAYEADcfT7+wR7fILfXJR1xTaRzdi2mqthaew/6+X2FSlz8Z/4rex9gyNTHjtqBygk04iMUv2m9Fb2XkCNtc0lat9ohzM2kja9aaaEC6fRVEfd1EYZp2CoWPkdVTRG8uabtb1OUAcjkzbkG7DKQpIdJrBOgakR5SSUZ3QqAGzbcZllR/BmbFtPAs6Dw1RBlleVXWvJmgmETpA2Jltf3AVA/MtN3sOCdWhm2/IQJIluf45OpiY+8KajwukvtrzyImaBVGVGEwgn74Ec9gxxcA6YNcE2TYU8w7dlXC9itiOg453SJktsZs1QX5AJw2NWhb38PMOsXlqZSf3akDQLj5/OyydsZ5JposRjEGLfCPdmi/xFBxUXEJ42nbHLkwr1WURDHzsnSnRU5sHeDBOExvIBeJMFJjgSuOCrUtCLsoiR/Ngf0xjOJtQN6Qx5f2vKSRcC8Empd960kBNL6qxuATPJE6RwA/GDanEMCceappuWsztD0l8Prq9Od0POf4/lEeaXs2T", "mtls_cert": "-----BEGIN CERTIFICATE-----\nMIIDrzCCApegAwIBAgIBBDANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJVUzEm\nMCQGA1UEAwwdS2V5bGltZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxCzAJBgNVBAgM\nAk1BMRIwEAYDVQQHDAlMZXhpbmd0b24xDjAMBgNVBAoMBU1JVExMMQswCQYDVQQL\nDAI1MzAeFw0yMzA3MTEyMDI4MDVaFw0yNDA3MTAyMDI4MDVaMGIxCzAJBgNVBAYT\nAlVTMRUwEwYDVQQDDAwxMC4yNDQuMS4xNDYxCzAJBgNVBAgMAk1BMRIwEAYDVQQH\nDAlMZXhpbmd0b24xDjAMBgNVBAoMBU1JVExMMQswCQYDVQQLDAI1MzCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBALuIpKV5LPTzvoOuyHv48B8ZHlhs4vwm\nnnie9NnSpLTquD8xvvtMnAjuHNvpvv/g69i9BWxRV4ItR44EmLnkfnHp3mY4ytMB\nos2s1k/KFTDmC5bK6XY5AiTROixt3pkiHfSDoHEtWDyJB4xy4eywLpGqNOUu/62y\n+dVTwVGw9O6Ac7E1JyY9JpEqyZ9OxKevzy0RJ29WLYZd+OLGnabRReUsGy53tlaJ\n/lJtrJgXtrHhXnVnIVNhjXCcj/OvOPH7sL4qjUmkndz6/BdxKeNDxLtCCCtSNLrb\nPKQut2rXwrfKOSMAaQRyKV5FnP7CkE1WkYlhcxKbyWfxvCaA/fz/vBUCAwEAAaNf\nMF0wFwYJYIZIAYb4QgENBApTU0wgU2VydmVyMBcGA1UdEQQQMA6CDDEwLjI0NC4x\nLjE0NjApBgNVHR8EIjAgMB6gHKAahhhodHRwOi8vbG9jYWxob3N0L2NybC5wZW0w\nDQYJKoZIhvcNAQELBQADggEBAFM5Jomn7GR4x6qPRdNV3rOxQDUUa+Vm46RAQSPg\nx2s6dSEMDnaaPWTwCtzG8JTLJwQZU/O7tCJeMDhgSsTvvsyC3+e9sb979a5RdBfM\nuKPnS4lO4X8vV6SQoELB/ekWcS1oUJ5FvoZdYFXFcXOgl8mk0J35l2Mc1bjpL1Mq\nMKqZ4mdH1/ahzDywjxJTQjrurslwoQi5ivu4k+W6GoO0EBOL3HA8pqQrszij380s\nlToXI9Yy61Jz+hpvm6NGub2mC2iWNrzRN0Wvt6TmAYcney+ppRXyZv/IKvM+/kGm\nXU048XB980OZ70ZCee7HXc+UMvcDY+8vghxc746kMazV4e4=\n-----END CERTIFICATE-----\n", "ip": "10.244.1.146", "port": 9002, "regcount": 1}}`)
				}
			}))
			defer ts.Close()
			url, err := url.Parse(ts.URL)
			if err != nil {
				panic(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := &registrarClient{
				http:              ts.Client(),
				url:               url,
				internalCtx:       ctx,
				internalCtxCancel: cancel,
			}

			_, err = c.GetAgent(ctx, tt.args.uuid)
			if (err != nil) != tt.wantErr {
				t.Errorf("registrarClient.GetAgent() error = %v, wantErr %v", err, tt.wantErr)
				return
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
			hc, err := khttp.NewKeylimeHTTPClient(
				khttp.ClientCertificate("/home/mheese/src/keylime-attestation-operator/hack/client-cert.crt", "/home/mheese/src/keylime-attestation-operator/hack/client-private.pem"),
				khttp.InsecureSkipVerify(),
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
