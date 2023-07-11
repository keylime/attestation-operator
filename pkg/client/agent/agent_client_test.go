package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func Test_agentClient_GetIdentityQuote(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name: "success",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.EscapedPath() {
				case "/v2.1/quotes/identity":
					fmt.Fprint(w, `{"code":200,"status":"Success","results":{"quote":"r/1RDR4AYACIAC2i0s/Qh8lr6ixZ8UqLLfgGVuRAJSPffNRNJdgsjWEGOABQwMTIzNDU2Nzg5MDEyMzQ1Njc4OQAAAAAQXO76AAAAGAAAAAEBIBkQIwAWNjYAAAABAAsDAAABACBtN88TUrCX4i2bSpg/g0QEJbr9e11fX9HZoA6n/EF84w==:ABQACwEAfJA+dpagHF+C0+m+gwhPwt1OrScDJTKEW/zXDDkLOIOQrL38uOYugheMwTxDzMnXAp8T+72EePY32tggf/4NINv46JcDOe3bw6WON2AS7r+CZROJeUn1/Fsjjzz6NKZQBzG1NSOLjV4ekuAO9XOIKq4mYGa+tSguaxH5YgtYzvteA+z+zZDgnL/wviuUpr4MyzFYQimCVwlYv0JExW9eap6qbZcTalh0EbhvybLCyjRmYyEwzNIl6+Ac+rHE3mszQTTHfInjUhms9k5P+Riyu+8dh4ApsH1eaeWP5tu+qAh563FfWK81yFMZhugP6vGr2hJYEj0qtY9sTMhQUn/9gw==:AQAAAAsAAwAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAgACWS4X11JDIdgbIee8i4ufcENNMA5iCTFNwz2hFuv28CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","hash_alg":"sha256","enc_alg":"rsa","sign_alg":"rsassa","pubkey":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyPLxttCRDVGQ2a/s2JjC\np5iddrnsS4meNpSiZJDp7lavS4p7fmAvcPTZFpYybEtlcDIFfTkiE7M0i8a22SHz\nkan+BFxDw4ZtrRUgHLvWVFfeaAzG7C0jZpuwvpZB7uNWH+U305ZNT+zJX/mpk/wB\npTJbW/fgnAA0PEcve011sK6vH9YCW2tQjrAdT6GIeYDNvajp4+FlspW47gtH6f5Z\nQBk5+cciUfdRb451qMT9EXNldZqIcQfAmF7y31w59Bz+OWre0mBDZmTvQJgzRAxl\nd/bdNzP8IEZcaP77VNLTwQt6omAE7AHPtG6w4dYZawl/1G9X7C8go8+BVoLtot/y\nKwIDAQAB\n-----END PUBLIC KEY-----\n"}}`)
				}
			}))
			defer ts.Close()
			url, err := url.Parse(ts.URL)
			if err != nil {
				panic(err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := &agentClient{
				http:              ts.Client(),
				url:               url,
				internalCtx:       ctx,
				internalCtxCancel: cancel,
			}
			_, err = c.GetIdentityQuote(ctx, "01234567890123456789")
			if (err != nil) != tt.wantErr {
				t.Errorf("agentClient.GetIdentityQuote() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
