package ekcert

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"reflect"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// this is a *REAL* EK certificate taken from a Lenovo laptop
var ekCert2Base64 = `MIIEBzCCAu+gAwIBAgIUfQXib2CM3tWXhf261F+67UMkfkUwDQYJKoZIhvcNAQELBQAwVTELMAkGA1UEBhMCQ0gxHjAcBgNVBAoTFVNUTWljcm9lbGVjdHJvbmljcyBOVjEmMCQGA1UEAxMdU1RNIFRQTSBFSyBJbnRlcm1lZGlhdGUgQ0EgMDYwIBcNMjIwNTE0MDc0NTI5WhgPOTk5OTEyMzEyMzU5NTlaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9FxncyTx0kQQHlpQcTOiPGumJXFJWY8MS1uw30+VxfAa1ccxb7FmAE12lXSbh/nXws1m1AWzvBeL7Pz7qIkXT3HvlovMvQ9807bbXKj75MAZXzPk2x1B/3mM1zLTSsgwRURHL5q5TBGotX22q3ZOIf6WDviqpbUeqmJo+tVG9MsnwcT07DwIX9l7h4lmiTQIoh8I1xQsaSF0HIJ2KWbDV3yXGLXFU4y6xcZUWLVRXyAmn1T/LIWh/M/8IUnX647lyWfxZJ1jlRY8ezkEXaUwyJMdIPJFiVvJ8k9niApUne50/yBLaScA0cCZUYarFMwkYL4yKNbDfQWiHPC+2Af/1AgMBAAGjggEgMIIBHDAfBgNVHSMEGDAWgBT7F9cNc0hw6RnE6OYDl15mTg5D3jBZBgNVHREBAf8ETzBNpEswSTEWMBQGBWeBBQIBDAtpZDo1MzU0NEQyMDEXMBUGBWeBBQICDAxTVDMzSFRQSEFIRTAxFjAUBgVngQUCAwwLaWQ6MDAwMTAyMDAwIgYDVR0JBBswGTAXBgVngQUCEDEOMAwMAzIuMAIBAAICAIowDAYDVR0TAQH/BAIwADAQBgNVHSUECTAHBgVngQUIATAOBgNVHQ8BAf8EBAMCBSAwSgYIKwYBBQUHAQEEPjA8MDoGCCsGAQUFBzAChi5odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL3N0bXRwbWVraW50MDYuY3J0MA0GCSqGSIb3DQEBCwUAA4IBAQAbhmG/IeZeLf9diT0/eYRIMEVd9Yc0qjmiNRcezVRRMJgaFVO/pwEq0IGu+10dvgSvUrNrSI0QbRnTO7EIsyheB0g5p7jC8b5YdUWUSRUTh5L/lNnZRKXs0MAy5xqjqB45jHd1Zdo92obN5VCHl5ecProGEopS8Y6yEOZMdupfDiX9Or2vi6Wa/XcUordrWYsVFg8kt52ltOw38OU591U5k6ZfbB0TA/A6PllCXa6RfJj5NCNAYXzYSF9qfLjw7lPpTz9chcQEJLBskMG41hey+8/VghWCtdEPp7Y1nLrZ0x2yT+yruACN5TwfulcYZmEZ86WnPGhcYaHhbdiSV0gC`

// this is an EK certificate that has been generated with swtpm
var ekCertBase64 = `MIID8jCCAlqgAwIBAgICAKQwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAxMNc3d0cG0tbG9jYWxjYTAgFw0yMzA2MDgyMjUxMjRaGA85OTk5MTIzMTIzNTk1OVowDzENMAsGA1UEAxMEazhzMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALcpL2zDbQ9c8SG+45tO2rjdkqu/23i0YCq1du604YZZxNCIhHkBMnJrKumKq/4i/yBTm+OCYQdpNWiniktX6WOA1Pr0OrgQ7M9ClA3WvL706Zs6HY3LmnpyPJSBgLO9c6tOgRaS3SvA85kG+GZIr5Zc5K5QGyB2w+a+dDE0JVIll5nRECutg1Gdz4L5OrFkjeXFTcqMsXegYaQMuF8wY2eHCP791z1C3RqnTOJqHydSwkjo1c9Nemkq07ySUmIti6Yvp2yeyEwi5lFs5f3Ad6ptAkCIN1ynvWUxi1bfwJBRiuj9oUBjIDcqKVUYar1b3DAP+nV6Q7khpxWjvt1zTWsCAwEAAaOBzDCByTAQBgNVHSUECTAHBgVngQUIATBSBgNVHREBAf8ESDBGpEQwQjEWMBQGBWeBBQIBDAtpZDowMDAwMTAxNDEQMA4GBWeBBQICDAVzd3RwbTEWMBQGBWeBBQIDDAtpZDoyMDE5MTAyMzAMBgNVHRMBAf8EAjAAMCIGA1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgCkMB8GA1UdIwQYMBaAFDZWef5azYB/0OS2WHtfAVdvQOjIMA4GA1UdDwEB/wQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAYEAk9T+VsixngyuMr31SRxKESSw66I7/YR4oy016q313mc4k21MPfOW1nVRaUJPVQbV/gFRUok3taQIokGGb0sSSPykgrkdPfm3GFim0rPICyzuK2js6yD/5FIwAGuCL4qwlbndvjd1Do4JQModZ9+nQ1CLpSITq5DpjumLzFeknIzaZWQVrz1oI69FvCfQXV4HicBFgymbP/WRR1mzs8mMi55w7gHA4iMxjG3NtdsMXEhwNB33j40KqshL1jpMXb/8CystW2eYTo3pWpQA+v7t/Jiq48VQ0d2UwxutBtn6TKMM3Rmuzjm42e1omkUcukrRjOt7yNR5KmfMhVFGO6sQRB6PWhr1g3cnIK15fbWGfjVgWB5FBfzbnPO61TPQkRRx90t9dE7p8nwo6z+wQXXaEfd4sCNp6/0B810J6q8WYVndlJG95AclZ1fRbWhHQKNQqqt29o+JnfSVuqQ5kCjPgxTpSkZG4835eGJA8YiGkI954zBAfwjI/P0JDvGSLcmV`

func getCerts() []*x509.Certificate {
	ekCert, err := base64.StdEncoding.DecodeString(ekCertBase64)
	if err != nil {
		panic(err)
	}
	ekCert2, err := base64.StdEncoding.DecodeString(ekCert2Base64)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(ekCert)
	if err != nil {
		panic(err)
	}
	cert2, err := x509.ParseCertificate(ekCert2)
	if err != nil {
		panic(err)
	}
	return []*x509.Certificate{cert, cert2}
}

func getExtensionValues(oid asn1.ObjectIdentifier) []cryptobyte.String {
	certs := getCerts()
	ret := make([]cryptobyte.String, 0, len(certs))
	for _, cert := range certs {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oid) {
				ret = append(ret, ext.Value)
			}
		}
	}
	if len(ret) != len(certs) {
		panic("certs do not have extension data")
	}
	return ret
}

func TestParseEKSDA(t *testing.T) {
	args := getExtensionValues(OIDSDA)
	tests := []struct {
		name    string
		arg     cryptobyte.String
		want    *EKSDA
		wantErr bool
	}{
		{
			name: "success1",
			arg:  args[0],
			want: &EKSDA{
				Family:   "2.0",
				Level:    0,
				Revision: 164,
			},
		},
		{
			name: "success2",
			arg:  args[1],
			want: &EKSDA{
				Family:   "2.0",
				Level:    0,
				Revision: 138,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEKSDA(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEKSDA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseEKSDA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseEKSANs(t *testing.T) {
	args := getExtensionValues(OIDSAN)
	tests := []struct {
		name    string
		arg     cryptobyte.String
		want    *EKSAN
		wantErr bool
	}{
		{
			name: "success1",
			arg:  args[0],
			want: &EKSAN{
				TPMManufacturer: &TPMManufacturer{raw: "id:" + TPMHardwareVendorIBM.HexString()},
				TPMModel:        &TPMModel{raw: "swtpm"},
				TPMVersion:      &TPMVersion{raw: "id:20191023"},
			},
		},
		{
			name: "success2",
			arg:  args[1],
			want: &EKSAN{
				TPMManufacturer: &TPMManufacturer{raw: "id:" + TPMCapabilityVendorSTMicroelectronics.HexString()},
				TPMModel:        &TPMModel{raw: "ST33HTPHAHE0"},
				TPMVersion:      &TPMVersion{raw: "id:00010200"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEKSANs(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEKSANs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseEKSANs() = %v, want %v", got, tt.want)
			}
		})
	}
}
