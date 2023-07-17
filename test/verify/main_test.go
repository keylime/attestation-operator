package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestVerify(t *testing.T) {
	ekCert2Base64 := `MIIEBzCCAu+gAwIBAgIUfQXib2CM3tWXhf261F+67UMkfkUwDQYJKoZIhvcNAQELBQAwVTELMAkGA1UEBhMCQ0gxHjAcBgNVBAoTFVNUTWljcm9lbGVjdHJvbmljcyBOVjEmMCQGA1UEAxMdU1RNIFRQTSBFSyBJbnRlcm1lZGlhdGUgQ0EgMDYwIBcNMjIwNTE0MDc0NTI5WhgPOTk5OTEyMzEyMzU5NTlaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9FxncyTx0kQQHlpQcTOiPGumJXFJWY8MS1uw30+VxfAa1ccxb7FmAE12lXSbh/nXws1m1AWzvBeL7Pz7qIkXT3HvlovMvQ9807bbXKj75MAZXzPk2x1B/3mM1zLTSsgwRURHL5q5TBGotX22q3ZOIf6WDviqpbUeqmJo+tVG9MsnwcT07DwIX9l7h4lmiTQIoh8I1xQsaSF0HIJ2KWbDV3yXGLXFU4y6xcZUWLVRXyAmn1T/LIWh/M/8IUnX647lyWfxZJ1jlRY8ezkEXaUwyJMdIPJFiVvJ8k9niApUne50/yBLaScA0cCZUYarFMwkYL4yKNbDfQWiHPC+2Af/1AgMBAAGjggEgMIIBHDAfBgNVHSMEGDAWgBT7F9cNc0hw6RnE6OYDl15mTg5D3jBZBgNVHREBAf8ETzBNpEswSTEWMBQGBWeBBQIBDAtpZDo1MzU0NEQyMDEXMBUGBWeBBQICDAxTVDMzSFRQSEFIRTAxFjAUBgVngQUCAwwLaWQ6MDAwMTAyMDAwIgYDVR0JBBswGTAXBgVngQUCEDEOMAwMAzIuMAIBAAICAIowDAYDVR0TAQH/BAIwADAQBgNVHSUECTAHBgVngQUIATAOBgNVHQ8BAf8EBAMCBSAwSgYIKwYBBQUHAQEEPjA8MDoGCCsGAQUFBzAChi5odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL3N0bXRwbWVraW50MDYuY3J0MA0GCSqGSIb3DQEBCwUAA4IBAQAbhmG/IeZeLf9diT0/eYRIMEVd9Yc0qjmiNRcezVRRMJgaFVO/pwEq0IGu+10dvgSvUrNrSI0QbRnTO7EIsyheB0g5p7jC8b5YdUWUSRUTh5L/lNnZRKXs0MAy5xqjqB45jHd1Zdo92obN5VCHl5ecProGEopS8Y6yEOZMdupfDiX9Or2vi6Wa/XcUordrWYsVFg8kt52ltOw38OU591U5k6ZfbB0TA/A6PllCXa6RfJj5NCNAYXzYSF9qfLjw7lPpTz9chcQEJLBskMG41hey+8/VghWCtdEPp7Y1nLrZ0x2yT+yruACN5TwfulcYZmEZ86WnPGhcYaHhbdiSV0gC`
	ekCertBase64 := `MIID8jCCAlqgAwIBAgICAKQwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAxMNc3d0cG0tbG9jYWxjYTAgFw0yMzA2MDgyMjUxMjRaGA85OTk5MTIzMTIzNTk1OVowDzENMAsGA1UEAxMEazhzMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALcpL2zDbQ9c8SG+45tO2rjdkqu/23i0YCq1du604YZZxNCIhHkBMnJrKumKq/4i/yBTm+OCYQdpNWiniktX6WOA1Pr0OrgQ7M9ClA3WvL706Zs6HY3LmnpyPJSBgLO9c6tOgRaS3SvA85kG+GZIr5Zc5K5QGyB2w+a+dDE0JVIll5nRECutg1Gdz4L5OrFkjeXFTcqMsXegYaQMuF8wY2eHCP791z1C3RqnTOJqHydSwkjo1c9Nemkq07ySUmIti6Yvp2yeyEwi5lFs5f3Ad6ptAkCIN1ynvWUxi1bfwJBRiuj9oUBjIDcqKVUYar1b3DAP+nV6Q7khpxWjvt1zTWsCAwEAAaOBzDCByTAQBgNVHSUECTAHBgVngQUIATBSBgNVHREBAf8ESDBGpEQwQjEWMBQGBWeBBQIBDAtpZDowMDAwMTAxNDEQMA4GBWeBBQICDAVzd3RwbTEWMBQGBWeBBQIDDAtpZDoyMDE5MTAyMzAMBgNVHRMBAf8EAjAAMCIGA1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgCkMB8GA1UdIwQYMBaAFDZWef5azYB/0OS2WHtfAVdvQOjIMA4GA1UdDwEB/wQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAYEAk9T+VsixngyuMr31SRxKESSw66I7/YR4oy016q313mc4k21MPfOW1nVRaUJPVQbV/gFRUok3taQIokGGb0sSSPykgrkdPfm3GFim0rPICyzuK2js6yD/5FIwAGuCL4qwlbndvjd1Do4JQModZ9+nQ1CLpSITq5DpjumLzFeknIzaZWQVrz1oI69FvCfQXV4HicBFgymbP/WRR1mzs8mMi55w7gHA4iMxjG3NtdsMXEhwNB33j40KqshL1jpMXb/8CystW2eYTo3pWpQA+v7t/Jiq48VQ0d2UwxutBtn6TKMM3Rmuzjm42e1omkUcukrRjOt7yNR5KmfMhVFGO6sQRB6PWhr1g3cnIK15fbWGfjVgWB5FBfzbnPO61TPQkRRx90t9dE7p8nwo6z+wQXXaEfd4sCNp6/0B810J6q8WYVndlJG95AclZ1fRbWhHQKNQqqt29o+JnfSVuqQ5kCjPgxTpSkZG4835eGJA8YiGkI954zBAfwjI/P0JDvGSLcmV`
	cas := `-----BEGIN CERTIFICATE-----
MIIEKjCCApKgAwIBAgIUZxt5GsFtYoDbsZHsILYXHHdWOvEwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAxMUc3d0cG0tbG9jYWxjYS1yb290Y2EwIBcNMjMwNDI3MjMx
OTU1WhgPOTk5OTEyMzEyMzU5NTlaMBgxFjAUBgNVBAMTDXN3dHBtLWxvY2FsY2Ew
ggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDjopxfC56L1D6h8vB9Ctbh
GvEndLm9U8/isnsaK8DHeNTcmJ+2Gj7oY4OHLbDs3QOblTmsHGnKX0Fxun099VkD
kepH6nZ8FNNb/XBg6XXdahXLHe+gHc2MKTTz6S/Elp28y3AYT0B3frJUsinHFS78
cO+bFu2Dn5LbcMxQ+KETX8WC6Gs6OsDVtHaZPq7QmlfXVfQAXiQ8YXsOU8Ea4R9v
G7uxoFvjsZWLf8B0P8UvHFeTepCw3276VzmWcj0S0V1xrSPSfwORtuAe/Lqk+9eG
N0OrJmGv+F3vvvLVD5tsR6RtPaEZonmyfe14HbK7oDB5nn2DALJUrpWuXbihConp
VVLP+MMmdLSZalYuaCRK+tHD90+ZSkwi5cbW3KwYF3fkWvnOOfs7fGQCTlh1CMiJ
H1oBMrKVTyxPf5ymWBas2f/yxIeo4/xvr9KFt+zipN/5jKyyAXVF5upbDVovP8U/
r32m+GtkiwyruAIKpBaQl5trVzqTtxz48z3w+EGQom8CAwEAAaNjMGEwDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0OBBYEFDZWef5azYB/0OS2
WHtfAVdvQOjIMB8GA1UdIwQYMBaAFIcjThTQOT4ag4WnUjUFoaZHMkx1MA0GCSqG
SIb3DQEBCwUAA4IBgQCPSVHHM0AQl1ty3tHS1I8elj2/kOa1HvPJqZL3y4W5AvRr
L8KKC5PUe1PQpmQGbhdw0lh66zY8mSzyAs+TS4mh5af1GAt68lF7JQDeyWF77Ng9
JZ5oTA+9rwf0DLelr4ULjTKq8BwbJg0EGHpbg4Jt/TqdckjRI9lU0vmTQRN5dZdT
NsDlV5+zplCx7cB0EzbeC5RQYJ9vscD9p+p9GuK8sz630ovDzugVRYbGduORAS9r
piAVj95A4eaX7XFfDgOb1SvXNlGi7gbCCqkuEaG6X+Jfa0knLSNh1cmQzOwFxmMK
so8IGYEoQW5YTfobGpzdI3Swwjm1C5mThfxeASH9YaD4OlfAt56BvmApOsAdB7vz
8ixgYhVQf+Cg0/4ZBdqdaGXUUvn69MgfdzP/8y2YpoxpspjNxNxX/ARkGsJvcy5G
eWPBflPUAD0qFREoTT4mmNjhwx7iQYtBtrLQzmUg37tnLDOyoZvkoJMVEmvrMYps
sCFRITKncJVxtmAN5q8=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEEDCCAnigAwIBAgIUY3QU2aB2qhWYMIRjvY5Vs8GcP90wDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAxMUc3d0cG0tbG9jYWxjYS1yb290Y2EwIBcNMjMwNDI3MjMx
OTU1WhgPOTk5OTEyMzEyMzU5NTlaMB8xHTAbBgNVBAMTFHN3dHBtLWxvY2FsY2Et
cm9vdGNhMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvwYzTxqzZyJ8
No9oMxnKVGk6TzfblYRx6+q1iEQU+UwWfvpXPTH3H6NoWcka6z68FTPkFGDDpCeJ
97+OULdlXfuUxXvgsg6yErhDKl1RxXgiaAzkT0GjC1AZEtaGtO4D/eWPdf3btnkR
+h/D8aVmiC1IT1PJuIeMnuXboBIZRG/6RgIDZHgndtAClNZHvEJiZe1w+2Q5ZZMe
YBvlozc/xD9s31/ZK9iAzLTosZbQBXdd1coe/EUtOlG+0wOIXHi+F7MERAx2bndG
FcZbLuiMQxn6pcIhglUGnG8PC5Ny67OwoWW5KVKnCspC3lE9vGYYb1RrronKY8tP
DcAnV+6rSR6LD+6mAyZnXjbFCAmpHXXxCYzffN7QsOlkevf1cv58NEW3b6lB60Eq
mCfSkJuzv3d8MIWBeIT6Ovv1aU4hKivyJovoGF2gUyk9BRLAdmh5hxnfFINVxCs5
OkIY4hfg2uRL09Hs1hKoOsavxrpOsGMUx+fmvHY3WwskKKQ5AQPVAgMBAAGjQjBA
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMB0GA1UdDgQWBBSHI04U
0Dk+GoOFp1I1BaGmRzJMdTANBgkqhkiG9w0BAQsFAAOCAYEAe5677YhW+MHE0K1L
6Y2yrKa4aMvB7FeHsBRcQ/CHtb7IDRYhMSzmxxPzvVloZFrLqadcrZawMFa9dd4m
Mg8GMYYxfe3o/QQnxP3APx9gii+ArZnUxNozqOGac1Ov5oIp9DkxuHv7MywAHC4a
kdMb695ub20+5t4tyKzN2FWkilq24LCEiXJcgTCtedjaj6J7GJbjAKA4+ixSO87E
3XB/vpUEV8hK+maDeh1AjSXfaamu4Z4zCDWtWDVYgWyznVmM2ocazzXPIIVi6yen
XjIIgAyuDmGRsVTHC6ACpNnt8gVOTI1BmAlXR6NjjS6EUxiH2YF48WLu6d1QuC3N
SrIPMF49qkHHuHYr4g7bgmpBJL58tQ8vZMnwakigf4cyefv0XtwYasbbUWZXhKSj
padP8dpi6M9qMO7k2w6FL0itDMpSpPLsziZz7Ar6EsaccNnwbwXHwxUZZrovmihX
nM8F2IloskbDDps2gsVxllmvm5lk4BgKgMPGeE+hFclMs+k1
-----END CERTIFICATE-----
`
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM([]byte(cas)) {
		panic("no certs added to pool")
	}
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
	fmt.Println("cert1:")
	var eksan *EKSAN
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			var err error
			eksan, err = parseEKSANs(ext.Value)
			if err != nil {
				panic(err)
			}
		}
	}
	fmt.Printf("%s\n", eksan)
	fmt.Println("cert2:")
	for _, ext := range cert2.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			var err error
			eksan, err = parseEKSANs(ext.Value)
			if err != nil {
				panic(err)
			}
		}
	}
	fmt.Printf("%s\n", eksan)
	cert.UnhandledCriticalExtensions = nil
	// cert.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots: p,
		// Intermediates: p,
	})
	if err != nil {
		panic(err)
	}
	t.Logf("chains: %v\n", chains)
	panic(err)
}

const (
	classConstructed     = 0x20
	classContextSpecific = 0x80
)

/*
-- TCG specific OIDs
tcg OBJECT IDENTIFIER ::= {
joint-iso-itu-t(2) international-organizations(23) tcg(133) }
tcg-tcpaSpecVersion OBJECT IDENTIFIER ::= {tcg 1}
tcg-attribute OBJECT IDENTIFIER ::= {tcg 2}
tcg-protocol OBJECT IDENTIFIER ::= {tcg 3}
tcg-algorithm OBJECT IDENTIFIER ::= {tcg 4}
tcg-ce OBJECT IDENTIFIER ::= {tcg 6}
tcg-kp OBJECT IDENTIFIER ::= {tcg 8}

-- TCG Spec Version OIDs
tcg-sv-tpm12 OBJECT IDENTIFIER ::= { tcg-tcpaSpecVersion 1}
tcg-sv-tpm20 OBJECT IDENTIFIER ::= { tcg-tcpaSpecVersion 2}

-- TCG Attribute OIDs
tcg-at-tpmManufacturer OBJECT IDENTIFIER ::= {tcg-attribute 1}
tcg-at-tpmModel OBJECT IDENTIFIER ::= {tcg-attribute 2}
tcg-at-tpmVersion OBJECT IDENTIFIER ::= {tcg-attribute 3}
tcg-at-platformManufacturer OBJECT IDENTIFIER ::= {tcg-attribute 4}
tcg-at-platformModel OBJECT IDENTIFIER ::= {tcg-attribute 5}
tcg-at-platformVersion OBJECT IDENTIFIER ::= {tcg-attribute 6}
*/

var (
	// OID 2.23.133.2.1 - tpmManufacturer
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}

	// OID 2.23.133.2.2 - tpmModel
	oidTPMModel = asn1.ObjectIdentifier{2, 23, 133, 2, 2}

	// OID 2.23.133.2.3 - tpmVersion
	oidTPMVersion = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
)

type EKSAN struct {
	TPMManufacturer *TPMManufacturer
	TPMModel        *TPMModel
	TPMVersion      *TPMVersion
}

func (e EKSAN) String() string {
	return fmt.Sprintf("[TPMManufacturer: %s, TPMModel: %s, TPMVersion: %s]", e.TPMManufacturer, e.TPMModel, e.TPMVersion)
}

type TPMVendorID uint32

/*
Taken from: https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-VendorIDRegistry-v1p06-r0p91-pub.pdf

TPM Hardware Vendor List

AMD 0x1022
Atmel 0x1114
Broadcom 0x14E4
Cisco 0xC5C0
FlySlice Technologies 0x232B
Fuzhou Rockchip 0x232A
Google 0x6666
HPE 0x1590
Huawei 0x8888
IBM 0x1014
Infineon 0x15D1
Intel 0x8086
Lenovo 0x17AA
Microsoft 0x1414
National Semi 0x100B
Nationz 0x1B4E
Winbond 0x1050
Nuvoton Technology 0x1050
Qualcomm 0x1011
Samsung 0x144D
Sinosun 0x19FA
SMSC 0x1055
STMicroelectronics 0x104A
Texas Instruments 0x104C

TPM Capability Vendor List

AMD <AMD > 0x41 0x4D 0x44 0x00
Atmel <ATML> 0x41 0x54 0x4D 0x4C
Broadcom <BRCM> 0x42 0x52 0x43 0x4D
Cisco <CSCO> 0x43 0x53 0x43 0x4F
Flyslice Technologies <FLYS> 0x46 0x4C 0x59 0x53
Fuzhou Rockchip <ROCC> 0x52 0x4F 0x43 0x43
Google <GOOG> 0x47 0x4F 0x4F 0x47
HPE <HPE > 0x48 0x50 0x45 0x00
Huawei <HISI> 0x48 0x49 0x53 0x49
IBM <IBM > 0x49 0x42 0x4d 0x00
Infineon <IFX > 0x49 0x46 0x58 0x00
Intel <INTC> 0x49 0x4E 0x54 0x43
Lenovo <LEN > 0x4C 0x45 0x4E 0x00
Microsoft <MSFT> 0x4D 0x53 0x46 0x54
National Semiconductor <NSM > 0x4E 0x53 0x4D 0x20
Nationz <NTZ > 0x4E 0x54 0x5A 0x00
Nuvoton Technology <NTC > 0x4E 0x54 0x43 0x00
Qualcomm <QCOM> 0x51 0x43 0x4F 0x4D
Samsung <SMSN> 0x53 0x4D 0x53 0x4E
Sinosun <SNS > 0x53 0x4E 0x53 0x00
SMSC <SMSC> 0x53 0x4D 0x53 0x43
ST Microelectronics <STM > 0x53 0x54 0x4D 0x20
Texas Instruments <TXN > 0x54 0x58 0x4E 0x00
Winbond <WEC > 0x57 0x45 0x43 0x00

Simulator 0 <SIM0> 0x53 0x49 0x4d 0x30
Simulator 1 <SIM1> 0x53 0x49 0x4d 0x31
Simulator 2 <SIM2> 0x53 0x49 0x4d 0x32
Simulator 3 <SIM3> 0x53 0x49 0x4d 0x33
Simulator 4 <SIM4> 0x53 0x49 0x4d 0x34
Simulator 5 <SIM5> 0x53 0x49 0x4d 0x35
Simulator 6 <SIM6> 0x53 0x49 0x4d 0x36
Simulator 7 <SIM7> 0x53 0x49 0x4d 0x37
Test 0 <TST0> 0x54 0x53 0x54 0x30
Test 1 <TST1> 0x54 0x53 0x54 0x31
Test 2 <TST2> 0x54 0x53 0x54 0x32
Test 3 <TST3> 0x54 0x53 0x54 0x33
Test 4 <TST4> 0x54 0x53 0x54 0x34
Test 5 <TST5> 0x54 0x53 0x54 0x35
Test 6 <TST6> 0x54 0x53 0x54 0x36
Test 7 <TST7> 0x54 0x53 0x54 0x37
*/

var tpmVendorMap map[TPMVendorID]struct {
	ascii  string
	vendor string
} = map[TPMVendorID]struct {
	ascii  string
	vendor string
}{
	TPMHardwareVendorAMD:                     {vendor: "AMD"},
	TPMHardwareVendorAtmel:                   {vendor: "Atmel"},
	TPMHardwareVendorBroadcom:                {vendor: "Broadcom"},
	TPMHardwareVendorCisco:                   {vendor: "Cisco"},
	TPMHardwareVendorFlySliceTechnologies:    {vendor: "FlySlice Technologies"},
	TPMHardwareVendorFuzhouRockchip:          {vendor: "Fuzhou Rockchip"},
	TPMHardwareVendorGoogle:                  {vendor: "Google"},
	TPMHardwareVendorHPE:                     {vendor: "HPE"},
	TPMHardwareVendorHuawei:                  {vendor: "Huawei"},
	TPMHardwareVendorIBM:                     {vendor: "IBM"},
	TPMHardwareVendorInfineon:                {vendor: "Infineon"},
	TPMHardwareVendorIntel:                   {vendor: "Intel"},
	TPMHardwareVendorLenovo:                  {vendor: "Lenovo"},
	TPMHardwareVendorMicrosoft:               {vendor: "Microsoft"},
	TPMHardwareVendorNationalSemi:            {vendor: "National Semi"},
	TPMHardwareVendorNationz:                 {vendor: "Nationz"},
	TPMHardwareVendorWinbond:                 {vendor: "Winbond"},
	TPMHardwareVendorNuvotonTechnology:       {vendor: "Nuvoton Technology"},
	TPMHardwareVendorQualcomm:                {vendor: "Qualcomm"},
	TPMHardwareVendorSamsung:                 {vendor: "Samsung"},
	TPMHardwareVendorSinosun:                 {vendor: "Sinosun"},
	TPMHardwareVendorSMSC:                    {vendor: "SMSC"},
	TPMHardwareVendorSTMicroelectronics:      {vendor: "STMicroelectronics"},
	TPMHardwareVendorTexasInstruments:        {vendor: "Texas Instruments"},
	TPMCapabilityVendorAMD:                   {vendor: "AMD", ascii: "AMD "},
	TPMCapabilityVendorAtmel:                 {vendor: "Atmel", ascii: "ATML"},
	TPMCapabilityVendorBroadcom:              {vendor: "Broadcom", ascii: "BRCM"},
	TPMCapabilityVendorCisco:                 {vendor: "Cisco", ascii: "CSCO"},
	TPMCapabilityVendorFlysliceTechnologies:  {vendor: "Flyslice Technologies", ascii: "FLYS"},
	TPMCapabilityVendorFuzhouRockchip:        {vendor: "Fuzhou Rockchip", ascii: "ROCC"},
	TPMCapabilityVendorGoogle:                {vendor: "Google", ascii: "GOOG"},
	TPMCapabilityVendorHPE:                   {vendor: "HPE", ascii: "HPE "},
	TPMCapabilityVendorHuawei:                {vendor: "Huawei", ascii: "HISI"},
	TPMCapabilityVendorIBM:                   {vendor: "IBM", ascii: "IBM "},
	TPMCapabilityVendorInfineon:              {vendor: "Infineon", ascii: "IFX "},
	TPMCapabilityVendorIntel:                 {vendor: "Intel", ascii: "INTC"},
	TPMCapabilityVendorLenovo:                {vendor: "Lenovo", ascii: "LEN "},
	TPMCapabilityVendorMicrosoft:             {vendor: "Microsoft", ascii: "MSFT"},
	TPMCapabilityVendorNationalSemiconductor: {vendor: "National Semiconductor", ascii: "NSM "},
	TPMCapabilityVendorNationz:               {vendor: "Nationz", ascii: "NTZ "},
	TPMCapabilityVendorNuvotonTechnology:     {vendor: "Nuvoton Technology", ascii: "NTC "},
	TPMCapabilityVendorQualcomm:              {vendor: "Qualcomm", ascii: "QCOM"},
	TPMCapabilityVendorSamsung:               {vendor: "Samsung", ascii: "SMSN"},
	TPMCapabilityVendorSinosun:               {vendor: "Sinosun", ascii: "SNS "},
	TPMCapabilityVendorSMSC:                  {vendor: "SMSC", ascii: "SMSC"},
	TPMCapabilityVendorSTMicroelectronics:    {vendor: "ST Microelectronics", ascii: "STM "},
	TPMCapabilityVendorTexasInstruments:      {vendor: "Texas Instruments", ascii: "TXN "},
	TPMCapabilityVendorWinbond:               {vendor: "Winbond", ascii: "WEC "},
	TPMTestingVendorSimulator0:               {vendor: "Simulator 0", ascii: "SIM0"},
	TPMTestingVendorSimulator1:               {vendor: "Simulator 1", ascii: "SIM1"},
	TPMTestingVendorSimulator2:               {vendor: "Simulator 2", ascii: "SIM2"},
	TPMTestingVendorSimulator3:               {vendor: "Simulator 3", ascii: "SIM3"},
	TPMTestingVendorSimulator4:               {vendor: "Simulator 4", ascii: "SIM4"},
	TPMTestingVendorSimulator5:               {vendor: "Simulator 5", ascii: "SIM5"},
	TPMTestingVendorSimulator6:               {vendor: "Simulator 6", ascii: "SIM6"},
	TPMTestingVendorSimulator7:               {vendor: "Simulator 7", ascii: "SIM7"},
	TPMTestingVendorTest0:                    {vendor: "Test 0", ascii: "TST0"},
	TPMTestingVendorTest1:                    {vendor: "Test 1", ascii: "TST1"},
	TPMTestingVendorTest2:                    {vendor: "Test 2", ascii: "TST2"},
	TPMTestingVendorTest3:                    {vendor: "Test 3", ascii: "TST3"},
	TPMTestingVendorTest4:                    {vendor: "Test 4", ascii: "TST4"},
	TPMTestingVendorTest5:                    {vendor: "Test 5", ascii: "TST5"},
	TPMTestingVendorTest6:                    {vendor: "Test 6", ascii: "TST6"},
	TPMTestingVendorTest7:                    {vendor: "Test 7", ascii: "TST7"},
}

var (
	TPMHardwareVendorAMD                     = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x10, 0x22}))
	TPMHardwareVendorAtmel                   = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x11, 0x14}))
	TPMHardwareVendorBroadcom                = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x14, 0xE4}))
	TPMHardwareVendorCisco                   = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0xC5, 0xC0}))
	TPMHardwareVendorFlySliceTechnologies    = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x23, 0x2B}))
	TPMHardwareVendorFuzhouRockchip          = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x23, 0x2A}))
	TPMHardwareVendorGoogle                  = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x66, 0x66}))
	TPMHardwareVendorHPE                     = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x15, 0x90}))
	TPMHardwareVendorHuawei                  = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x88, 0x88}))
	TPMHardwareVendorIBM                     = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x10, 0x14}))
	TPMHardwareVendorInfineon                = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x15, 0xD1}))
	TPMHardwareVendorIntel                   = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x80, 0x86}))
	TPMHardwareVendorLenovo                  = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x17, 0xAA}))
	TPMHardwareVendorMicrosoft               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x14, 0x14}))
	TPMHardwareVendorNationalSemi            = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x10, 0x0B}))
	TPMHardwareVendorNationz                 = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x1B, 0x4E}))
	TPMHardwareVendorWinbond                 = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x10, 0x50}))
	TPMHardwareVendorNuvotonTechnology       = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x10, 0x50}))
	TPMHardwareVendorQualcomm                = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x10, 0x11}))
	TPMHardwareVendorSamsung                 = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x14, 0x4D}))
	TPMHardwareVendorSinosun                 = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x19, 0xFA}))
	TPMHardwareVendorSMSC                    = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x10, 0x55}))
	TPMHardwareVendorSTMicroelectronics      = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x10, 0x4A}))
	TPMHardwareVendorTexasInstruments        = TPMVendorID(binary.BigEndian.Uint32([]byte{0x0, 0x0, 0x10, 0x4C}))
	TPMCapabilityVendorAMD                   = TPMVendorID(binary.BigEndian.Uint32([]byte{0x41, 0x4D, 0x44, 0x00}))
	TPMCapabilityVendorAtmel                 = TPMVendorID(binary.BigEndian.Uint32([]byte{0x41, 0x54, 0x4D, 0x4C}))
	TPMCapabilityVendorBroadcom              = TPMVendorID(binary.BigEndian.Uint32([]byte{0x42, 0x52, 0x43, 0x4D}))
	TPMCapabilityVendorCisco                 = TPMVendorID(binary.BigEndian.Uint32([]byte{0x43, 0x53, 0x43, 0x4F}))
	TPMCapabilityVendorFlysliceTechnologies  = TPMVendorID(binary.BigEndian.Uint32([]byte{0x46, 0x4C, 0x59, 0x53}))
	TPMCapabilityVendorFuzhouRockchip        = TPMVendorID(binary.BigEndian.Uint32([]byte{0x52, 0x4F, 0x43, 0x43}))
	TPMCapabilityVendorGoogle                = TPMVendorID(binary.BigEndian.Uint32([]byte{0x47, 0x4F, 0x4F, 0x47}))
	TPMCapabilityVendorHPE                   = TPMVendorID(binary.BigEndian.Uint32([]byte{0x48, 0x50, 0x45, 0x00}))
	TPMCapabilityVendorHuawei                = TPMVendorID(binary.BigEndian.Uint32([]byte{0x48, 0x49, 0x53, 0x49}))
	TPMCapabilityVendorIBM                   = TPMVendorID(binary.BigEndian.Uint32([]byte{0x49, 0x42, 0x4d, 0x00}))
	TPMCapabilityVendorInfineon              = TPMVendorID(binary.BigEndian.Uint32([]byte{0x49, 0x46, 0x58, 0x00}))
	TPMCapabilityVendorIntel                 = TPMVendorID(binary.BigEndian.Uint32([]byte{0x49, 0x4E, 0x54, 0x43}))
	TPMCapabilityVendorLenovo                = TPMVendorID(binary.BigEndian.Uint32([]byte{0x4C, 0x45, 0x4E, 0x00}))
	TPMCapabilityVendorMicrosoft             = TPMVendorID(binary.BigEndian.Uint32([]byte{0x4D, 0x53, 0x46, 0x54}))
	TPMCapabilityVendorNationalSemiconductor = TPMVendorID(binary.BigEndian.Uint32([]byte{0x4E, 0x53, 0x4D, 0x20}))
	TPMCapabilityVendorNationz               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x4E, 0x54, 0x5A, 0x00}))
	TPMCapabilityVendorNuvotonTechnology     = TPMVendorID(binary.BigEndian.Uint32([]byte{0x4E, 0x54, 0x43, 0x00}))
	TPMCapabilityVendorQualcomm              = TPMVendorID(binary.BigEndian.Uint32([]byte{0x51, 0x43, 0x4F, 0x4D}))
	TPMCapabilityVendorSamsung               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x4D, 0x53, 0x4E}))
	TPMCapabilityVendorSinosun               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x4E, 0x53, 0x00}))
	TPMCapabilityVendorSMSC                  = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x4D, 0x53, 0x43}))
	TPMCapabilityVendorSTMicroelectronics    = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x54, 0x4D, 0x20}))
	TPMCapabilityVendorTexasInstruments      = TPMVendorID(binary.BigEndian.Uint32([]byte{0x54, 0x58, 0x4E, 0x00}))
	TPMCapabilityVendorWinbond               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x57, 0x45, 0x43, 0x00}))
	TPMTestingVendorSimulator0               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x49, 0x4d, 0x30}))
	TPMTestingVendorSimulator1               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x49, 0x4d, 0x31}))
	TPMTestingVendorSimulator2               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x49, 0x4d, 0x32}))
	TPMTestingVendorSimulator3               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x49, 0x4d, 0x33}))
	TPMTestingVendorSimulator4               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x49, 0x4d, 0x34}))
	TPMTestingVendorSimulator5               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x49, 0x4d, 0x35}))
	TPMTestingVendorSimulator6               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x49, 0x4d, 0x36}))
	TPMTestingVendorSimulator7               = TPMVendorID(binary.BigEndian.Uint32([]byte{0x53, 0x49, 0x4d, 0x37}))
	TPMTestingVendorTest0                    = TPMVendorID(binary.BigEndian.Uint32([]byte{0x54, 0x53, 0x54, 0x30}))
	TPMTestingVendorTest1                    = TPMVendorID(binary.BigEndian.Uint32([]byte{0x54, 0x53, 0x54, 0x31}))
	TPMTestingVendorTest2                    = TPMVendorID(binary.BigEndian.Uint32([]byte{0x54, 0x53, 0x54, 0x32}))
	TPMTestingVendorTest3                    = TPMVendorID(binary.BigEndian.Uint32([]byte{0x54, 0x53, 0x54, 0x33}))
	TPMTestingVendorTest4                    = TPMVendorID(binary.BigEndian.Uint32([]byte{0x54, 0x53, 0x54, 0x34}))
	TPMTestingVendorTest5                    = TPMVendorID(binary.BigEndian.Uint32([]byte{0x54, 0x53, 0x54, 0x35}))
	TPMTestingVendorTest6                    = TPMVendorID(binary.BigEndian.Uint32([]byte{0x54, 0x53, 0x54, 0x36}))
	TPMTestingVendorTest7                    = TPMVendorID(binary.BigEndian.Uint32([]byte{0x54, 0x53, 0x54, 0x37}))
)

func (v TPMVendorID) String() string {
	ven, ok := tpmVendorMap[v]
	if !ok {
		return fmt.Sprintf("Unknown [%s]", hex.EncodeToString(binary.BigEndian.AppendUint32(nil, uint32(v))))
	}
	return ven.vendor
}

func (v TPMVendorID) ASCII() string {
	ven, ok := tpmVendorMap[v]
	if !ok {
		return "    "
	}
	return ven.ascii
}

var (
	ErrNotATPMVendorID = errors.New("not a TPM Vendor ID")
)

type TPMManufacturer struct {
	raw string
}

func (m TPMManufacturer) VendorID() (TPMVendorID, error) {
	if len(m.raw) != 11 {
		return 0, ErrNotATPMVendorID
	}
	if !strings.HasPrefix(m.raw, "id:") {
		return 0, ErrNotATPMVendorID
	}
	vendor, err := hex.DecodeString(m.raw[3:])
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrNotATPMVendorID, err)
	}
	// techincally this should be a "TPM Capability Vendor" (4 bytes), but that's not always the case irl
	if len(vendor) != 4 {
		return 0, ErrNotATPMVendorID
	}
	return TPMVendorID(binary.BigEndian.Uint32(vendor)), nil
}

func (m TPMManufacturer) String() string {
	if !strings.HasPrefix(m.raw, "id:") {
		return m.raw
	}

	vendor, err := m.VendorID()
	if err != nil {
		return m.raw
	}

	return vendor.String()
}

type TPMModel struct {
	raw string
}

func (m TPMModel) String() string {
	return m.raw
}

type TPMVersion struct {
	raw string
}

func (v TPMVersion) Major() uint16 {
	if len(v.raw) < 7 {
		return 0
	}
	if !strings.HasPrefix(v.raw, "id:") {
		return 0
	}
	b, err := hex.DecodeString(v.raw[3:])
	if err != nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (v TPMVersion) Minor() uint16 {
	if len(v.raw) < 11 {
		return 0
	}
	if !strings.HasPrefix(v.raw, "id:") {
		return 0
	}
	b, err := hex.DecodeString(v.raw[7:])
	if err != nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (v TPMVersion) String() string {
	maj := v.Major()
	// something is probably off, so we'll just return the raw thing
	if maj == 0 {
		return v.raw
	}
	min := v.Minor()
	return fmt.Sprintf("%d.%d (%s)", maj, min, v.raw)
}

func parseEKSANs(der cryptobyte.String) (*EKSAN, error) {
	var ret EKSAN
	// this is what identifies it as an EK SAN
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid subject alternative names")
	}
	if !der.ReadASN1(&der, cryptobyte_asn1.OCTET_STRING|classConstructed|classContextSpecific) {
		return nil, errors.New("x509: not an EK SAN")
	}

	// now from here on it's: SEQUENCE -> (SET -> SEQUENCE -> OID, UTF-8 String)*
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid EK SAN")
	}
	for !der.Empty() {
		// SET
		var set, seq cryptobyte.String
		if !der.ReadASN1(&set, cryptobyte_asn1.SET) {
			return nil, errors.New("x509: set: invalid subject alternative name")
		}
		// SEQUENCE
		if !set.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("x509: seq: invalid subject alternative name")
		}

		// OID
		var oid asn1.ObjectIdentifier
		if !seq.ReadASN1ObjectIdentifier(&oid) {
			return nil, errors.New("x509: oid: invalid subject alternative name")
		}

		// UTF-8 String
		var val cryptobyte.String
		if !seq.ReadASN1(&val, cryptobyte_asn1.UTF8String) {
			return nil, errors.New("x509: utf8: invalid subject alternative name")
		}

		if oid.Equal(oidTPMManufacturer) {
			ret.TPMManufacturer = &TPMManufacturer{raw: string(val)}
		} else if oid.Equal(oidTPMModel) {
			ret.TPMModel = &TPMModel{raw: string(val)}
		} else if oid.Equal(oidTPMVersion) {
			ret.TPMVersion = &TPMVersion{raw: string(val)}
		} else {
			return nil, fmt.Errorf("x509: oid: unexpected OID in EK SAN: %s", oid.String())
		}
	}
	return &ret, nil
}
