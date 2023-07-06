package v1alpha1

type TPMHashAlg string

const (
	HashAlgSHA1     TPMHashAlg = "sha1"
	HashAlgSHA256   TPMHashAlg = "sha256"
	HashAlgSHA384   TPMHashAlg = "sha384"
	HashAlgSHA512   TPMHashAlg = "sha512"
	HashAlgSM3_256  TPMHashAlg = "sm3_256"
	HashAlgSHA3_256 TPMHashAlg = "sha3_256"
	HashAlgSHA3_384 TPMHashAlg = "sha3_384"
	HashAlgSHA3_512 TPMHashAlg = "sha3_512"
)

type TPMEncryptionAlg string

const (
	EncAlgRSA TPMEncryptionAlg = "rsa"
	EncAlgECC TPMEncryptionAlg = "ecc"
)

type TPMSigningAlg string

const (
	SignAlgRSASSA    TPMSigningAlg = "rsassa"
	SignAlgRSAPSS    TPMSigningAlg = "rsapss"
	SignAlgECDSA     TPMSigningAlg = "ecdsa"
	SignAlgECDAA     TPMSigningAlg = "ecdaa"
	SignAlgECSCHNORR TPMSigningAlg = "ecschnorr"
)

type TPMPolicy struct {
	PCR0  []string `json:"0,omitempty"`
	PCR1  []string `json:"1,omitempty"`
	PCR2  []string `json:"2,omitempty"`
	PCR3  []string `json:"3,omitempty"`
	PCR4  []string `json:"4,omitempty"`
	PCR5  []string `json:"5,omitempty"`
	PCR6  []string `json:"6,omitempty"`
	PCR7  []string `json:"7,omitempty"`
	PCR8  []string `json:"8,omitempty"`
	PCR9  []string `json:"9,omitempty"`
	PCR10 []string `json:"10,omitempty"`
	PCR11 []string `json:"11,omitempty"`
	PCR12 []string `json:"12,omitempty"`
	PCR13 []string `json:"13,omitempty"`
	PCR14 []string `json:"14,omitempty"`
	PCR15 []string `json:"15,omitempty"`
	PCR16 []string `json:"16,omitempty"`
	PCR17 []string `json:"17,omitempty"`
	PCR18 []string `json:"18,omitempty"`
	PCR19 []string `json:"19,omitempty"`
	PCR20 []string `json:"20,omitempty"`
	PCR21 []string `json:"21,omitempty"`
	PCR22 []string `json:"22,omitempty"`
	PCR23 []string `json:"23,omitempty"`
	Mask  string   `json:"mask,omitempty"`
}
