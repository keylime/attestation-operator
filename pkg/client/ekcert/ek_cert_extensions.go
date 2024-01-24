package ekcert

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

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
	// OIDSAN represents the OID of the SAN (Subject Alternative Names) extension object
	OIDSAN = asn1.ObjectIdentifier{2, 5, 29, 17}

	// OIDSDA represents the OID of the Subject Directory Attributes extension object
	OIDSDA = asn1.ObjectIdentifier{2, 5, 29, 9}
)

var (
	// OID 2.23.133.2.1 - tpmManufacturer
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}

	// OID 2.23.133.2.2 - tpmModel
	oidTPMModel = asn1.ObjectIdentifier{2, 23, 133, 2, 2}

	// OID 2.23.133.2.3 - tpmVersion
	oidTPMVersion = asn1.ObjectIdentifier{2, 23, 133, 2, 3}

	// OID 2.23.133.2.16 - tpmSpecification
	oidTPMSpecification = asn1.ObjectIdentifier{2, 23, 133, 2, 16}
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

func (v TPMVendorID) Bytes() []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(v))
}

func (v TPMVendorID) HexString() string {
	return strings.ToUpper(hex.EncodeToString(binary.BigEndian.AppendUint32(nil, uint32(v))))
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

// ParseEKSANs expects the input of the "Subject Alternative Name" of an X509v3 extension from an EK certificate as input
func ParseEKSANs(der cryptobyte.String) (*EKSAN, error) {
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

type EKSDA struct {
	Family   string
	Level    int
	Revision int
}

func (e EKSDA) String() string {
	return fmt.Sprintf("%s lvl %d rev %d", e.Family, e.Level, e.Revision)
}

// ParseEKSDA expects the input of a "Subject Directory Attributes" X509v3 extension from an EK certificate as input.
func ParseEKSDA(der cryptobyte.String) (*EKSDA, error) {
	// this is what identifies it as an EK Subject Directory Attributes
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: first seq: invalid x509v3 extension")
	}
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: second seq: invalid EK Subject Directory Attributes")
	}

	// OID
	var oid asn1.ObjectIdentifier
	if !der.ReadASN1ObjectIdentifier(&oid) {
		return nil, errors.New("x509: oid: invalid EK Subject Directory Attributes")
	}
	if !oid.Equal(oidTPMSpecification) {
		return nil, fmt.Errorf("x509:oid: unexpected OID in EK Subject Directory Attributes: %s", oid.String())
	}

	// SET
	var set, seq cryptobyte.String
	if !der.ReadASN1(&set, cryptobyte_asn1.SET) {
		return nil, errors.New("x509: set: invalid EK Subject Directory Attributes")
	}

	// SEQUENCE
	if !set.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: seq: invalid EK Subject Directory Attributes")
	}

	// UTF-8 String - Family
	var family cryptobyte.String
	if !seq.ReadASN1(&family, cryptobyte_asn1.UTF8String) {
		return nil, errors.New("x509: utf8: family: invalid EK Subject Directory Attributes")
	}

	// INTEGER - Level
	var level, revision int
	if !seq.ReadASN1Integer(&level) {
		return nil, errors.New("x509: integer: level: invalid EK Subject Directory Attributes")
	}

	// INTEGER - Revision
	if !seq.ReadASN1Integer(&revision) {
		return nil, errors.New("x509: integer: revision: invalid EK Subject Directory Attributes")
	}
	return &EKSDA{
		Family:   string(family),
		Level:    level,
		Revision: revision,
	}, nil
}
