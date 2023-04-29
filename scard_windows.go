//go:build windows
// +build windows

// Copyright (c) 2023, El Mostafa IDRASSI.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package goscard

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type hnd uintptr
type dword uint32

//////////////////////////////////////////////////////////////////////////////////////
// Misc.
//////////////////////////////////////////////////////////////////////////////////////

func hexStringToByteArray(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func byteArrayToHexString(data []byte) string {
	return hex.EncodeToString(data)
}

// utf16BytesToString transforms a []byte which contains a wide char string in LE
// into its []uint16 corresponding representation,
// then returns the UTF-8 encoding of the UTF-16 sequence,
// with a terminating NUL removed. If after converting the []byte into
// a []uint16, there is a NUL uint16, the conversion to string stops
// at that NUL uint16.
func utf16BytesToString(buf []byte) (string, error) {

	if len(buf)%2 != 0 {
		return "", fmt.Errorf("input is not a valid byte representation of a wide char string in LE")
	}
	b := make([]uint16, len(buf)/2)

	// LPCSTR (Windows' representation of utf16) is always little endian.
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, b); err != nil {
		return "", err
	}
	return windows.UTF16ToString(b), nil
}

// utf16ToString transforms a []utf16 which contains a wide char string in LE
// into its UTF-8 encoding representation, with a terminating NUL removed.
// The conversion stops at the first encountered NUL uint16.
func utf16ToString(buf []uint16) (string, error) {
	return windows.UTF16ToString(buf), nil
}

// utf16PtrToString transforms a *utf16 which contains a wide char string in LE
// into its UTF-8 encoding representation, with a terminating NUL removed.
// The conversion stops at the first encountered NUL uint16.
func utf16PtrToString(buf *uint16) string {
	return windows.UTF16PtrToString(buf)
}

// stringToUtf16Ptr returns the UTF-16 encoding of the UTF-8 string
// str, with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func stringToUtf16(str string) ([]uint16, error) {
	if str == "" {
		return nil, nil
	}
	return windows.UTF16FromString(str)
}

// stringToUtf16Ptr returns the UTF-16 encoding of the UTF-8 string
// str, with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func stringToUtf16Ptr(str string) (*uint16, error) {
	if str == "" {
		return nil, nil
	}
	return windows.UTF16PtrFromString(str)
}

// bytesToUtf16Ptr returns the UTF-16 encoding of the UTF-8 string
// contained in buf as a byte array, with a terminating NUL added.
// If str contains a NUL byte at any location, it returns (nil, EINVAL).
func bytesToUtf16Ptr(buf []byte) (*uint16, error) {
	str := string(buf)
	return stringToUtf16Ptr(str)
}

// bytesToUtf16 returns the UTF-16 encoding of the UTF-8 string
// contained in buf as a byte array, with a terminating NUL added.
// If str contains a NUL byte at any location, it returns (nil, EINVAL).
func bytesToUtf16(buf []byte) ([]uint16, error) {
	str := string(buf)
	return stringToUtf16(str)
}

// stringToUtf16Bytes returns the UTF-16 encoding of the UTF-8 string
// str, as a byte array with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func stringToUtf16Bytes(str string) ([]byte, error) {
	if str == "" {
		return nil, nil
	}
	utf16Str, err := windows.UTF16FromString(str)
	if err != nil {
		return nil, err
	}
	bytesStr := make([]byte, len(utf16Str)*2)
	j := 0
	for _, utf16 := range utf16Str {
		b := make([]byte, 2)
		// LPCSTR (Windows' representation of utf16) is always little endian.
		binary.LittleEndian.PutUint16(b, utf16)
		bytesStr[j] = b[0]
		bytesStr[j+1] = b[1]
		j += 2
	}
	return bytesStr, nil
}

// stringToUtf16String returns the UTF-16 encoding of the UTF-8 string
// str, with a terminating NUL added. If str contains a NUL byte at any
// location, it returns (nil, EINVAL).
func stringToUtf16String(str string) ([]uint16, error) {
	if str == "" {
		return nil, nil
	}
	utf16Str, err := windows.UTF16FromString(str)
	if err != nil {
		return nil, err
	}
	return utf16Str, nil
}

// multiUtf16StringToStrings splits a []utf16, which contains one or
// more wide char strings in LE separated with \0 (multi-string),
// into separate UTF-8 strings and returns them in as a string
// array.
func multiUtf16StringToStrings(multiUtf16String []uint16) ([]string, error) {
	var strings []string
	for len(multiUtf16String) > 0 && multiUtf16String[0] != 0 {
		i := 0
		for i = range multiUtf16String {
			if multiUtf16String[i] == 0 {
				break
			}
		}
		str, err := utf16ToString(multiUtf16String[:i+1]) // need to include the \0, therefore i+1
		if err != nil {
			return nil, err
		}
		strings = append(strings, str)
		multiUtf16String = multiUtf16String[i+1:]
	}

	return strings, nil
}

// stringsToMultiUtf16String creates a wide char multi-string
// from the passed string array. The wide char strings are
// separated with \0, and the whole multi-string is terminated
// with a double \0.
func stringsToMultiUtf16String(strings []string) ([]uint16, error) {
	var multiUtf16String []uint16
	for _, str := range strings {
		utf16String, err := stringToUtf16(str)
		if err != nil {
			return nil, err
		}
		multiUtf16String = append(multiUtf16String, utf16String...)
	}
	multiUtf16String = append(multiUtf16String, 0x00) // Add terminating \0 to get a double trailing zero.

	return multiUtf16String, nil
}

// ======================================================================================
// Windows error codes.
// From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\shared\winerror.h.
// ======================================================================================

var (
	// Smart Card Error Codes.
	scardErrNums = map[uint64]string{
		0x80100001: "SCARD_F_INTERNAL_ERROR",
		0x80100002: "SCARD_E_CANCELLED",
		0x80100003: "SCARD_E_INVALID_HANDLE",
		0x80100004: "SCARD_E_INVALID_PARAMETER",
		0x80100005: "SCARD_E_INVALID_TARGET",
		0x80100006: "SCARD_E_NO_MEMORY",
		0x80100007: "SCARD_F_WAITED_TOO_LONG",
		0x80100008: "SCARD_E_INSUFFICIENT_BUFFER",
		0x80100009: "SCARD_E_UNKNOWN_READER",
		0x8010000A: "SCARD_E_TIMEOUT",
		0x8010000B: "SCARD_E_SHARING_VIOLATION",
		0x8010000C: "SCARD_E_NO_SMARTCARD",
		0x8010000D: "SCARD_E_UNKNOWN_CARD",
		0x8010000E: "SCARD_E_CANT_DISPOSE",
		0x8010000F: "SCARD_E_PROTO_MISMATCH",
		0x80100010: "SCARD_E_NOT_READY",
		0x80100011: "SCARD_E_INVALID_VALUE",
		0x80100012: "SCARD_E_SYSTEM_CANCELLED",
		0x80100013: "SCARD_F_COMM_ERROR",
		0x80100014: "SCARD_F_UNKNOWN_ERROR",
		0x80100015: "SCARD_E_INVALID_ATR",
		0x80100016: "SCARD_E_NOT_TRANSACTED",
		0x80100017: "SCARD_E_READER_UNAVAILABLE",
		0x80100018: "SCARD_P_SHUTDOWN",
		0x80100019: "SCARD_E_PCI_TOO_SMALL",
		0x8010001A: "SCARD_E_READER_UNSUPPORTED",
		0x8010001B: "SCARD_E_DUPLICATE_READER",
		0x8010001C: "SCARD_E_CARD_UNSUPPORTED",
		0x8010001D: "SCARD_E_NO_SERVICE",
		0x8010001E: "SCARD_E_SERVICE_STOPPED",
		0x8010001F: "SCARD_E_UNEXPECTED",
		0x80100020: "SCARD_E_ICC_INSTALLATION",
		0x80100021: "SCARD_E_ICC_CREATEORDER",
		0x80100022: "SCARD_E_UNSUPPORTED_FEATURE",
		0x80100023: "SCARD_E_DIR_NOT_FOUND",
		0x80100024: "SCARD_E_FILE_NOT_FOUND",
		0x80100025: "SCARD_E_NO_DIR",
		0x80100026: "SCARD_E_NO_FILE",
		0x80100027: "SCARD_E_NO_ACCESS",
		0x80100028: "SCARD_E_WRITE_TOO_MANY",
		0x80100029: "SCARD_E_BAD_SEEK",
		0x8010002A: "SCARD_E_INVALID_CHV",
		0x8010002B: "SCARD_E_UNKNOWN_RES_MNG",
		0x8010002C: "SCARD_E_NO_SUCH_CERTIFICATE",
		0x8010002D: "SCARD_E_CERTIFICATE_UNAVAILABLE",
		0x8010002E: "SCARD_E_NO_READERS_AVAILABLE",
		0x8010002F: "SCARD_E_COMM_DATA_LOST",
		0x80100030: "SCARD_E_NO_KEY_CONTAINER",
		0x80100031: "SCARD_E_SERVER_TOO_BUSY",
		0x80100032: "SCARD_E_PIN_CACHE_EXPIRED",
		0x80100033: "SCARD_E_NO_PIN_CACHE",
		0x80100034: "SCARD_E_READ_ONLY_CARD",
		0x80100065: "SCARD_W_UNSUPPORTED_CARD",
		0x80100066: "SCARD_W_UNRESPONSIVE_CARD",
		0x80100067: "SCARD_W_UNPOWERED_CARD",
		0x80100068: "SCARD_W_RESET_CARD",
		0x80100069: "SCARD_W_REMOVED_CARD",
		0x8010006A: "SCARD_W_SECURITY_VIOLATION",
		0x8010006B: "SCARD_W_WRONG_CHV",
		0x8010006C: "SCARD_W_CHV_BLOCKED",
		0x8010006D: "SCARD_W_EOF",
		0x8010006E: "SCARD_W_CANCELLED_BY_USER",
		0x8010006F: "SCARD_W_CARD_NOT_AUTHENTICATED",
		0x80100070: "SCARD_W_CACHE_ITEM_NOT_FOUND",
		0x80100071: "SCARD_W_CACHE_ITEM_STALE",
		0x80100072: "SCARD_W_CACHE_ITEM_TOO_BIG",
	}
)

func maybePcscErr(errNo uintptr) error {
	if code, known := scardErrNums[uint64(errNo)]; known {
		return fmt.Errorf("scard failure: 0x%X (%s) (%s)", errNo, code, syscall.Errno(errNo).Error())
	} else {
		return fmt.Errorf("errno code: 0x%X (%s)", errNo, syscall.Errno(errNo).Error())
	}
}

//////////////////////////////////////////////////////////////////////////////////////
// WinSMCRD header content.
// From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\shared\winsmcrd.h
//////////////////////////////////////////////////////////////////////////////////////

const (
	methodBuffered        dword = 0 // From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\um\winioctl.h
	fileAnyAccess         dword = 0 // From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\um\winioctl.h
	fileDeviceSmartCard   dword = 0x00000031
	scardAtrLength        dword = 33 // ISO 7816-3 spec.
	infiniteTimeout       dword = 0xFFFFFFFF
	maxBufferSize         dword = 258   // Maximum Tx/Rx Buffer for short APDU
	maxBufferSizeExtended dword = 65538 // Maximum Tx/Rx Buffer for extended APDU
)

//
///////////////////////////////////////////////////////////////////////////////
//
//  Protocol Flag definitions
//

type SCardProtocol dword

const (
	SCardProtocolUndefined SCardProtocol = 0x00000000 // There is no active protocol.
	SCardProtocolT0        SCardProtocol = 0x00000001 // T=0 is the active protocol.
	SCardProtocolT1        SCardProtocol = 0x00000002 // T=1 is the active protocol.
	SCardProtocolRaw       SCardProtocol = 0x00010000 // Raw is the active protocol.

	//
	// This is the mask of ISO defined transmission protocols
	//
	SCardProtocolTx  SCardProtocol = SCardProtocolT0 | SCardProtocolT1
	SCardProtocolAny SCardProtocol = SCardProtocolTx

	//
	// Use the default transmission parameters / card clock freq.
	//
	SCardProtocolDefault SCardProtocol = 0x80000000

	//
	// Use optimal transmission parameters / card clock freq.
	// Since using the optimal parameters is the default case no bit is defined to be 1
	//
	SCardProtocolOptimal SCardProtocol = 0x00000000

	//
	// T=15 protocol.
	//
	SCardProtocolT15 SCardProtocol = 0x00000008
)

func (p SCardProtocol) String() string {
	output := ""

	if p == SCardProtocolUndefined {
		output += "Undefined"
	} else {
		if p&SCardProtocolT0 == SCardProtocolT0 {
			output += "T0;"
		}
		if p&SCardProtocolT1 == SCardProtocolT1 {
			output += "T1;"
		}
		if p&SCardProtocolT15 == SCardProtocolT15 {
			output += "T15;"
		}
		if p&SCardProtocolRaw == SCardProtocolRaw {
			output += "Raw;"
		}
		if p&SCardProtocolDefault == SCardProtocolDefault {
			output += "Default;"
		}
	}

	return output
}

// Ioctl parameters 1 for IOCTL_SMARTCARD_POWER
type SCardPowerOperation dword

const (
	SCardPowerDown SCardPowerOperation = 0 // Power down the card.
	SCardColdReset SCardPowerOperation = 1 // Cycle power and reset the card.
	SCardWarmReset SCardPowerOperation = 2 // Force a reset on the card.
)

func (p *SCardPowerOperation) String() string {
	switch *p {
	case SCardPowerDown:
		return "PowerDown"
	case SCardColdReset:
		return "ColdReset"
	case SCardWarmReset:
		return "WarmReset"
	default:
		return "N/A"
	}
}

//
///////////////////////////////////////////////////////////////////////////////
//
//  Reader Action IOCTLs
//

type SCardCtlCode dword

// From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\um\winioctl.h
func ctlCode(DeviceType, Function, Method, Access dword) dword {
	return ((DeviceType << 16) | (Access << 14) | (Function << 2) | Method)
}

func scardCtlCodeFunc(code dword) SCardCtlCode {
	return SCardCtlCode(ctlCode(fileDeviceSmartCard, code, methodBuffered, fileAnyAccess))
}

var (
	IoctlSmartCardPower             = scardCtlCodeFunc(1)
	IoctlSmartCardGetAttribute      = scardCtlCodeFunc(2)
	IoctlSmartCardSetAttribute      = scardCtlCodeFunc(3)
	IoctlSmartCardConfiscate        = scardCtlCodeFunc(4)
	IoctlSmartCardTransmit          = scardCtlCodeFunc(5)
	IoctlSmartCardEject             = scardCtlCodeFunc(6)
	IoctlSmartCardSwallow           = scardCtlCodeFunc(7)
	IoctlSmartCardIsPresent         = scardCtlCodeFunc(10)
	IoctlSmartCardIsAbsent          = scardCtlCodeFunc(11)
	IoctlSmartCardSetProtocol       = scardCtlCodeFunc(12)
	IoctlSmartCardGetState          = scardCtlCodeFunc(14)
	IoctlSmartCardGetLastError      = scardCtlCodeFunc(15)
	IoctlSmartCardGetPerfCntr       = scardCtlCodeFunc(16)
	IoctlSmartCardGetFeatureRequest = scardCtlCodeFunc(3400)
	// IoctlSmartCardRead                = scardCtlCodeFunc(8) obsolete
	// IoctlSmartCardWrite               = scardCtlCodeFunc(9) obsolete
)

//
///////////////////////////////////////////////////////////////////////////////
//
// Tags for requesting card and reader attributes
//

const (
	maximumAttrStringLength = 32 // Nothing bigger than this from getAttr
	maximumSmartcardReaders = 10 // Limit the readers on the system
)

type SCardAttr dword
type SCardClass dword

func scardAttrValue(class SCardClass, tag dword) SCardAttr {
	return SCardAttr((dword(class) << 16) | tag)
}

const (
	SCardClassVendorInfo     SCardClass = 1      // Vendor information definitions
	SCardClassCommunications SCardClass = 2      // Communication definitions
	SCardClassProtocol       SCardClass = 3      // Protocol definitions
	SCardClassPowerMgmt      SCardClass = 4      // Power Management definitions
	SCardClassSecurity       SCardClass = 5      // Security Assurance definitions
	SCardClassMechanical     SCardClass = 6      // Mechanical characteristic definitions
	SCardClassVendorDefined  SCardClass = 7      // Vendor specific definitions
	SCardClassIFDProtocol    SCardClass = 8      // Interface Device Protocol options
	SCardClassICCState       SCardClass = 9      // ICC State specific definitions
	SCardClassPerf           SCardClass = 0x7ffe // Performance counters
	SCardClassSystem         SCardClass = 0x7fff // System-specific definitions
)

func (c *SCardClass) String() string {
	switch *c {
	case SCardClassVendorInfo:
		return "VendorInfo"
	case SCardClassCommunications:
		return "Communications"
	case SCardClassProtocol:
		return "Protocol"
	case SCardClassPowerMgmt:
		return "PowerMgmt"
	case SCardClassSecurity:
		return "Security"
	case SCardClassMechanical:
		return "Mechanical"
	case SCardClassVendorDefined:
		return "VendorDefined"
	case SCardClassIFDProtocol:
		return "IFDProtocol"
	case SCardClassICCState:
		return "ICCState"
	case SCardClassPerf:
		return "Perf"
	case SCardClassSystem:
		return "System"
	default:
		return "N/A"
	}
}

var (
	SCardAttrVendorName        SCardAttr = scardAttrValue(SCardClassVendorInfo, 0x0100)
	SCardAttrVendorIFDType     SCardAttr = scardAttrValue(SCardClassVendorInfo, 0x0101)
	SCardAttrVendorIFDVersion  SCardAttr = scardAttrValue(SCardClassVendorInfo, 0x0102)
	SCardAttrVendorIFDSerialNo SCardAttr = scardAttrValue(SCardClassVendorInfo, 0x0103)
	SCardAttrChannelID         SCardAttr = scardAttrValue(SCardClassCommunications, 0x0110)
	//SCardAttrAsyncProtocolTypes    SCardAttr = scardAttrValue(SCardClassProtocol, 0x0120)
	SCardAttrDefaultClk           SCardAttr = scardAttrValue(SCardClassProtocol, 0x0121)
	SCardAttrMaxClk               SCardAttr = scardAttrValue(SCardClassProtocol, 0x0122)
	SCardAttrDefaultDataRate      SCardAttr = scardAttrValue(SCardClassProtocol, 0x0123)
	SCardAttrMaxDataRate          SCardAttr = scardAttrValue(SCardClassProtocol, 0x0124)
	SCardAttrMaxIFSD              SCardAttr = scardAttrValue(SCardClassProtocol, 0x0125)
	SCardAttrPowerMgmtSupport     SCardAttr = scardAttrValue(SCardClassPowerMgmt, 0x0131)
	SCardAttrUserToCardAuthDevice SCardAttr = scardAttrValue(SCardClassSecurity, 0x0140)
	SCardAttrUserAuthInputDevice  SCardAttr = scardAttrValue(SCardClassSecurity, 0x0142)
	SCardAttrCharacteristics      SCardAttr = scardAttrValue(SCardClassMechanical, 0x0150)

	SCardAttrCurrentProtocolType SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x0201)
	SCardAttrCurrentClk          SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x0202)
	SCardAttrCurrentF            SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x0203)
	SCardAttrCurrentD            SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x0204)
	SCardAttrCurrentN            SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x0205)
	SCardAttrCurrentW            SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x0206)
	SCardAttrCurrentIFSC         SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x0207)
	SCardAttrCurrentIFSD         SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x0208)
	SCardAttrCurrentBWT          SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x0209)
	SCardAttrCurrentCWT          SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x020a)
	SCardAttrCurrentEBCEncoding  SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x020b)
	SCardAttrExtendedBWT         SCardAttr = scardAttrValue(SCardClassIFDProtocol, 0x020c)

	SCardAttrICCPresence        SCardAttr = scardAttrValue(SCardClassICCState, 0x0300)
	SCardAttrICCInterfaceStatus SCardAttr = scardAttrValue(SCardClassICCState, 0x0301)
	SCardAttrCurrentIOState     SCardAttr = scardAttrValue(SCardClassICCState, 0x0302)
	SCardAttrATRString          SCardAttr = scardAttrValue(SCardClassICCState, 0x0303)
	SCardAttrICCTYPEPerATR      SCardAttr = scardAttrValue(SCardClassICCState, 0x0304)

	SCardAttrESCReset           SCardAttr = scardAttrValue(SCardClassVendorDefined, 0xA000)
	SCardAttrESCCancel          SCardAttr = scardAttrValue(SCardClassVendorDefined, 0xA003)
	SCardAttrESCAuthRequest     SCardAttr = scardAttrValue(SCardClassVendorDefined, 0xA005)
	SCardAttrMaxInput           SCardAttr = scardAttrValue(SCardClassVendorDefined, 0xA007)
	SCardAttrVendorSpecificInfo SCardAttr = scardAttrValue(SCardClassVendorDefined, 0xA008)

	SCardAttrDeviceUnit           SCardAttr = scardAttrValue(SCardClassSystem, 0x0001)
	SCardAttrDeviceInUse          SCardAttr = scardAttrValue(SCardClassSystem, 0x0002)
	SCardAttrDeviceFriendlyNameA  SCardAttr = scardAttrValue(SCardClassSystem, 0x0003)
	SCardAttrDeviceSystemNameA    SCardAttr = scardAttrValue(SCardClassSystem, 0x0004)
	SCardAttrDeviceFriendlyNameW  SCardAttr = scardAttrValue(SCardClassSystem, 0x0005)
	SCardAttrDeviceSystemNameW    SCardAttr = scardAttrValue(SCardClassSystem, 0x0006)
	SCardAttrSuppressT1IFSRequest SCardAttr = scardAttrValue(SCardClassSystem, 0x0007)

	SCarddAttrPerfNumTransmissions SCardAttr = scardAttrValue(SCardClassPerf, 0x0001)
	SCarddAttrPerfBytesTransmitted SCardAttr = scardAttrValue(SCardClassPerf, 0x0002)
	SCarddAttrPerfTransmissionTime SCardAttr = scardAttrValue(SCardClassPerf, 0x0003)

	SCardAttrDeviceFriendlyName SCardAttr = SCardAttrDeviceFriendlyNameW
	SCardAttrDeviceSystemName   SCardAttr = SCardAttrDeviceSystemNameW
)

func (a *SCardAttr) String() string {
	switch *a {
	case SCardAttrVendorName:
		return "VendorName"
	case SCardAttrVendorIFDType:
		return "VendorIFDType"
	case SCardAttrVendorIFDVersion:
		return "VendorIFDVersion"
	case SCardAttrVendorIFDSerialNo:
		return "VendorIFDSerialNo"
	case SCardAttrChannelID:
		return "ChannelID"
	case SCardAttrDefaultClk:
		return "DefaultClk"
	case SCardAttrMaxClk:
		return "MaxClk"
	case SCardAttrDefaultDataRate:
		return "DefaultDataRate"
	case SCardAttrMaxDataRate:
		return "MaxDataRate"
	case SCardAttrMaxIFSD:
		return "MaxIFSD"
	case SCardAttrPowerMgmtSupport:
		return "PowerMgmtSupport"
	case SCardAttrUserToCardAuthDevice:
		return "UserToCardAuthDevice"
	case SCardAttrUserAuthInputDevice:
		return "UserAuthInputDevice"
	case SCardAttrCharacteristics:
		return "Characteristics"
	case SCardAttrCurrentProtocolType:
		return "CurrentProtocolType"
	case SCardAttrCurrentClk:
		return "CurrentClk"
	case SCardAttrCurrentF:
		return "CurrentF"
	case SCardAttrCurrentD:
		return "CurrentD"
	case SCardAttrCurrentN:
		return "CurrentN"
	case SCardAttrCurrentW:
		return "CurrentW"
	case SCardAttrCurrentIFSC:
		return "CurrentIFSC"
	case SCardAttrCurrentIFSD:
		return "CurrentIFSD"
	case SCardAttrCurrentBWT:
		return "CurrentBWT"
	case SCardAttrCurrentCWT:
		return "CurrentCWT"
	case SCardAttrCurrentEBCEncoding:
		return "CurrentEBCEncoding"
	case SCardAttrExtendedBWT:
		return "ExtendedBWT"
	case SCardAttrICCPresence:
		return "ICCPresence"
	case SCardAttrICCInterfaceStatus:
		return "ICCInterfaceStatus"
	case SCardAttrCurrentIOState:
		return "CurrentIOState"
	case SCardAttrATRString:
		return "ATRString"
	case SCardAttrICCTYPEPerATR:
		return "ICCTYPEPerATR"
	case SCardAttrESCReset:
		return "ESCReset"
	case SCardAttrESCCancel:
		return "ESCCancel"
	case SCardAttrESCAuthRequest:
		return "ESCAuthRequest"
	case SCardAttrMaxInput:
		return "MaxInput"
	case SCardAttrVendorSpecificInfo:
		return "VendorSpecificInfo"
	case SCardAttrDeviceUnit:
		return "DeviceUnit"
	case SCardAttrDeviceInUse:
		return "DeviceInUse"
	case SCardAttrDeviceFriendlyNameA:
		return "DeviceFriendlyNameA"
	case SCardAttrDeviceSystemNameA:
		return "DeviceSystemNameA"
	case SCardAttrDeviceFriendlyNameW:
	case SCardAttrDeviceFriendlyName:
		return "DeviceFriendlyNameW"
	case SCardAttrDeviceSystemNameW:
	case SCardAttrDeviceSystemName:
		return "DeviceSystemNameW"
	case SCardAttrSuppressT1IFSRequest:
		return "SuppressT1IFSRequest"
	case SCarddAttrPerfNumTransmissions:
		return "PerfNumTransmissions"
	case SCarddAttrPerfBytesTransmitted:
		return "PerfBytesTransmitted"
	case SCarddAttrPerfTransmissionTime:
		return "PerfTransmissionTime"
	}
	return "N/A"
}

// T=0 Protocol Defines
const (
	scardT0HeaderLength = 7
	scardT0CmdLength    = 5
)

// T=1 Protocol Defines
const (
	scardT1PrologueLength    = 3
	scardT1EpilogueLength    = 2 // CRC
	scardT1EpilogueLengthLRC = 1
	scardT1MaxIFs            = 254
)

//
///////////////////////////////////////////////////////////////////////////////
//
//  Reader states
//

type ReaderState dword

const (
	SCardUnknown    ReaderState = 0 // This value implies the driver is unaware of the current state of the reader.
	SCardAbsent     ReaderState = 1 // This value implies there is no card in the reader.
	SCardPresent    ReaderState = 2 // This value implies there is a card is present in the reader, but that it has not been moved into position for use.
	SCardSwallowed  ReaderState = 3 // This value implies there is a card in the reader in position for use. The card is not powered.
	SCardPowered    ReaderState = 4 // This value implies there is power is being provided to the card, but the Reader Driver is unaware of the mode of the card.
	SCardNegotiable ReaderState = 5 // This value implies the card has been reset and is awaiting PTS negotiation.
	SCardSpecific   ReaderState = 6 // This value implies the card has been reset and specific communication protocols have been established.
)

func (s *ReaderState) String() string {
	switch *s {
	case SCardUnknown:
		return "Unknown"
	case SCardAbsent:
		return "Absent"
	case SCardPresent:
		return "Present"
	case SCardSwallowed:
		return "Swallowed"
	case SCardPowered:
		return "Powered"
	case SCardNegotiable:
		return "Negotiable"
	case SCardSpecific:
		return "Specific"
	default:
		return "N/A"
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//  I/O Services
//
//      The following services provide access to the I/O capabilities of the
//      reader drivers.  Services of the Smart Card are requested by placing the
//      following structure into the protocol buffer:
//

type SCardIORequest struct {
	Protocol  dword // Protocol identifier
	PciLength dword // Protocol Control Information Length
}

//
////////////////////////////////////////////////////////////////////////////////
//
//  Driver attribute flags
//

type DriverAttribute dword

const (
	SCardReaderSwallows    DriverAttribute = 0x00000001 // Reader has a card swallowing mechanism.
	SCardReaderEjects      DriverAttribute = 0x00000002 // Reader has a card ejection mechanism.
	SCardReaderConfiscates DriverAttribute = 0x00000004 // Reader has a card capture mechanism.
	SCardReaderContactless DriverAttribute = 0x00000008 // Reader supports contactless.
)

func (a *DriverAttribute) String() string {
	switch *a {
	case SCardReaderSwallows:
		return "Swallows"
	case SCardReaderEjects:
		return "Ejects"
	case SCardReaderConfiscates:
		return "Confiscates"
	case SCardReaderContactless:
		return "Contactless"
	default:
		return "N/A"
	}
}

// /////////////////////////////////////////////////////////////////////////////
//
// Type of reader

type SCardReaderType dword

const (
	SCardReaderTypeSerial     SCardReaderType = 0x01
	SCardReaderTypeParallel   SCardReaderType = 0x02
	SCardReaderTypeKeyboard   SCardReaderType = 0x04
	SCardReaderTypeSCSI       SCardReaderType = 0x08
	SCardReaderTypeIDE        SCardReaderType = 0x10
	SCardReaderTypeUSB        SCardReaderType = 0x20
	SCardReaderTypePCMCIA     SCardReaderType = 0x40
	SCardReaderTypeTPM        SCardReaderType = 0x80
	SCardReaderTypeNFC        SCardReaderType = 0x100
	SCardReaderTypeUICC       SCardReaderType = 0x200
	SCardReaderTypeNGC        SCardReaderType = 0x400
	SCardReaderTypeEmbeddedSE SCardReaderType = 0x800
	SCardReaderTypeVendor     SCardReaderType = 0xF0
)

func (t *SCardReaderType) String() string {
	switch *t {
	case SCardReaderTypeSerial:
		return "Serial"
	case SCardReaderTypeParallel:
		return "Parallel"
	case SCardReaderTypeKeyboard:
		return "Keyboard"
	case SCardReaderTypeSCSI:
		return "SCSI"
	case SCardReaderTypeIDE:
		return "IDE"
	case SCardReaderTypeUSB:
		return "USB"
	case SCardReaderTypePCMCIA:
		return "PCMCIA"
	case SCardReaderTypeTPM:
		return "TPM"
	case SCardReaderTypeNFC:
		return "NFC"
	case SCardReaderTypeUICC:
		return "UICC"
	case SCardReaderTypeNGC:
		return "NGC"
	case SCardReaderTypeEmbeddedSE:
		return "EmbeddedSE"
	case SCardReaderTypeVendor:
		return "Vendor"
	default:
		return "N/A"
	}
}

//////////////////////////////////////////////////////////////////////////////////////
// WinSCard header content.
// From C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\um\winscard.h
//////////////////////////////////////////////////////////////////////////////////////

//
////////////////////////////////////////////////////////////////////////////////
//
//  Service Manager Access Services
//
//      The following services are used to manage user and terminal contexts for
//      Smart Cards.
//

type SCardContext hnd
type SCardHandle hnd

const invalidHandleValue = ^hnd(0)
const scardAutoAllocate = ^dword(0)

type SCardScope dword

const (
	// The context is a user context, and any
	// database operations are performed within the
	// domain of the user.
	SCardScopeUser SCardScope = 0
	// The context is that of the current terminal,
	// and any database operations are performed
	// within the domain of that terminal.  (The
	// calling application must have appropriate
	// access permissions for any database actions.)
	// This flag is currently unused; it is here for
	// compatibility with [PCSC5] section 3.1.3.
	// Using this flag with SCardEstablishContext
	// returns SCARD_E_INVALID_VALUE.
	SCardScopeTerminal SCardScope = 1
	// The context is the system context, and any
	// database operations are performed within the
	// domain of the system.  (The calling
	// application must have appropriate access
	// permissions for any database actions.)
	SCardScopeSystem SCardScope = 2
)

func (s *SCardScope) String() string {
	switch *s {
	case SCardScopeUser:
		return "User"
	case SCardScopeTerminal:
		return "Terminal"
	case SCardScopeSystem:
		return "System"
	default:
		return "N/A"
	}
}

//
////////////////////////////////////////////////////////////////////////////////
//
//  Smart Card Database Management Services
//
//      The following services provide for managing the Smart Card Database.
//

const (
	SCardAllReaders     = "SCard$AllReaders"
	SCardDefaultReaders = "SCard$DefaultReaders"
	SCardLocalReaders   = "SCard$LocalReaders"
	SCardSystemReaders  = "SCard$SystemReaders"
)

type SCardProviderType dword

const (
	SCardProviderPrimary    SCardProviderType = 1          // Primary Provider Id
	SCardProviderCSP        SCardProviderType = 2          // Crypto Service Provider Id
	SCardProviderKSP        SCardProviderType = 3          // Key Storage Provider Id
	SCardProviderCardModule SCardProviderType = 0x80000001 // Name of the card module
)

func (t *SCardProviderType) String() string {
	switch *t {
	case SCardProviderPrimary:
		return "Primary"
	case SCardProviderCSP:
		return "CSP"
	case SCardProviderKSP:
		return "KSP"
	case SCardProviderCardModule:
		return "CardModule"
	default:
		return "N/A"
	}
}

//
////////////////////////////////////////////////////////////////////////////////
//
//  Reader Services
//
//      The following services supply means for tracking cards within readers.
//

// This is the actual golang equivalent of Windows SCardReaderState.
type scardReaderState struct {
	Reader       *uint16        // reader name
	UserData     unsafe.Pointer // user defined data
	CurrentState SCardState     // current state of reader at time of call
	EventState   SCardState     // state of reader after state change
	AtrLen       dword          // Number of bytes in the returned ATR
	Atr          [36]byte       // Atr of inserted card (extra alignment bytes)
}

type SCardReaderState struct {
	Reader       string         // reader name
	UserData     unsafe.Pointer // user defined data
	CurrentState SCardState     // current state of reader at time of call
	EventState   SCardState     // state of reader after state change
	Atr          string         // Atr of inserted card
}

func (s *SCardReaderState) fromInternal(internalReaderState scardReaderState) {
	s.Reader = utf16PtrToString(internalReaderState.Reader)
	s.UserData = internalReaderState.UserData
	s.CurrentState = internalReaderState.CurrentState
	s.EventState = internalReaderState.EventState
	if internalReaderState.AtrLen > 0 {
		s.Atr = byteArrayToHexString(internalReaderState.Atr[:internalReaderState.AtrLen])
	}
}

func (s *SCardReaderState) toInternal() (scardReaderState, error) {
	var atrBytes []byte
	var atr [36]byte
	var atrLen dword
	readerNameUtf16Ptr, err := stringToUtf16Ptr(s.Reader)
	if err != nil {
		return scardReaderState{}, fmt.Errorf("failed to parse reader name \"%s\" (%v)", s.Reader, err)
	}
	if len(s.Atr) > 0 {
		atrBytes, err = hexStringToByteArray(s.Atr)
		if err != nil {
			return scardReaderState{}, fmt.Errorf("failed to parse atr \"%s\" (%v)", s.Atr, err)
		}
		copy(atr[:], atrBytes)
		atrLen = dword(len(atrBytes))
		if len(atrBytes) > 36 {
			atrLen = 36
		}
	}
	return scardReaderState{
		Reader:       readerNameUtf16Ptr,
		UserData:     s.UserData,
		CurrentState: s.CurrentState,
		EventState:   s.EventState,
		AtrLen:       atrLen,
		Atr:          atr,
	}, nil
}

type SCardState dword

const (
	// The application is unaware of the
	// current state, and would like to
	// know.  The use of this value
	// results in an immediate return
	// from state transition monitoring
	// services.  This is represented by
	// all bits set to zero.
	SCardStateUnaware SCardState = 0x00000000
	// The application requested that
	// this reader be ignored.  No other
	// bits will be set.
	SCardStateIgnore SCardState = 0x00000001
	// This implies that there is a
	// difference between the state
	// believed by the application, and
	// the state known by the Service
	// Manager.  When this bit is set,
	// the application may assume a
	// significant state change has
	// occurred on this reader.
	SCardStateChanged SCardState = 0x00000002
	// This implies that the given
	// reader name is not recognized by
	// the Service Manager.  If this bit
	// is set, then SCARD_STATE_CHANGED
	// and SCARD_STATE_IGNORE will also
	// be set.
	SCardStateUnknown SCardState = 0x00000004
	// This implies that the actual
	// state of this reader is not
	// available.  If this bit is set,
	// then all the following bits are
	// clear.
	SCardStateUnavailable SCardState = 0x00000008
	// This implies that there is not
	// card in the reader.  If this bit
	// is set, all the following bits
	// will be clear.
	SCardStateEmpty SCardState = 0x00000010
	// This implies that there is a card
	// in the reader.
	SCardStatePresent SCardState = 0x00000020
	// This implies that there is a card
	// in the reader with an ATR
	// matching one of the target cards.
	// If this bit is set,
	// SCARD_STATE_PRESENT will also be
	// set.  This bit is only returned
	// on the SCardLocateCard() service.
	SCardStateAtrmatch SCardState = 0x00000040
	// This implies that the card in the
	// reader is allocated for exclusive
	// use by another application.  If
	// this bit is set,
	// SCARD_STATE_PRESENT will also be
	// set.
	SCardStateExclusive SCardState = 0x00000080
	// This implies that the card in the
	// reader is in use by one or more
	// other applications, but may be
	// connected to in shared mode.  If
	// this bit is set,
	// SCARD_STATE_PRESENT will also be
	// set.
	SCardStateInuse SCardState = 0x00000100
	// This implies that the card in the
	// reader is unresponsive or not
	// supported by the reader or
	// software.
	SCardStateMute SCardState = 0x00000200
	// This implies that the card in the
	// reader has not been powered up.
	SCardStateUnpowered SCardState = 0x00000400
)

func (s *SCardState) String() string {
	output := ""

	if *s == SCardStateUnaware {
		output += "Unaware;"
	} else {
		if *s&SCardStateIgnore == SCardStateIgnore {
			output += "Ignore;"
		}
		if *s&SCardStateChanged == SCardStateChanged {
			output += "Changed;"
		}
		if *s&SCardStateUnknown == SCardStateUnknown {
			output += "Unknown;"
		}
		if *s&SCardStateUnavailable == SCardStateUnavailable {
			output += "Unavailable;"
		}
		if *s&SCardStateEmpty == SCardStateEmpty {
			output += "Empty;"
		}
		if *s&SCardStatePresent == SCardStatePresent {
			output += "Present;"
		}
		if *s&SCardStateAtrmatch == SCardStateAtrmatch {
			output += "Atrmatch;"
		}
		if *s&SCardStateExclusive == SCardStateExclusive {
			output += "Exclusive;"
		}
		if *s&SCardStateInuse == SCardStateInuse {
			output += "Inuse;"
		}
		if *s&SCardStateMute == SCardStateMute {
			output += "Mute;"
		}
		if *s&SCardStateUnpowered == SCardStateUnpowered {
			output += "Unpowered;"
		}
	}

	return output
}

// This is the actual golang equivalent of Windows SCardAtrMask.
type scardAtrMask struct {
	AtrLen dword    // Number of bytes in the ATR and the mask
	Atr    [36]byte // Atr of card (extra alignment bytes)
	Mask   [36]byte // Mask for the Atr (extra alignment bytes)
}

type SCardAtrMask struct {
	Atr  string // Atr of card
	Mask string // Mask for the Atr
}

func (s *SCardAtrMask) fromInternal(internalSCardAtrMask scardAtrMask) {
	if internalSCardAtrMask.AtrLen > 0 {
		s.Atr = byteArrayToHexString(internalSCardAtrMask.Atr[:internalSCardAtrMask.AtrLen])
		s.Mask = byteArrayToHexString(internalSCardAtrMask.Mask[:internalSCardAtrMask.AtrLen])
	}
}

func (s *SCardAtrMask) toInternal() (scardAtrMask, error) {
	var atrBytes []byte
	var atr [36]byte
	var atrLen dword
	var maskBytes []byte
	var mask [36]byte
	var err error

	if len(s.Atr) != len(s.Mask) {
		return scardAtrMask{}, fmt.Errorf("atr and atrmask do not have the same length")
	}
	if s.Atr != "" && s.Mask != "" {
		atrBytes, err = hexStringToByteArray(s.Atr)
		if err != nil {
			return scardAtrMask{}, fmt.Errorf("failed to parse atr \"%s\" (%v)", s.Atr, err)
		}
		maskBytes, err = hexStringToByteArray(s.Mask)
		if err != nil {
			return scardAtrMask{}, fmt.Errorf("failed to parse atrmask \"%s\" (%v)", s.Mask, err)
		}

		copy(atr[:], atrBytes)
		copy(mask[:], maskBytes)
		atrLen = dword(len(atrBytes))
		if len(atrBytes) > 36 {
			atrLen = 36
		}
	}

	return scardAtrMask{
		AtrLen: atrLen,
		Atr:    atr,
		Mask:   mask,
	}, nil
}

//
////////////////////////////////////////////////////////////////////////////////
//
//  Card/Reader Communication Services
//
//      The following services provide means for communication with the card.
//

type SCardShareMode dword

const (
	// This application is not willing to share this
	// card with other applications.
	SCardShareExclusive SCardShareMode = 1
	// This application is willing to share this
	// card with other applications.
	SCardShareShared SCardShareMode = 2
	// This application demands direct control of
	// the reader, so it is not available to other
	// applications.
	SCardShareDirect SCardShareMode = 3
)

func (m *SCardShareMode) String() string {
	switch *m {
	case SCardShareExclusive:
		return "Exclusive"
	case SCardShareShared:
		return "Shared"
	case SCardShareDirect:
		return "Direct"
	default:
		return "N/A"
	}
}

type SCardDisposition dword

const (
	// Don't do anything special on close
	SCardLeaveCard SCardDisposition = 0
	// Reset the card on close
	SCardResetCard SCardDisposition = 1
	// Power down the card on close
	SCardUnpowerCard SCardDisposition = 2
	// Eject the card on close
	SCardEjectCard SCardDisposition = 3
)

func (d *SCardDisposition) String() string {
	switch *d {
	case SCardLeaveCard:
		return "LeaveCard"
	case SCardResetCard:
		return "ResetCard"
	case SCardUnpowerCard:
		return "UnpowerCard"
	case SCardEjectCard:
		return "EjectCard"
	default:
		return "N/A"
	}
}

type SCardAuditEvent dword

const (
	// A smart card holder verification (CHV)
	// attempt failed.
	SCardAuditCHVFailure SCardAuditEvent = 0x0
	// A smart card holder verification (CHV)
	// attempt succeeded.
	SCardAuditCHVSuccess SCardAuditEvent = 0x1
)

func (e *SCardAuditEvent) String() string {
	switch *e {
	case SCardAuditCHVFailure:
		return "CHVFailure"
	case SCardAuditCHVSuccess:
		return "CHVSuccess"
	default:
		return "N/A"
	}
}

//////////////////////////////////////////////////////////////////////////////////////
// DLL references.
//////////////////////////////////////////////////////////////////////////////////////

var (
	kernel32 *windows.DLL
	winScard *windows.DLL

	getProcAddressProc *windows.Proc

	scardAccessStartedEventProc              *windows.Proc
	scardAddReaderToGroupProc                *windows.Proc
	scardAuditProc                           *windows.Proc
	scardBeginTransactionProc                *windows.Proc
	scardCancelProc                          *windows.Proc
	scardConnectProc                         *windows.Proc
	scardControlProc                         *windows.Proc
	scardDisconnectProc                      *windows.Proc
	scardEndTransactionProc                  *windows.Proc
	scardCancelTransactionProc               *windows.Proc
	scardEstablishContextProc                *windows.Proc
	scardForgetCardTypeProc                  *windows.Proc
	scardForgetReaderGroupProc               *windows.Proc
	scardForgetReaderProc                    *windows.Proc
	scardFreeMemoryProc                      *windows.Proc
	scardGetAttribProc                       *windows.Proc
	scardGetCardTypeProviderNameProc         *windows.Proc
	scardGetDeviceTypeIdProc                 *windows.Proc
	scardGetProviderIdProc                   *windows.Proc
	scardGetReaderDeviceInstanceIdProc       *windows.Proc
	scardGetReaderIconProc                   *windows.Proc
	scardGetStatusChangeProc                 *windows.Proc
	scardGetTransmitCountProc                *windows.Proc
	scardIntroduceCardTypeProc               *windows.Proc
	scardIntroduceReaderGroupProc            *windows.Proc
	scardIntroduceReaderProc                 *windows.Proc
	scardIsValidContextProc                  *windows.Proc
	scardListCardsProc                       *windows.Proc
	scardListInterfacesProc                  *windows.Proc
	scardListReaderGroupsProc                *windows.Proc
	scardListReadersProc                     *windows.Proc
	scardListReadersWithDeviceInstanceIdProc *windows.Proc
	scardLocateCardsByATRProc                *windows.Proc
	scardLocateCardsProc                     *windows.Proc
	scardReadCacheProc                       *windows.Proc
	scardReconnectProc                       *windows.Proc
	scardReleaseContextProc                  *windows.Proc
	scardReleaseStartedEventProc             *windows.Proc
	scardRemoveReaderFromGroupProc           *windows.Proc
	scardSetAttribProc                       *windows.Proc
	scardSetCardTypeProviderNameProc         *windows.Proc
	scardStatusProc                          *windows.Proc
	scardTransmitProc                        *windows.Proc
	scardWriteCacheProc                      *windows.Proc
	scardPciT0                               *windows.Proc
	scardPciT1                               *windows.Proc
	scardPciRaw                              *windows.Proc

	SCardIoRequestT0  SCardIORequest
	SCardIoRequestT1  SCardIORequest
	SCardIoRequestRaw SCardIORequest

	winScardProcs = map[string]**windows.Proc{
		"SCardAccessStartedEvent":               &scardAccessStartedEventProc,
		"SCardAddReaderToGroupW":                &scardAddReaderToGroupProc,
		"SCardAudit":                            &scardAuditProc,
		"SCardBeginTransaction":                 &scardBeginTransactionProc,
		"SCardCancel":                           &scardCancelProc,
		"SCardConnectW":                         &scardConnectProc,
		"SCardControl":                          &scardControlProc,
		"SCardDisconnect":                       &scardDisconnectProc,
		"SCardEndTransaction":                   &scardEndTransactionProc,
		"SCardCancelTransaction":                &scardCancelTransactionProc,
		"SCardEstablishContext":                 &scardEstablishContextProc,
		"SCardForgetCardTypeW":                  &scardForgetCardTypeProc,
		"SCardForgetReaderGroupW":               &scardForgetReaderGroupProc,
		"SCardForgetReaderW":                    &scardForgetReaderProc,
		"SCardFreeMemory":                       &scardFreeMemoryProc,
		"SCardGetAttrib":                        &scardGetAttribProc,
		"SCardGetCardTypeProviderNameW":         &scardGetCardTypeProviderNameProc,
		"SCardGetDeviceTypeIdW":                 &scardGetDeviceTypeIdProc,
		"SCardGetProviderIdW":                   &scardGetProviderIdProc,
		"SCardGetReaderDeviceInstanceIdW":       &scardGetReaderDeviceInstanceIdProc,
		"SCardGetReaderIconW":                   &scardGetReaderIconProc,
		"SCardGetStatusChangeW":                 &scardGetStatusChangeProc,
		"SCardGetTransmitCount":                 &scardGetTransmitCountProc,
		"SCardIntroduceCardTypeW":               &scardIntroduceCardTypeProc,
		"SCardIntroduceReaderGroupW":            &scardIntroduceReaderGroupProc,
		"SCardIntroduceReaderW":                 &scardIntroduceReaderProc,
		"SCardIsValidContext":                   &scardIsValidContextProc,
		"SCardListCardsW":                       &scardListCardsProc,
		"SCardListInterfacesW":                  &scardListInterfacesProc,
		"SCardListReaderGroupsW":                &scardListReaderGroupsProc,
		"SCardListReadersW":                     &scardListReadersProc,
		"SCardListReadersWithDeviceInstanceIdW": &scardListReadersWithDeviceInstanceIdProc,
		"SCardLocateCardsByATRW":                &scardLocateCardsByATRProc,
		"SCardLocateCardsW":                     &scardLocateCardsProc,
		"SCardReadCacheW":                       &scardReadCacheProc,
		"SCardReconnect":                        &scardReconnectProc,
		"SCardReleaseContext":                   &scardReleaseContextProc,
		"SCardReleaseStartedEvent":              &scardReleaseStartedEventProc,
		"SCardRemoveReaderFromGroupW":           &scardRemoveReaderFromGroupProc,
		"SCardSetAttrib":                        &scardSetAttribProc,
		"SCardSetCardTypeProviderNameW":         &scardSetCardTypeProviderNameProc,
		"SCardStatusW":                          &scardStatusProc,
		"SCardTransmit":                         &scardTransmitProc,
		"SCardWriteCacheW":                      &scardWriteCacheProc,
		"g_rgSCardT0Pci":                        &scardPciT0,
		"g_rgSCardT1Pci":                        &scardPciT1,
		"g_rgSCardRawPci":                       &scardPciRaw,
	}
)

//////////////////////////////////////////////////////////////////////////////////////
// SCard functions.
//////////////////////////////////////////////////////////////////////////////////////

// Initialize is the very first function that must be called
// on goscard. It ensures that the underlying pcsc library and all
// its functions are loaded.
//
// If customLogger is nil, the library will use its default logger
// which will print log messages to stderr using INFO log level.
// To disable logging, a NewDefaultLogger can be passed with LogLevel
// set to LogLevelNone.
//
// If scardLibPaths is not set, the library will look for
// winscard in its usual places (e.g. C:\\Windows\\System32\\WinSCard.dll).
// Otherwise, the specified paths will be used.
func Initialize(customLogger Logger, scardLibPaths ...string) (errRet error) {
	if winScard == nil {
		// Set logger.
		if customLogger != nil {
			logger = customLogger
		}

		defer func() {
			if errRet != nil {
				logger.Error(errRet)
			}
		}()

		// Get System32 directory.
		systemDirPath, err := windows.GetSystemDirectory()
		if err != nil {
			errRet = fmt.Errorf("failed to get system directory: %v", err)
			return
		}
		logger.Debugf("Using system directory \"%s\"", systemDirPath)

		// Load kernel32 dll to get GetProcAddress.
		kernel32Lib := systemDirPath + "\\kernel32.dll"
		logger.Debugf("Loading Kernel32 at \"%s\"", kernel32Lib)
		kernel32, err = windows.LoadDLL(kernel32Lib)
		if err != nil {
			errRet = fmt.Errorf("could not load kernel32 library (%v)", err)
			return
		}
		getProcAddressProc, err = kernel32.FindProc("GetProcAddress")
		if err != nil {
			errRet = fmt.Errorf("could not find \"GetProcAddress\" in kernel32 library (%v)", err)
			return
		}

		// Construct the winscard paths.
		winScardLibPaths := scardLibPaths
		if winScardLibPaths == nil {
			winScardLibPaths = []string{filepath.Join(systemDirPath, "WinSCard.dll")}
		}

		// Load winscard.dll.
		for _, winScardLibPath := range winScardLibPaths {
			logger.Debugf("Loading WinSCard at \"%s\"", winScardLibPath)
			winScard, err = windows.LoadDLL(winScardLibPath)
			if err != nil {
				logger.Errorf("Failed to load WinSCard at \"%s\" (%v)", winScardLibPath, err)
			} else if winScard == nil {
				logger.Errorf("WinSCard loaded at \"%s\" is nil (%v)", winScardLibPath, err)
			} else {
				break
			}
		}
		if winScard == nil {
			errRet = fmt.Errorf("could not load Winscard library")
			return
		}

		// Find scard functions.
		for winScardProcName, winScardProc := range winScardProcs {
			winScardProcNamePtr, err := windows.BytePtrFromString(winScardProcName)
			if err != nil {
				logger.Errorf("Could not parse proc name \"%s\" (%v)", winScardProcName, err)
			} else {
				r, _, err := getProcAddressProc.Call(
					uintptr(winScard.Handle),
					uintptr(unsafe.Pointer(winScardProcNamePtr)))
				if r != 0 {
					// FindProc performs GetProcAddress internally.
					// Therefore, we do not need to perform error checking
					// if our GetProcAddress succeeds.
					*winScardProc, _ = winScard.FindProc(winScardProcName)
				} else if err != nil {
					if err == windows.ERROR_PROC_NOT_FOUND {
						logger.Warnf("Could not find \"%s\"", winScardProcName)
					} else {
						logger.Errorf("Failed to find \"%s\" (%v)", winScardProcName, err)
					}
				}
			}
		}
		if scardPciT0 != nil {
			SCardIoRequestT0St := unsafe.Slice((*SCardIORequest)(unsafe.Pointer(scardPciT0.Addr())), 1)
			if len(SCardIoRequestT0St) == 1 {
				SCardIoRequestT0 = SCardIoRequestT0St[0]
			}
		} else {
			// If, for some reason, we're not able to gather SCardIoRequestT0 from winScard,
			// we set it manually.
			SCardIoRequestT0 = SCardIORequest{
				Protocol:  dword(SCardProtocolT0),
				PciLength: dword(unsafe.Sizeof(SCardIORequest{})),
			}
		}
		if scardPciT1 != nil {
			SCardIoRequestT1St := unsafe.Slice((*SCardIORequest)(unsafe.Pointer(scardPciT1.Addr())), 1)
			if len(SCardIoRequestT1St) == 1 {
				SCardIoRequestT1 = SCardIoRequestT1St[0]
			}
		} else {
			// If, for some reason, we're not able to gather SCardIoRequestT1 from winScard,
			// we set it manually.
			SCardIoRequestT1 = SCardIORequest{
				Protocol:  dword(SCardProtocolT1),
				PciLength: dword(unsafe.Sizeof(SCardIORequest{})),
			}
		}
		if scardPciRaw != nil {
			SCardIoRequestRawSt := unsafe.Slice((*SCardIORequest)(unsafe.Pointer(scardPciRaw.Addr())), 1)
			if len(SCardIoRequestRawSt) == 1 {
				SCardIoRequestRaw = SCardIoRequestRawSt[0]
			}
		} else {
			// If, for some reason, we're not able to gather SCardIoRequestRaw from winScard,
			// we set it manually.
			SCardIoRequestRaw = SCardIORequest{
				Protocol:  dword(SCardProtocolRaw),
				PciLength: dword(unsafe.Sizeof(SCardIORequest{})),
			}
		}

		return
	} else {
		errRet = fmt.Errorf("goscard already initialized")
		return
	}
}

// Finalize is the very last function that must be called
// on goscard. It ensures that the previously loaded
// pcsc library and functions are unloaded.
func Finalize() {
	if winScard != nil {
		winScard.Release()
		winScard = nil

		scardAccessStartedEventProc = nil
		scardAddReaderToGroupProc = nil
		scardAuditProc = nil
		scardBeginTransactionProc = nil
		scardCancelProc = nil
		scardConnectProc = nil
		scardControlProc = nil
		scardDisconnectProc = nil
		scardEndTransactionProc = nil
		scardCancelTransactionProc = nil
		scardEstablishContextProc = nil
		scardForgetCardTypeProc = nil
		scardForgetReaderGroupProc = nil
		scardForgetReaderProc = nil
		scardFreeMemoryProc = nil
		scardGetAttribProc = nil
		scardGetCardTypeProviderNameProc = nil
		scardGetDeviceTypeIdProc = nil
		scardGetProviderIdProc = nil
		scardGetReaderDeviceInstanceIdProc = nil
		scardGetReaderIconProc = nil
		scardGetStatusChangeProc = nil
		scardGetTransmitCountProc = nil
		scardIntroduceCardTypeProc = nil
		scardIntroduceReaderGroupProc = nil
		scardIntroduceReaderProc = nil
		scardIsValidContextProc = nil
		scardListCardsProc = nil
		scardListInterfacesProc = nil
		scardListReaderGroupsProc = nil
		scardListReadersProc = nil
		scardListReadersWithDeviceInstanceIdProc = nil
		scardLocateCardsByATRProc = nil
		scardLocateCardsProc = nil
		scardReadCacheProc = nil
		scardReconnectProc = nil
		scardReleaseContextProc = nil
		scardReleaseStartedEventProc = nil
		scardRemoveReaderFromGroupProc = nil
		scardSetAttribProc = nil
		scardSetCardTypeProviderNameProc = nil
		scardStatusProc = nil
		scardTransmitProc = nil
		scardWriteCacheProc = nil
		scardPciT0 = nil
		scardPciT1 = nil
		scardPciRaw = nil
	}
}

// NewContext is a wrapper around SCardEstablichContext.
//
// This function establishes the resource manager context (the scope)
// within which database operations are performed.
func NewContext(
	scope SCardScope,
	reserved1 unsafe.Pointer,
	reserved2 unsafe.Pointer,
) (context Context, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var scardContext SCardContext
	context.ctx = SCardContext(invalidHandleValue)

	logger.Infof("NewContext, IN : (scope=%s, reserved1=%p, reserved2=%p)",
		scope.String(), reserved1, reserved2)
	defer func() { logger.Infof("NewContext, OUT: (context=0x%X)", scardContext) }()

	if scardEstablishContextProc == nil {
		err = fmt.Errorf("scardEstablishContext() not found in winscard.dll")
		return
	}

	r, _, msg := scardEstablishContextProc.Call(
		uintptr(scope),                         /* DWORD */
		uintptr(reserved1),                     /* LPCVOID */
		uintptr(reserved2),                     /* LPCVOID */
		uintptr(unsafe.Pointer(&scardContext)), /* LPSCARDCONTEXT */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardEstablishContext() returned 0x%X [%v]", r, msg)
		return
	}

	context.ctx = scardContext

	return
}

// Release function is a wrapper around SCardReleaseContext.
//
// This function closes an established resource manager context,
// freeing any resources allocated under that context, including SCardHandle
// objects and memory allocated using the scardAutoAllocate length designator.
func (c *Context) Release() (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("Release, IN : (context=0x%X)", c.ctx)
	defer func() { logger.Infof("Release, OUT : (context=0x%X)", c.ctx) }()

	if scardReleaseContextProc == nil {
		err = fmt.Errorf("scardReleaseContext() not found in winscard.dll")
		return
	}

	r, _, msg := scardReleaseContextProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardReleaseContext() returned 0x%X [%v]", r, msg)
		return
	}

	c.ctx = SCardContext(invalidHandleValue)

	return
}

// IsValid is a wrapper around SCardIsValidContext.
//
// This function determines whether a smart card context handle is valid.
func (c *Context) IsValid() (isValid bool, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("IsValid, IN : (context=0x%X)", c.ctx)
	defer func() { logger.Infof("IsValid, OUT: (context=0x%X)", c.ctx) }()

	if scardIsValidContextProc == nil {
		err = fmt.Errorf("scardIsValidContext() not found in winscard.dll")
		return
	}

	r, _, msg := scardIsValidContextProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardIsValidContext() returned 0x%X [%v]", r, msg)
		return
	}

	isValid = true
	return
}

// ListReaders is a wrapper around SCardListReaders.
//
// This function provides the list of readers within
// a set of named reader groups, eliminating duplicates.
// The caller supplies a list of reader groups, and receives the
// list of readers within the named groups. Unrecognized group names
// are ignored. This function only returns readers within the named
// groups that are currently attached to the system and available for use.
func (c *Context) ListReaders(
	groups []string,
) (readers []string, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var groupsUtf16 []uint16
	var groupsUtf16Ptr *uint16
	var readersUtf16 []uint16
	var readersUtf16Len dword

	logger.Infof("ListReaders, IN : (context=0x%X, groups=%v)", c.ctx, groups)
	defer func() { logger.Infof("ListReaders, OUT: (context=0x%X, readers=%v)", c.ctx, readers) }()

	if scardListReadersProc == nil {
		err = fmt.Errorf("scardListReaders() not found in winscard.dll")
		return
	}

	if len(groups) > 0 {
		groupsUtf16, err = stringsToMultiUtf16String(groups)
		if err != nil {
			err = fmt.Errorf("failed to parse groups (%v)", err)
			return
		}
		groupsUtf16Ptr = &groupsUtf16[0]
	}

	r, _, msg := scardListReadersProc.Call(
		uintptr(c.ctx),                            /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(groupsUtf16Ptr)),   /* LPCWSTR */
		uintptr(0),                                /* LPWSTR */
		uintptr(unsafe.Pointer(&readersUtf16Len)), /* LPDWORD */
	)
	if r != 0 {
		ret = uint64(r)
		if r != 0x8010002E && r != 0x8010001E { // SCARD_E_NO_READERS_AVAILABLE / SCARD_E_SERVICE_STOPPED
			if winErr := maybePcscErr(r); winErr != nil {
				msg = winErr
			}
			err = fmt.Errorf("scardListReaders() 1st call returned 0x%X [%v]", r, msg)
		}
		return
	}

	if readersUtf16Len > 0 {
		readersUtf16 = make([]uint16, readersUtf16Len)
		r, _, msg = scardListReadersProc.Call(
			uintptr(c.ctx),                            /* SCARDCONTEXT */
			uintptr(unsafe.Pointer(groupsUtf16Ptr)),   /* LPCWSTR */
			uintptr(unsafe.Pointer(&readersUtf16[0])), /* LPWSTR */
			uintptr(unsafe.Pointer(&readersUtf16Len)), /* LPDWORD */
		)
		if r != 0 {
			ret = uint64(r)
			if r != 0x8010002E && r != 0x8010001E { // SCARD_E_NO_READERS_AVAILABLE / SCARD_E_SERVICE_STOPPED
				if winErr := maybePcscErr(r); winErr != nil {
					msg = winErr
				}
				err = fmt.Errorf("scardListReaders() 2nd call returned 0x%X [%v]", r, msg)
			}
			return
		}

		if readersUtf16Len > 0 && readersUtf16 != nil {
			readersUtf16 = readersUtf16[:readersUtf16Len]
			readers, err = multiUtf16StringToStrings(readersUtf16)
			if err != nil {
				readers = nil
				err = fmt.Errorf("failed to parse readers names %v (%v))", readersUtf16, err)
				return
			}
		}
	}

	return
}

// FreeMemory is a wrapper around SCardFreeMemory.
//
// This function releases memory that has been
// returned from the resource manager using the
// scardAutoAllocate length designator.
func (c *Context) FreeMemory(
	mem unsafe.Pointer,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("FreeMemory, IN : (context=0x%X, mem=%p)", c.ctx, mem)
	defer func() { logger.Infof("FreeMemory, OUT: (context=0x%X, mem=%p)", c.ctx, mem) }()

	if scardFreeMemoryProc == nil {
		err = fmt.Errorf("scardFreeMemory() not found in winscard.dll")
		return
	}

	r, _, msg := scardFreeMemoryProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(mem),   /* LPCVOID */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardFreeMemory() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// GetStatusChange is a wrapper around SCardGetStatusChange.
//
// This function blocks execution until
// the current availability of the cards in a specific
// set of readers changes.
// The caller supplies a list of readers to be monitored
// by an SCardReaderState array and the maximum amount
// of time (in milliseconds) that it is willing to wait
// for an action to occur on one of the listed readers.
// Note that SCardGetStatusChange uses the user-supplied
// value in the CurrentState members of the readerStates
// array as the definition of the current state of the readers.
// The function returns when there is a change in availability,
// having filled in the EventState members of rgReaderStates
// appropriately.
//
// N.B: The function will update the SCardStates inside of the
// passed SCardReaderState array.
func (c *Context) GetStatusChange(
	timeout Timeout,
	readerStates []SCardReaderState,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var internalReaderStates []scardReaderState
	var internalReaderStatesPtr *scardReaderState

	logger.Infof("GetStatusChange, IN : (context=0x%X, timeout=%vms, readerStates=%v)",
		c.ctx, timeout.Milliseconds(), readerStates)
	defer func() { logger.Infof("GetStatusChange, OUT: (context=0x%X, readerStates=%v)", c.ctx, readerStates) }()

	if scardGetStatusChangeProc == nil {
		err = fmt.Errorf("scardGetStatusChange() not found in winscard.dll")
		return
	}

	if len(readerStates) > 0 {
		internalReaderStates = make([]scardReaderState, len(readerStates))
		for i, readerState := range readerStates {
			internalReaderStates[i], err = readerState.toInternal()
			if err != nil {
				return
			}
		}
		internalReaderStatesPtr = (*scardReaderState)(unsafe.Pointer(&internalReaderStates[0]))
	}

	r, _, msg := scardGetStatusChangeProc.Call(
		uintptr(c.ctx),                                   /* SCARDCONTEXT */
		uintptr(timeout.Milliseconds()),                  /* DWORD */
		uintptr(unsafe.Pointer(internalReaderStatesPtr)), /* LPSCARD_READERSTATEW */
		uintptr(len(readerStates)),                       /* DWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardGetStatusChange() returned 0x%X [%v]", r, msg)
		return
	}

	for i, internalReaderState := range internalReaderStates {
		readerStates[i].fromInternal(internalReaderState)
	}

	return
}

// Cancel is a wrapper around SCardCancel.
//
// This function terminates all outstanding
// actions within a specific resource manager context.
// The only requests that you can cancel are those that
// require waiting for external action by the smart card
// or user. Any such outstanding action requests will
// terminate with a status indication that the action was
// canceled. This is especially useful to force outstanding
// SCardGetStatusChange calls to terminate.
func (c *Context) Cancel() (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("Cancel, IN : (context=0x%X)", c.ctx)
	defer func() { logger.Infof("Cancel, OUT: (context=0x%X)", c.ctx) }()

	if scardCancelProc == nil {
		err = fmt.Errorf("scardCancel() not found in winscard.dll")
		return
	}

	r, _, msg := scardCancelProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardCancel() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// Connect is a wrapper around SCardConnect.
//
// This function establishes a connection
// (using a specific resource manager context)
// between the calling application and a smart card
// contained by a specific reader. If no card exists
// in the specified reader, an error is returned.
func (c *Context) Connect(
	readerName string,
	shareMode SCardShareMode,
	preferredProtocols SCardProtocol,
) (card Card, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var scardHandle SCardHandle
	var activeProtocol SCardProtocol
	var readerNamesUtf16 []uint16
	var readerNamesUtf16Ptr *uint16
	card.handle = SCardHandle(invalidHandleValue)

	logger.Infof("Connect, IN : (context=0x%X, readerName=%s, shareMode=%s, preferredProtocols=%s)",
		c.ctx, readerName, shareMode.String(), preferredProtocols.String())
	defer func() {
		logger.Infof("Connect, OUT: (context=0x%X, handle=0x%X, protocol=%s)",
			c.ctx, card.handle, card.activeProtocol.String())
	}()

	if scardConnectProc == nil {
		err = fmt.Errorf("scardConnect() not found in winscard.dll")
		return
	}

	if len(readerName) > 0 {
		readerNamesUtf16, err = stringToUtf16(readerName)
		if err != nil {
			err = fmt.Errorf("failed to parse reader name \"%s\" (%v)", readerName, err)
			return
		}
		readerNamesUtf16Ptr = (*uint16)(unsafe.Pointer(&readerNamesUtf16[0]))
	}

	r, _, msg := scardConnectProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(readerNamesUtf16Ptr)), /* LPCWSTR */
		uintptr(shareMode),                           /* DWORD */
		uintptr(preferredProtocols),                  /* DWORD */
		uintptr(unsafe.Pointer(&scardHandle)),        /* LPSCARDHANDLE */
		uintptr(unsafe.Pointer(&activeProtocol)),     /* LPDWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardConnect() returned 0x%X [%v]", r, msg)
		return
	}

	card.handle = scardHandle
	card.activeProtocol = activeProtocol

	return
}

// Reconnect is a wrapper around SCardReconnect.
//
// This function reestablishes an existing
// connection between the calling application and a
// smart card. This function moves a card handle from
// direct access to general access, or acknowledges and
// clears an error condition that is preventing further
// access to the card.
func (c *Card) Reconnect(
	shareMode SCardShareMode,
	preferredProtocols SCardProtocol,
	initialization SCardDisposition,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var activeProtocol SCardProtocol

	logger.Infof("Reconnect, IN : (handle=0x%X, shareMode=%s, preferredProtocols=%s, initialization=%s)",
		c.handle, shareMode.String(), preferredProtocols.String(), initialization.String())
	defer func() {
		logger.Infof("Reconnect, OUT: (handle=0x%X, protocol=%s)", c.handle, c.activeProtocol.String())
	}()

	if scardReconnectProc == nil {
		err = fmt.Errorf("scardReconnect() not found in winscard.dll")
		return
	}

	r, _, msg := scardReconnectProc.Call(
		uintptr(c.handle),                        /* SCARDHANDLE */
		uintptr(shareMode),                       /* DWORD */
		uintptr(preferredProtocols),              /* DWORD */
		uintptr(initialization),                  /* DWORD */
		uintptr(unsafe.Pointer(&activeProtocol)), /* LPDWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardReconnect() returned 0x%X [%v]", r, msg)
		return
	}

	c.activeProtocol = activeProtocol

	return
}

// Disconnect is a wrapper around SCardDisconnect.
//
// This function terminates a connection
// previously opened between the calling application
// and a smart card in the target reader.
func (c *Card) Disconnect(
	scardDisposition SCardDisposition,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("Disconnect, IN : (handle=0x%X, scardDisposition=%s)",
		c.handle, scardDisposition.String())
	defer func() { logger.Infof("Disconnect, OUT: (handle=0x%X)", c.handle) }()

	if scardDisconnectProc == nil {
		err = fmt.Errorf("scardDisconnect() not found in winscard.dll")
		return
	}

	r, _, msg := scardDisconnectProc.Call(
		uintptr(c.handle),         /* SCARDHANDLE */
		uintptr(scardDisposition), /* DWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardDisconnect() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// BeginTransaction is a wrapper around SCardBeginTransaction.
//
// This function starts a transaction.
// The function waits for the completion of all other
// transactions before it begins. After the transaction
// starts, all other applications are blocked from accessing
// the smart card while the transaction is in progress.
func (c *Card) BeginTransaction() (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("BeginTransaction, IN : (handle=0x%X)", c.handle)
	defer func() { logger.Infof("BeginTransaction, OUT: (handle=0x%X)", c.handle) }()

	if scardBeginTransactionProc == nil {
		err = fmt.Errorf("scardBeginTransaction() not found in winscard.dll")
		return
	}

	r, _, msg := scardBeginTransactionProc.Call(
		uintptr(c.handle), /* SCARDHANDLE */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardBeginTransaction() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// EndTransaction is a wrapper around SCardEndTransaction.
//
// This function completes a previously
// declared transaction, allowing other applications
// to resume interactions with the card.
func (c *Card) EndTransaction(
	scardDisposition SCardDisposition,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("EndTransaction, IN : (handle=0x%X, scardDisposition=%s)",
		c.handle, scardDisposition.String())
	defer func() {
		logger.Infof("EndTransaction, IN : (handle=0x%X, scardDisposition=%s)",
			c.handle, scardDisposition.String())
	}()

	if scardEndTransactionProc == nil {
		err = fmt.Errorf("scardEndTransaction() not found in winscard.dll")
		return
	}

	r, _, msg := scardEndTransactionProc.Call(
		uintptr(c.handle),         /* SCARDHANDLE */
		uintptr(scardDisposition), /* DWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardEndTransaction() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// Status is a wrapper around SCardStatus.
//
// This function provides the current status of
// a smart card in a reader. You can call it any time
// after a successful call to SCardConnect and before
// a successful call to SCardDisconnect. It does not
// affect the state of the reader or reader driver.
func (c *Card) Status() (cardStatus CardStatus, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var readerNames []string
	var readerState ReaderState
	var scardProtocol SCardProtocol
	var readerNamesUtf16 []uint16
	var readerNamesUtf16Len dword
	var readerNamesUtf16Ptr *uint16
	var atrBytes []byte
	var atrBytesLen dword
	var atrBytesPtr *byte

	logger.Infof("Status, IN : (handle=0x%X)", c.handle)
	defer func() { logger.Infof("Status, OUT: (handle=0x%X, status=%v)", c.handle, cardStatus) }()

	if scardStatusProc == nil {
		err = fmt.Errorf("scardStatus() not found in winscard.dll")
		return
	}

	r, _, msg := scardStatusProc.Call(
		uintptr(c.handle), /* SCARDHANDLE */
		uintptr(0),        /* LPCWSTR */
		uintptr(unsafe.Pointer(&readerNamesUtf16Len)), /* LPDWORD */
		uintptr(unsafe.Pointer(&readerState)),         /* LPDWORD */
		uintptr(unsafe.Pointer(&scardProtocol)),       /* LPDWORD */
		uintptr(0),                                    /* LPBYTE */
		uintptr(unsafe.Pointer(&atrBytesLen)),         /* LPDWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardStatus() 1st call returned 0x%X [%v]", r, msg)
		return
	}
	if readerNamesUtf16Len > 0 || atrBytesLen > 0 {
		if readerNamesUtf16Len > 0 {
			readerNamesUtf16 = make([]uint16, readerNamesUtf16Len)
			readerNamesUtf16Ptr = &readerNamesUtf16[0]
		}
		if atrBytesLen > 0 {
			atrBytes = make([]byte, atrBytesLen)
			atrBytesPtr = &atrBytes[0]
		}

		r, _, msg = scardStatusProc.Call(
			uintptr(c.handle), /* SCARDHANDLE */
			uintptr(unsafe.Pointer(readerNamesUtf16Ptr)),  /* LPCWSTR */
			uintptr(unsafe.Pointer(&readerNamesUtf16Len)), /* LPDWORD */
			uintptr(unsafe.Pointer(&readerState)),         /* LPDWORD */
			uintptr(unsafe.Pointer(&scardProtocol)),       /* LPDWORD */
			uintptr(unsafe.Pointer(atrBytesPtr)),          /* LPBYTE */
			uintptr(unsafe.Pointer(&atrBytesLen)),         /* LPDWORD */
		)
		if r != 0 {
			if winErr := maybePcscErr(r); winErr != nil {
				msg = winErr
			}
			ret = uint64(r)
			err = fmt.Errorf("scardStatus() 2nd call returned 0x%X [%v]", r, msg)
			return
		}

		if readerNamesUtf16Len > 0 && readerNamesUtf16 != nil {
			readerNamesUtf16 = readerNamesUtf16[:readerNamesUtf16Len]
			readerNames, err = multiUtf16StringToStrings(readerNamesUtf16)
			if err != nil {
				err = fmt.Errorf("failed to parse reader names %v (%v)", readerNamesUtf16, err)
				return
			}

			cardStatus.ReaderNames = readerNames
		}

		if atrBytesLen > 0 && atrBytes != nil {
			atrBytes = atrBytes[:atrBytesLen]
			cardStatus.Atr = byteArrayToHexString(atrBytes)
		}

		cardStatus.ActiveProtocol = scardProtocol
		cardStatus.State = readerState
	}

	return
}

// Transmit is a wrapper around SCardTransmit.
//
// This function sends a service request to
// the smart card and expects to receive data back
// from the card.
//
// N.B: This function implements handling of the case
// of SCARD_E_INSUFFICIENT_BUFFER (0x80100008) internally.
func (c *Card) Transmit(
	ioSendPci *SCardIORequest,
	sendBuffer []byte,
	ioRecvPci *SCardIORequest,
) (recvBuffer []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var sendBufferPtr *byte
	var recvBufferPtr *byte

	logger.Infof("Transmit, IN : (handle=0x%X, sendBuffer=%v)", c.handle, sendBuffer)
	defer func() { logger.Infof("Transmit, OUT: (handle=0x%X, recvBuffer=%v)", c.handle, recvBuffer) }()

	if scardTransmitProc == nil {
		err = fmt.Errorf("scardTransmit() not found in winscard.dll")
		return
	}

	if len(sendBuffer) > 0 {
		sendBufferPtr = &sendBuffer[0]
	}

	// We use the short APDU buffer size.
	// If this is not sufficient, the card will let us know
	// and we'll use the returned size.
	recvLength := dword(maxBufferSize)
	recvBuffer = make([]byte, recvLength)
	recvBufferPtr = &recvBuffer[0]
	r, _, msg := scardTransmitProc.Call(
		uintptr(c.handle),                      /* SCARDHANDLE */
		uintptr(unsafe.Pointer(ioSendPci)),     /* LPCSCARD_IO_REQUEST */
		uintptr(unsafe.Pointer(sendBufferPtr)), /* LPCBYTE */
		uintptr(len(sendBuffer)),               /* DWORD */
		uintptr(unsafe.Pointer(ioRecvPci)),     /* LPCSCARD_IO_REQUEST */
		uintptr(unsafe.Pointer(recvBufferPtr)), /* LPBYTE */
		uintptr(unsafe.Pointer(&recvLength)),   /* LPDWORD */
	)
	if r == 0x80100008 && recvLength > 0 { // SCARD_E_INSUFFICIENT_BUFFER
		recvBuffer = make([]byte, recvLength)
		recvBufferPtr = &recvBuffer[0]
		r, _, msg = scardTransmitProc.Call(
			uintptr(c.handle),                      /* SCARDHANDLE */
			uintptr(unsafe.Pointer(ioSendPci)),     /* LPCSCARD_IO_REQUEST */
			uintptr(unsafe.Pointer(sendBufferPtr)), /* LPCBYTE */
			uintptr(len(sendBuffer)),               /* DWORD */
			uintptr(unsafe.Pointer(ioRecvPci)),     /* LPCSCARD_IO_REQUEST */
			uintptr(unsafe.Pointer(recvBufferPtr)), /* LPBYTE */
			uintptr(unsafe.Pointer(&recvLength)),   /* LPDWORD */
		)
	}
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		recvBuffer = nil
		ret = uint64(r)
		err = fmt.Errorf("scardTransmit() returned 0x%X [%v]", r, msg)
		return
	}

	if recvLength > 0 && recvBuffer != nil {
		recvBuffer = recvBuffer[:recvLength]
	}

	return
}

// Control is a wrapper around SCardControl.
//
// This function gives you direct control of
// the reader. You can call it any time after a successful
// call to SCardConnect and before a successful call to
// SCardDisconnect. The effect on the state of the reader
// depends on the control code.
//
// N.B: This function implements handling of the case
// of SCARD_E_INSUFFICIENT_BUFFER (0x80100008) internally.
func (c *Card) Control(
	scardControlCode SCardCtlCode,
	inBuffer []byte,
) (outBuffer []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var inBufferPtr *byte
	var outBufferPtr *byte
	var bytesReturned dword

	logger.Infof("Control, IN : (handle=0x%X, inBuffer=%v)", c.handle, inBuffer)
	defer func() { logger.Infof("Control, OUT: (handle=0x%X, outBuffer=%v)", c.handle, outBuffer) }()

	if scardControlProc == nil {
		err = fmt.Errorf("scardControl() not found in winscard.dll")
		return
	}

	if len(inBuffer) > 0 {
		inBufferPtr = &inBuffer[0]
	}

	// We use the short APDU buffer size.
	// If this is not sufficient, the card will let us know
	// and we'll use the returned size.
	outBufferSize := dword(maxBufferSize)
	outBuffer = make([]byte, outBufferSize)
	outBufferPtr = &outBuffer[0]
	r, _, msg := scardControlProc.Call(
		uintptr(c.handle),         /* SCARDHANDLE */
		uintptr(scardControlCode), /* DWORD */
		uintptr(unsafe.Pointer(inBufferPtr)),
		uintptr(len(inBuffer)),
		uintptr(unsafe.Pointer(outBufferPtr)),
		uintptr(outBufferSize),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if r == 0x80100008 && bytesReturned > 0 { // SCARD_E_INSUFFICIENT_BUFFER
		outBuffer = make([]byte, bytesReturned)
		outBufferPtr = &outBuffer[0]
		r, _, msg = scardControlProc.Call(
			uintptr(c.handle),         /* SCARDHANDLE */
			uintptr(scardControlCode), /* DWORD */
			uintptr(unsafe.Pointer(inBufferPtr)),
			uintptr(len(inBuffer)),
			uintptr(unsafe.Pointer(outBufferPtr)),
			uintptr(outBufferSize),
			uintptr(unsafe.Pointer(&bytesReturned)),
		)
	}
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		outBuffer = nil
		ret = uint64(r)
		err = fmt.Errorf("scardControl() returned 0x%X [%v]", r, msg)
		return
	}

	if bytesReturned > 0 && outBuffer != nil {
		outBuffer = outBuffer[:bytesReturned]
	}

	return
}

// GetAttrib is a wrapper around SCardGetAttrib.
//
// This function retrieves the current
// reader attributes for the given handle. It does
// not affect the state of the reader, driver, or card.
func (c *Card) GetAttrib(
	attrId SCardAttr,
) (attrBytes []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var attrBytesLen dword

	logger.Infof("GetAttrib, IN : (handle=0x%X, attrId=%v)", c.handle, attrId)
	defer func() { logger.Infof("GetAttrib, OUT: (handle=0x%X, attrBytes=%v)", c.handle, attrBytes) }()

	if scardGetAttribProc == nil {
		err = fmt.Errorf("scardGetAttrib() not found in winscard.dll")
		return
	}

	r, _, msg := scardGetAttribProc.Call(
		uintptr(c.handle),                      /* SCARDHANDLE */
		uintptr(attrId),                        /* DWORD */
		uintptr(0),                             /* LPBYTE */
		uintptr(unsafe.Pointer(&attrBytesLen)), /* LPDWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardGetAttrib() 1st call returned 0x%X [%v]", r, msg)
		return
	}

	if attrBytesLen > 0 {
		attrBytes = make([]byte, attrBytesLen)
		r, _, msg = scardGetAttribProc.Call(
			uintptr(c.handle),                      /* SCARDHANDLE */
			uintptr(attrId),                        /* DWORD */
			uintptr(unsafe.Pointer(&attrBytes[0])), /* LPBYTE */
			uintptr(unsafe.Pointer(&attrBytesLen)), /* LPDWORD */
		)
		if r != 0 {
			if winErr := maybePcscErr(r); winErr != nil {
				msg = winErr
			}
			ret = uint64(r)
			err = fmt.Errorf("scardGetAttrib() 2nd call returned 0x%X [%v]", r, msg)
			return
		}

		if attrBytesLen > 0 && attrBytes != nil {
			attrBytes = attrBytes[:attrBytesLen]
		}
	}

	return
}

// SetAttrib is a wrapper around SCardSetAttrib.
//
// This function sets the given reader
// attribute for the given handle. It does not affect
// the state of the reader, reader driver, or smart card.
// Not all attributes are supported by all readers
// (nor can they be set at all times) as many of the
// attributes are under direct control of the transport
// protocol.
func (c *Card) SetAttrib(
	attrId SCardAttr,
	attr []byte,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var attrPtr *byte

	logger.Infof("SetAttrib, IN : (handle=0x%X, attrId=%v, attr=%v)", c.handle, attrId, attr)
	defer func() { logger.Infof("SetAttrib, OUT: (handle=0x%X, attrId=%v, attr=%v)", c.handle, attrId, attr) }()

	if scardSetAttribProc == nil {
		err = fmt.Errorf("scardSetAttrib() not found in winscard.dll")
		return
	}

	if len(attr) > 0 {
		attrPtr = &attr[0]
	}

	r, _, msg := scardSetAttribProc.Call(
		uintptr(c.handle), /* SCARDHANDLE */
		uintptr(attrId),   /* DWORD */
		uintptr(unsafe.Pointer(attrPtr)),
		uintptr(len(attr)),
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardSetAttrib() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// ListReaderGroups is a wrapper around SCardListReaderGroups.
//
// This function provides the list of reader groups
// that have previously been introduced to the system.
func (c *Context) ListReaderGroups() (groups []string, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var groupsUtf16 []uint16
	var groupsUtf16Len dword

	logger.Infof("ListReaderGroups, IN : (context=0x%X)", c.ctx)
	defer func() { logger.Infof("ListReaderGroups, OUT: (context=0x%X, groups=%v)", c.ctx, groups) }()

	if scardListReaderGroupsProc == nil {
		err = fmt.Errorf("scardListReaderGroups() not found in winscard.dll")
		return
	}

	r, _, msg := scardListReaderGroupsProc.Call(
		uintptr(c.ctx),                           /* SCARDCONTEXT */
		uintptr(0),                               /* LPWSTR */
		uintptr(unsafe.Pointer(&groupsUtf16Len)), /* LPDWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardListReaderGroups() 1st call returned 0x%X [%v]", r, msg)
		return
	}

	if groupsUtf16Len > 0 {
		groupsUtf16 = make([]uint16, groupsUtf16Len)
		r, _, msg = scardListReaderGroupsProc.Call(
			uintptr(c.ctx),                           /* SCARDCONTEXT */
			uintptr(unsafe.Pointer(&groupsUtf16[0])), /* LPWSTR */
			uintptr(unsafe.Pointer(&groupsUtf16Len)), /* LPDWORD */
		)
		if r != 0 {
			if winErr := maybePcscErr(r); winErr != nil {
				msg = winErr
			}
			ret = uint64(r)
			err = fmt.Errorf("scardListReaderGroups() 2nd call returned 0x%X [%v]", r, msg)
			return
		}

		if groupsUtf16Len > 0 && groupsUtf16 != nil {
			groupsUtf16 = groupsUtf16[:groupsUtf16Len]
			groups, err = multiUtf16StringToStrings(groupsUtf16)
			if err != nil {
				groups = nil
				err = fmt.Errorf("failed to parse groups names %v (%v))", groupsUtf16, err)
				return
			}

		}
	}

	return
}

// The following functions are not defined by PCSCLite,
// and therefore, are proper to the Windows implementation
// of PC/SC.

func (c *Card) CancelTransaction() (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("CancelTransaction, IN : (handle=0x%X)", c.handle)
	defer func() { logger.Infof("CancelTransaction, OUT: (handle=0x%X)", c.handle) }()

	if scardCancelTransactionProc == nil {
		err = fmt.Errorf("scardCancelTransaction() not found in winscard.dll")
		return
	}

	r, _, msg := scardCancelTransactionProc.Call(
		uintptr(c.handle), /* SCARDHANDLE */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardCancelTransaction() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// GetTransmitCount is a wrapper around SCardGetTransmitCount.
//
// This function retrieves the
// number of transmit operations that have completed
// since the specified card reader was inserted.
func (c *Card) GetTransmitCount() (transmitCount dword, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("GetTransmitCount, IN : (handle=0x%X)", c.handle)
	defer func() { logger.Infof("GetTransmitCount, OUT: (handle=0x%X, count=%v)", transmitCount) }()

	if scardGetTransmitCountProc == nil {
		err = fmt.Errorf("scardGetTransmitCount() not found in winscard.dll")
		return
	}

	r, _, msg := scardGetTransmitCountProc.Call(
		uintptr(c.handle),                       /* SCARDHANDLE */
		uintptr(unsafe.Pointer(&transmitCount)), /* LPDWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		transmitCount = 0
		ret = uint64(r)
		err = fmt.Errorf("scardGetTransmitCount() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// AccessStartedEvent is a wrapper around SCardAccessStartedEvent.
//
// This function returns an event handle
// when an event signals that the smart card resource manager
// is started. The event-object handle can be specified in
// a call to one of the wait functions.
func AccessStartedEvent() (eventHandle windows.Handle, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("AccessStartedEvent, IN : ")
	defer func() { logger.Infof("AccessStartedEvent, OUT: (handle=x%X)", eventHandle) }()

	if scardAccessStartedEventProc == nil {
		err = fmt.Errorf("scardAccessStartedEvent() not found in winscard.dll")
		return
	}

	r, _, msg := scardAccessStartedEventProc.Call()
	if r == 0 {
		ret = uint64(r)
		err = fmt.Errorf("scardAccessStartedEvent() returned 0x%X [%v]", r, msg)
		return
	}

	eventHandle = windows.Handle(r)
	return
}

// ReleaseStartedEvent is a wrapper around SCardReleaseStartedEvent.
//
// This function decrements the reference
// count for a handle acquired by a previous call to the
// AccessStartedEvent function.
func ReleaseStartedEvent() (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("ReleaseStartedEvent, IN : ")
	defer func() { logger.Infof("ReleaseStartedEvent, OUT: ") }()

	if scardReleaseStartedEventProc == nil {
		err = fmt.Errorf("scardReleaseStartedEvent() not found in winscard.dll")
		return
	}

	r, _, msg := scardAccessStartedEventProc.Call()
	if msg != windows.Errno(0) {
		err = fmt.Errorf("scardAccessStartedEvent() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// LocateCards is a wrapper around SCardLocateCards.
//
// This function searches the readers listed
// in the readerStates parameter for a card with a
// name that matches one of the card names specified
// in cardsNames, returning immediately with the result.
//
// N.B: This function will update the SCardStates directly
// in the passed SCardReaderState array.
func (c *Context) LocateCards(
	cardsNames []string,
	readerStates []SCardReaderState,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var cardsNamesUtf16 []uint16
	var cardsNamesUtf16Ptr *uint16
	var internalReaderStates []scardReaderState
	var internalReaderStatesPtr *scardReaderState

	logger.Infof("LocateCards, IN : (context=0x%X, cardsNames=%v, readerStates=%v)",
		c.ctx, cardsNames, readerStates)
	defer func() {
		logger.Infof("LocateCards, OUT: (context=0x%X, cardsNames=%v, readerStates=%v)",
			c.ctx, cardsNames, readerStates)
	}()

	if scardLocateCardsProc == nil {
		err = fmt.Errorf("scardLocateCards() not found in winscard.dll")
		return
	}

	if len(cardsNames) > 0 {
		cardsNamesUtf16, err = stringsToMultiUtf16String(cardsNames)
		if err != nil {
			err = fmt.Errorf("failed to parse cards names %v (%v)", cardsNames, err)
			return
		}

		cardsNamesUtf16Ptr = (*uint16)(unsafe.Pointer(&cardsNamesUtf16[0]))
	}

	if len(readerStates) > 0 {
		internalReaderStates = make([]scardReaderState, len(readerStates))
		for i, readerState := range readerStates {
			internalReaderStates[i], err = readerState.toInternal()
			if err != nil {
				return
			}
		}
		internalReaderStatesPtr = (*scardReaderState)(unsafe.Pointer(&internalReaderStates[0]))
	}

	r, _, msg := scardLocateCardsProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(cardsNamesUtf16Ptr)),      /* LPCWSTR */
		uintptr(unsafe.Pointer(internalReaderStatesPtr)), /* LPSCARD_READERSTATEW */
		uintptr(len(readerStates)),                       /* DWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardLocateCards() returned 0x%X [%v]", r, msg)
		return
	}

	for i, internalReaderState := range internalReaderStates {
		readerStates[i].fromInternal(internalReaderState)
	}

	return
}

// LocateCardsByATR is a wrapper around SCardLocateCardsByATR.
//
// This function searches the readers
// listed in the readerStates parameter for a card
// with a name that matches one of the card names contained
// in one of the SCardAtrMask structures specified by the
// atrMasks parameter.
//
// N.B: This function will update the SCardStates directly
// in the passed SCardReaderState array.
func (c *Context) LocateCardsByATR(
	atrMasks []SCardAtrMask,
	readerStates []SCardReaderState,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var internalAtrMasks []scardAtrMask
	var internalAtrMasksPtr *scardAtrMask
	var internalReaderStates []scardReaderState
	var internalReaderStatesPtr *scardReaderState

	logger.Infof("LocateCardsByATR, IN : (context=0x%X, atrMasks=%v, readerStates=%v)",
		c.ctx, atrMasks, readerStates)
	defer func() {
		logger.Infof("LocateCardsByATR, OUT: (context=0x%X, atrMasks=%v, readerStates=%v)",
			c.ctx, atrMasks, readerStates)
	}()

	if scardLocateCardsByATRProc == nil {
		err = fmt.Errorf("scardLocateCardsByATR() not found in winscard.dll")
		return
	}

	if len(atrMasks) > 0 {
		internalAtrMasks = make([]scardAtrMask, len(atrMasks))
		for i, atrMask := range atrMasks {
			internalAtrMasks[i], err = atrMask.toInternal()
			if err != nil {
				return
			}
		}
		internalAtrMasksPtr = (*scardAtrMask)(unsafe.Pointer(&internalAtrMasks[0]))
	}

	if len(readerStates) > 0 {
		internalReaderStates = make([]scardReaderState, len(readerStates))
		for i, readerState := range readerStates {
			internalReaderStates[i], err = readerState.toInternal()
			if err != nil {
				return
			}
		}
		internalReaderStatesPtr = (*scardReaderState)(unsafe.Pointer(&internalReaderStates[0]))
	}

	r, _, msg := scardLocateCardsByATRProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(internalAtrMasksPtr)),     /* LPSCARD_ATRMASK */
		uintptr(len(atrMasks)),                           /* DWORD */
		uintptr(unsafe.Pointer(internalReaderStatesPtr)), /* LPSCARD_READERSTATEW */
		uintptr(len(readerStates)),                       /* DWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardLocateCardsByATR() returned 0x%X [%v]", r, msg)
		return
	}

	for i, internalReaderState := range internalReaderStates {
		readerStates[i].fromInternal(internalReaderState)
	}

	return
}

// ListCards is a wrapper around SCardListCards.
//
// This function searches the smart card database
// and provides a list of named cards previously introduced
// to the system by the user.
// The caller specifies an ATR string, a set of interface
// identifiers (GUIDs), or both. If both an ATR string and
// an identifier array are supplied, the cards returned will
// match the ATR string supplied and support the interfaces
// specified.
func (c *Context) ListCards(
	atr string,
	guidInterfaces []windows.GUID,
) (cards []string, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var atrBytes []byte
	var atrBytesPtr *byte
	var guidInterfacesPtr *windows.GUID
	var cardsUtf16Len dword
	var cardsUtf16 []uint16

	logger.Infof("ListCards, IN : (context=0x%X, atr=%v, guidInterfaces=%v)",
		c.ctx, atr, guidInterfaces)
	defer func() {
		logger.Infof("ListCards, OUT: (context=0x%X, cards=%v)",
			c.ctx, cards)
	}()

	if scardListCardsProc == nil {
		err = fmt.Errorf("scardListCards() not found in winscard.dll")
		return
	}

	if atr != "" {
		atrBytes, err = hexStringToByteArray(atr)
		if err != nil {
			err = fmt.Errorf("failed to parse atr \"%s\" (%v)", atr, err)
			return
		}
		atrBytesPtr = (*byte)(unsafe.Pointer(&atrBytes[0]))
	}

	if len(guidInterfaces) != 0 {
		guidInterfacesPtr = (*windows.GUID)(unsafe.Pointer(&guidInterfaces[0]))
	}

	r, _, msg := scardListCardsProc.Call(
		uintptr(c.ctx),                             /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(atrBytesPtr)),       /* LPCBYTE */
		uintptr(unsafe.Pointer(guidInterfacesPtr)), /* LPCGUID */
		uintptr(len(guidInterfaces)),               /* DWORD */
		uintptr(0),                                 /* WCHAR* */
		uintptr(unsafe.Pointer(&cardsUtf16Len)),    /* LPDWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardListCards() 1st call returned 0x%X [%v]", r, msg)
		return
	}

	if cardsUtf16Len > 0 {
		cardsUtf16 = make([]uint16, cardsUtf16Len)
		r, _, msg = scardListCardsProc.Call(
			uintptr(c.ctx),                             /* SCARDCONTEXT */
			uintptr(unsafe.Pointer(atrBytesPtr)),       /* LPCBYTE */
			uintptr(unsafe.Pointer(guidInterfacesPtr)), /* LPCGUID */
			uintptr(len(guidInterfaces)),               /* DWORD */
			uintptr(unsafe.Pointer(&cardsUtf16[0])),    /* WCHAR* */
			uintptr(unsafe.Pointer(&cardsUtf16Len)),    /* LPDWORD */
		)
		if r != 0 {
			if winErr := maybePcscErr(r); winErr != nil {
				msg = winErr
			}
			ret = uint64(r)
			err = fmt.Errorf("scardListCards() 2nd call returned 0x%X [%v]", r, msg)
			return
		}

		if cardsUtf16Len > 0 && cardsUtf16 != nil {
			cardsUtf16 = cardsUtf16[:cardsUtf16Len]
			cards, err = multiUtf16StringToStrings(cardsUtf16)
			if err != nil {
				cards = nil
				err = fmt.Errorf("failed to parse cards names %v (%v))", cardsUtf16, err)
				return
			}
		}
	}

	return
}

// ListInterfaces is a wrapper around SCardListInterfaces.
//
// This function provides a list of interfaces
// supplied by a given card.
// The caller supplies the name of a smart card previously
// introduced to the subsystem, and receives the list of
// interfaces supported by the card.
func (c *Context) ListInterfaces(
	cardName string,
) (guidInterfaces []windows.GUID, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var guidInterfacesLen dword
	var cardNameUtf16Ptr *uint16

	logger.Infof("ListInterfaces, IN : (context=0x%X, cardName=%v)",
		c.ctx, cardName)
	defer func() {
		logger.Infof("ListInterfaces, OUT: (context=0x%X, cardName=%v, guidInterfaces=%v)",
			c.ctx, cardName, guidInterfaces)
	}()

	if scardListInterfacesProc == nil {
		err = fmt.Errorf("scardListInterfaces() not found in winscard.dll")
		return
	}

	if cardName != "" {
		cardNameUtf16Ptr, err = stringToUtf16Ptr(cardName)
		if err != nil {
			err = fmt.Errorf("failed to parse card name \"%s\" (%v)", cardName, err)
			return
		}
	}

	r, _, msg := scardListInterfacesProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(cardNameUtf16Ptr)), /* LPCWSTR */
		uintptr(0), /* LPGUID */
		uintptr(unsafe.Pointer(&guidInterfacesLen)), /* LPDWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardListInterfaces() 1st call returned 0x%X [%v]", r, msg)
		return
	}

	if guidInterfacesLen > 0 {
		guidInterfaces = make([]windows.GUID, guidInterfacesLen)
		r, _, msg = scardListInterfacesProc.Call(
			uintptr(c.ctx), /* SCARDCONTEXT */
			uintptr(unsafe.Pointer(cardNameUtf16Ptr)),   /* LPCWSTR */
			uintptr(unsafe.Pointer(&guidInterfaces[0])), /* LPGUID */
			uintptr(unsafe.Pointer(&guidInterfacesLen)), /* LPDWORD */
		)
		if r != 0 {
			if winErr := maybePcscErr(r); winErr != nil {
				msg = winErr
			}
			guidInterfaces = nil
			ret = uint64(r)
			err = fmt.Errorf("scardListInterfaces() 2nd call returned 0x%X [%v]", r, msg)
			return
		}

		if guidInterfacesLen > 0 && guidInterfaces != nil {
			guidInterfaces = guidInterfaces[:guidInterfacesLen]
		}
	}

	return
}

// GetProviderId is a wrapper around SCardGetProviderId.
//
// This function returns the identifier (GUID)
// of the primary service provider for a given card.
// The caller supplies the name of a smart card (previously
// introduced to the system) and receives the registered
// identifier of the primary service provider GUID, if one exists.
func (c *Context) GetProviderId(
	cardName string,
) (guidProviderId windows.GUID, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var cardNameUtf16Ptr *uint16

	logger.Infof("GetProviderId, IN : (context=0x%X, cardName=%v)",
		c.ctx, cardName)
	defer func() {
		logger.Infof("GetProviderId, OUT: (context=0x%X, cardName=%v, guidProviderId=%v)",
			c.ctx, cardName, guidProviderId)
	}()

	if scardGetProviderIdProc == nil {
		err = fmt.Errorf("scardGetProviderId() not found in winscard.dll")
		return
	}

	if cardName != "" {
		cardNameUtf16Ptr, err = stringToUtf16Ptr(cardName)
		if err != nil {
			err = fmt.Errorf("failed to parse card name \"%s\" (%v)", cardName, err)
			return
		}
	}

	r, _, msg := scardGetProviderIdProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(cardNameUtf16Ptr)), /* LPCWSTR */
		uintptr(unsafe.Pointer(&guidProviderId)),  /* LPGUID */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		guidProviderId = windows.GUID{}
		ret = uint64(r)
		err = fmt.Errorf("scardGetProviderId() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// GetCardTypeProviderName is a wrapper around
// SCardGetCardTypeProviderName.
//
// This function returns the name of the module
// (dynamic link library) that contains the provider
// for a given card name and provider type.
func (c *Context) GetCardTypeProviderName(
	cardName string,
	providerId SCardProviderType,
) (providerName string, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var cardNameUtf16Ptr *uint16
	var providerNameUtf16 []uint16
	var providerNameUtf16Len dword

	logger.Infof("GetCardTypeProviderName, IN : (context=0x%X, cardName=%v, providerId=%v)",
		c.ctx, cardName, providerId)
	defer func() {
		logger.Infof("GetCardTypeProviderName, OUT: (context=0x%X, cardName=%v, providerId=%v, providerName=%v)",
			c.ctx, cardName, providerId, providerName)
	}()

	if scardGetCardTypeProviderNameProc == nil {
		err = fmt.Errorf("scardGetCardTypeProviderName() not found in winscard.dll")
		return
	}

	if cardName != "" {
		cardNameUtf16Ptr, err = stringToUtf16Ptr(cardName)
		if err != nil {
			err = fmt.Errorf("failed to parse card name \"%s\" (%v)", cardName, err)
			return
		}
	}

	r, _, msg := scardGetCardTypeProviderNameProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(cardNameUtf16Ptr)),      /* LPCWSTR */
		uintptr(providerId),                            /* DWORD */
		uintptr(0),                                     /* WCHAR* */
		uintptr(unsafe.Pointer(&providerNameUtf16Len)), /* LPDWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardGetCardTypeProviderName() 1st call returned 0x%X [%v]", r, msg)
		return
	}

	if providerNameUtf16Len > 0 {
		providerNameUtf16 = make([]uint16, providerNameUtf16Len)
		r, _, msg = scardGetCardTypeProviderNameProc.Call(
			uintptr(c.ctx), /* SCARDCONTEXT */
			uintptr(unsafe.Pointer(cardNameUtf16Ptr)),      /* LPCWSTR */
			uintptr(providerId),                            /* DWORD */
			uintptr(unsafe.Pointer(&providerNameUtf16[0])), /* WCHAR* */
			uintptr(unsafe.Pointer(&providerNameUtf16Len)), /* LPDWORD */
		)
		if r != 0 {
			if winErr := maybePcscErr(r); winErr != nil {
				msg = winErr
			}
			ret = uint64(r)
			err = fmt.Errorf("scardGetCardTypeProviderName() 2nd call returned 0x%X [%v]", r, msg)
			return
		}

		if providerNameUtf16Len > 0 && providerNameUtf16 != nil {
			providerNameUtf16 = providerNameUtf16[:providerNameUtf16Len]
			providerName, err = utf16ToString(providerNameUtf16)
			if err != nil {
				providerName = ""
				err = fmt.Errorf("failed to parse provider name %v (%v))", providerNameUtf16, err)
				return
			}
		}

	}

	return
}

// IntroduceReaderGroup is a wrapper around SCardIntroduceReaderGroup.
//
// This function introduces a reader group
// to the smart card subsystem. However, the reader group is not
// created until the group is specified when adding a reader to
// the smart card database.
func (c *Context) IntroduceReaderGroup(
	groupName string,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var groupNameUtf16Ptr *uint16

	logger.Infof("IntroduceReaderGroup, IN : (context=0x%X, groupName=%v)", c.ctx, groupName)
	defer func() { logger.Infof("IntroduceReaderGroup, OUT: (context=0x%X, groupName=%v)", c.ctx, groupName) }()

	if scardIntroduceReaderGroupProc == nil {
		err = fmt.Errorf("scardIntroduceReaderGroup() not found in winscard.dll")
		return
	}

	if groupName != "" {
		groupNameUtf16Ptr, err = stringToUtf16Ptr(groupName)
		if err != nil {
			err = fmt.Errorf("failed to parse group name \"%s\" (%v)", groupName, err)
			return
		}
	}

	r, _, msg := scardIntroduceReaderGroupProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(groupNameUtf16Ptr)), /* LPCWSTR */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardIntroduceReaderGroup() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// ForgetReaderGroup is a wrapper around SCardForgetReaderGroup.
//
// This function removes a previously introduced
// smart card reader group from the smart card subsystem. Although
// this function automatically clears all readers from the group,
// it does not affect the existence of the individual readers in
// the database.
func (c *Context) ForgetReaderGroup(
	groupName string,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var groupNameUtf16Ptr *uint16

	logger.Infof("ForgetReaderGroup, IN : (context=0x%X, groupName=%v)", c.ctx, groupName)
	defer func() { logger.Infof("ForgetReaderGroup, OUT: (context=0x%X, groupName=%v)", c.ctx, groupName) }()

	if scardForgetReaderGroupProc == nil {
		err = fmt.Errorf("scardForgetReaderGroup() not found in winscard.dll")
		return
	}

	if groupName != "" {
		groupNameUtf16Ptr, err = stringToUtf16Ptr(groupName)
		if err != nil {
			err = fmt.Errorf("failed to parse group name \"%s\" (%v)", groupName, err)
			return
		}
	}

	r, _, msg := scardForgetReaderGroupProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(groupNameUtf16Ptr)), /* LPCWSTR */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardForgetReaderGroup() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// IntroduceReader is a wrapper around SCardIntroduceReader.
//
// This function introduces a new name for an existing smart
// card reader.
func (c *Context) IntroduceReader(
	readerName string,
	deviceName string,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var readerNamesUtf16Ptr *uint16
	var deviceNameUtf16Ptr *uint16

	logger.Infof("IntroduceReader, IN : (context=0x%X, readerName=%v, deviceName=%s)",
		c.ctx, readerName, deviceName)
	defer func() {
		logger.Infof("IntroduceReader, OUT: (context=0x%X, readerName=%v, deviceName=%s)",
			c.ctx, readerName, deviceName)
	}()

	if scardIntroduceReaderProc == nil {
		err = fmt.Errorf("scardIntroduceReader() not found in winscard.dll")
		return
	}

	if readerName != "" {
		readerNamesUtf16Ptr, err = stringToUtf16Ptr(readerName)
		if err != nil {
			err = fmt.Errorf("failed to parse reader name \"%s\" (%v)", readerName, err)
			return
		}
	}

	if deviceName != "" {
		deviceNameUtf16Ptr, err = stringToUtf16Ptr(deviceName)
		if err != nil {
			err = fmt.Errorf("failed to parse device name \"%s\" (%v)", deviceName, err)
			return
		}
	}

	r, _, msg := scardIntroduceReaderProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(readerNamesUtf16Ptr)), /* LPCWSTR */
		uintptr(unsafe.Pointer(deviceNameUtf16Ptr)),  /* LPCWSTR */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardIntroduceReader() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// ForgetReader is a wrapper around SCardForgetReader.
//
// This function removes a previously introduced
// reader from control by the smart card subsystem. It is
// removed from the smart card database, including from any
// reader group that it may have been added to.
func (c *Context) ForgetReader(
	readerName string,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var readerNamesUtf16Ptr *uint16

	logger.Infof("ForgetReader, IN : (context=0x%X, readerName=%v)",
		c.ctx, readerName)
	defer func() {
		logger.Infof("ForgetReader, OUT: (context=0x%X, readerName=%v)",
			c.ctx, readerName)
	}()

	if scardForgetReaderProc == nil {
		err = fmt.Errorf("scardForgetReader() not found in winscard.dll")
		return
	}

	if readerName != "" {
		readerNamesUtf16Ptr, err = stringToUtf16Ptr(readerName)
		if err != nil {
			err = fmt.Errorf("failed to parse reader name \"%s\" (%v)", readerName, err)
			return
		}
	}

	r, _, msg := scardForgetReaderProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(readerNamesUtf16Ptr)), /* LPCWSTR */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardForgetReader() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// AddReaderToGroup is a wrapper around SCardAddReaderToGroup.
//
// This function adds a reader to a reader group.
func (c *Context) AddReaderToGroup(
	readerName string,
	groupName string,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var readerNamesUtf16Ptr *uint16
	var groupNameUtf16Ptr *uint16

	logger.Infof("ForgetReader, IN : (context=0x%X, readerName=%v, groupName=%v)",
		c.ctx, readerName, groupName)
	defer func() {
		logger.Infof("ForgetReader, OUT: (context=0x%X, readerName=%v, groupName=%v)",
			c.ctx, readerName, groupName)
	}()

	if scardAddReaderToGroupProc == nil {
		err = fmt.Errorf("scardAddReaderToGroup() not found in winscard.dll")
		return
	}

	if readerName != "" {
		readerNamesUtf16Ptr, err = stringToUtf16Ptr(readerName)
		if err != nil {
			err = fmt.Errorf("failed to parse reader name \"%s\" (%v)", readerName, err)
			return
		}
	}

	if groupName != "" {
		groupNameUtf16Ptr, err = stringToUtf16Ptr(groupName)
		if err != nil {
			err = fmt.Errorf("failed to parse group name \"%s\" (%v)", groupName, err)
			return
		}
	}

	r, _, msg := scardAddReaderToGroupProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(readerNamesUtf16Ptr)), /* LPCWSTR */
		uintptr(unsafe.Pointer(groupNameUtf16Ptr)),   /* LPCWSTR */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardAddReaderToGroup() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// RemoveReaderFromGroup is a wrapper around SCardRemoveReaderFromGroup.
//
// This function removes a reader from an existing reader group.
// This function has no effect on the reader.
func (c *Context) RemoveReaderFromGroup(
	readerName string,
	groupName string,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var readerNamesUtf16Ptr *uint16
	var groupNameUtf16Ptr *uint16

	logger.Infof("RemoveReaderFromGroup, IN : (context=0x%X, readerName=%v, groupName=%v)",
		c.ctx, readerName, groupName)
	defer func() {
		logger.Infof("RemoveReaderFromGroup, OUT: (context=0x%X, readerName=%v, groupName=%v)",
			c.ctx, readerName, groupName)
	}()

	if scardRemoveReaderFromGroupProc == nil {
		err = fmt.Errorf("scardRemoveReaderFromGroup() not found in winscard.dll")
		return
	}

	if readerName != "" {
		readerNamesUtf16Ptr, err = stringToUtf16Ptr(readerName)
		if err != nil {
			err = fmt.Errorf("failed to parse reader name \"%s\" (%v)", readerName, err)
			return
		}
	}

	if groupName != "" {
		groupNameUtf16Ptr, err = stringToUtf16Ptr(groupName)
		if err != nil {
			err = fmt.Errorf("failed to parse group name \"%s\" (%v)", groupName, err)
			return
		}
	}

	r, _, msg := scardRemoveReaderFromGroupProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(readerNamesUtf16Ptr)), /* LPCWSTR */
		uintptr(unsafe.Pointer(groupNameUtf16Ptr)),   /* LPCWSTR */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardRemoveReaderFromGroup() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// IntroduceCardType is a wrapper around SCardIntroduceCardType.
//
// This function introduces a smart card to the smart card
// subsystem (for the active user) by adding it to the smart
// card database.
func (c *Context) IntroduceCardType(
	cardName string,
	guidPrimaryProvider *windows.GUID,
	guidInterfaces []windows.GUID,
	atr string,
	atrMask string,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var cardNameUtf16Ptr *uint16
	var guidInterfacesPtr *windows.GUID
	var atrBytes []byte
	var atrMaskBytes []byte
	var atrBytesPtr *byte
	var atrMaskBytesPtr *byte

	logger.Infof("IntroduceCardType, IN : (context=0x%X, cardName=%v, guidPrimaryProvider=%v, guidInterfaces=%v, atr=%v, atrMask=%v)",
		c.ctx, cardName, guidPrimaryProvider, guidInterfaces, atr, atrMask)
	defer func() {
		logger.Infof("IntroduceCardType, OUT: (context=0x%X, cardName=%v, guidPrimaryProvider=%v, guidInterfaces=%v, atr=%v, atrMask=%v)",
			c.ctx, cardName, guidPrimaryProvider, guidInterfaces, atr, atrMask)
	}()

	if scardIntroduceCardTypeProc == nil {
		err = fmt.Errorf("scardIntroduceCardType() not found in winscard.dll")
		return
	}
	if c.ctx == 0 {
		err = fmt.Errorf("c.ctx cannot be 0 (NULL)")
		return
	}
	if cardName == "" {
		err = fmt.Errorf("cardName cannot be empty")
		return
	}
	if len(atr) != len(atrMask) {
		err = fmt.Errorf("atr and atrMask are not of the same length")
		return
	}

	if len(cardName) > 0 {
		cardNameUtf16Ptr, err = stringToUtf16Ptr(cardName)
		if err != nil {
			err = fmt.Errorf("failed to parse card name \"%s\" (%v)", cardName, err)
			return
		}
	}
	if len(atr) != 0 {
		atrBytes, err = hexStringToByteArray(atr)
		if err != nil {
			err = fmt.Errorf("failed to parse atr \"%s\" (%v)", atr, err)
			return
		}
		atrBytesPtr = (*byte)(unsafe.Pointer(&atrBytes[0]))
	}
	if len(atrMask) != 0 {
		atrMaskBytes, err = hexStringToByteArray(atrMask)
		if err != nil {
			err = fmt.Errorf("failed to parse atr mask \"%s\" (%v)", atrMask, err)
			return
		}
		atrMaskBytesPtr = (*byte)(unsafe.Pointer(&atrMaskBytes[0]))
	}
	if len(guidInterfaces) != 0 {
		guidInterfacesPtr = (*windows.GUID)(unsafe.Pointer(&guidInterfaces[0]))
	}

	r, _, msg := scardIntroduceCardTypeProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(cardNameUtf16Ptr)),    /* LPCWSTR */
		uintptr(unsafe.Pointer(guidPrimaryProvider)), /* LPCGUID */
		uintptr(unsafe.Pointer(guidInterfacesPtr)),   /* LPCGUID */
		uintptr(len(guidInterfaces)),                 /* DWORD */
		uintptr(unsafe.Pointer(atrBytesPtr)),         /* LPCBYTE */
		uintptr(unsafe.Pointer(atrMaskBytesPtr)),     /* LPCBYTE */
		uintptr(len(atr)/2),                          /* DWORD */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardIntroduceCardType() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// SetCardTypeProviderName is a wrapper around
// SCardSetCardTypeProviderName.
//
// This function specifies the name of the module
// (dynamic link library) containing the provider
// for a given card name and provider type.
func (c *Context) SetCardTypeProviderName(
	cardName string,
	providerId SCardProviderType,
	providerName string,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var cardNameUtf16Ptr *uint16
	var providerNameUtf16Ptr *uint16

	logger.Infof("SetCardTypeProviderName, IN : (context=0x%X, cardName=%v, providerId=%v, providerName=%v)",
		c.ctx, cardName, providerId, providerName)
	defer func() {
		logger.Infof("SetCardTypeProviderName, OUT: (context=0x%X, cardName=%v, providerId=%v, providerName=%v)",
			c.ctx, cardName, providerId, providerName)
	}()

	if scardSetCardTypeProviderNameProc == nil {
		err = fmt.Errorf("scardSetCardTypeProviderName() not found in winscard.dll")
		return
	}

	if len(cardName) > 0 {
		cardNameUtf16Ptr, err = stringToUtf16Ptr(cardName)
		if err != nil {
			err = fmt.Errorf("failed to parse card name \"%s\" (%v)", cardName, err)
			return
		}
	}

	if len(providerName) > 0 {
		providerNameUtf16Ptr, err = stringToUtf16Ptr(providerName)
		if err != nil {
			err = fmt.Errorf("failed to parse provider name \"%s\" (%v)", providerName, err)
			return
		}
	}

	r, _, msg := scardSetCardTypeProviderNameProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(cardNameUtf16Ptr)),     /* LPCWSTR */
		uintptr(providerId),                           /* DWORD */
		uintptr(unsafe.Pointer(providerNameUtf16Ptr)), /* LPCWSTR */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardSetCardTypeProviderName() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// ForgetCardType is a wrapper around SCardForgetCardType.
//
// This function removes an introduced smart card from the
// smart card subsystem.
func (c *Context) ForgetCardType(
	cardName string,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var cardNameUtf16Ptr *uint16

	logger.Infof("ForgetCardType, IN : (context=0x%X, cardName=%v)",
		c.ctx, cardName)
	defer func() {
		logger.Infof("ForgetCardType, OUT: (context=0x%X, cardName=%v)",
			c.ctx, cardName)
	}()

	if scardForgetCardTypeProc == nil {
		err = fmt.Errorf("scardForgetCardType() not found in winscard.dll")
		return
	}

	if len(cardName) > 0 {
		cardNameUtf16Ptr, err = stringToUtf16Ptr(cardName)
		if err != nil {
			err = fmt.Errorf("failed to parse card name \"%s\" (%v)", cardName, err)
			return
		}
	}

	r, _, msg := scardForgetCardTypeProc.Call(
		uintptr(c.ctx), /* SCARDCONTEXT */
		uintptr(unsafe.Pointer(cardNameUtf16Ptr)), /* LPCWSTR */
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardForgetCardType() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// ReadCache is a wrapper around SCardReadCache.
//
// This function retrieves the value portion of a
// name-value pair from the global cache maintained
// by the Smart Card Resource Manager.
func (c *Context) ReadCache(
	cardIdentifier *windows.GUID,
	freshnessCounter dword,
	lookupName string,
) (data []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var dataLen dword
	var lookupNameUtf16Ptr *uint16

	logger.Infof("ReadCache, IN : (context=0x%X, cardIdentifier=%v, freshnessCounter=%v, lookupName=%v)",
		c.ctx, cardIdentifier, freshnessCounter, lookupName)
	defer func() {
		logger.Infof("ReadCache, OUT: (context=0x%X, cardIdentifier=%v, freshnessCounter=%v, lookupName=%v)",
			c.ctx, cardIdentifier, freshnessCounter, lookupName)
	}()

	if scardReadCacheProc == nil {
		err = fmt.Errorf("scardReadCache() not found in winscard.dll")
		return
	}

	if lookupName != "" {
		lookupNameUtf16Ptr, err = stringToUtf16Ptr(lookupName)
		if err != nil {
			err = fmt.Errorf("failed to parse lookup name \"%s\" (%v)", lookupName, err)
			return
		}
	}

	r, _, msg := scardReadCacheProc.Call(
		uintptr(c.ctx),
		uintptr(unsafe.Pointer(cardIdentifier)),
		uintptr(freshnessCounter),
		uintptr(unsafe.Pointer(lookupNameUtf16Ptr)),
		uintptr(0),
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardReadCache() 1st call returned 0x%X [%v]", r, msg)
		return
	}

	if dataLen > 0 {
		data = make([]byte, dataLen)
		r, _, msg = scardReadCacheProc.Call(
			uintptr(c.ctx),
			uintptr(unsafe.Pointer(cardIdentifier)),
			uintptr(freshnessCounter),
			uintptr(unsafe.Pointer(lookupNameUtf16Ptr)),
			uintptr(unsafe.Pointer(&data[0])),
			uintptr(unsafe.Pointer(&dataLen)),
		)
		if r != 0 {
			if winErr := maybePcscErr(r); winErr != nil {
				msg = winErr
			}
			data = nil
			ret = uint64(r)
			err = fmt.Errorf("scardReadCache() 2nd call returned 0x%X [%v]", r, msg)
			return
		}

		if dataLen > 0 && data != nil {
			data = data[:dataLen]
		}
	}

	return
}

// WriteCache is a wrapper around SCardWriteCache.
//
// This function writes a name-value pair from a
// smart card to the global cache maintained by
// the Smart Card Resource Manager.
func (c *Context) WriteCache(
	cardIdentifier *windows.GUID,
	freshnessCounter dword,
	lookupName string,
	data []byte,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var lookupNameUtf16Ptr *uint16
	var dataPtr *byte

	logger.Infof("WriteCache, IN : (context=0x%X, cardIdentifier=%v, freshnessCounter=%v, lookupName=%v, data=%v)",
		c.ctx, cardIdentifier, freshnessCounter, lookupName, data)
	defer func() {
		logger.Infof("WriteCache, OUT: (context=0x%X, cardIdentifier=%v, freshnessCounter=%v, lookupName=%v, data=%v)",
			c.ctx, cardIdentifier, freshnessCounter, lookupName, data)
	}()

	if scardWriteCacheProc == nil {
		err = fmt.Errorf("scardWriteCache() not found in winscard.dll")
		return
	}

	if lookupName != "" {
		lookupNameUtf16Ptr, err = stringToUtf16Ptr(lookupName)
		if err != nil {
			err = fmt.Errorf("failed to parse lookup name \"%s\" (%v)", lookupName, err)
			return
		}
	}
	if len(data) > 0 {
		dataPtr = (*byte)(unsafe.Pointer(&data[0]))
	}

	r, _, msg := scardWriteCacheProc.Call(
		uintptr(c.ctx),
		uintptr(unsafe.Pointer(cardIdentifier)),
		uintptr(freshnessCounter),
		uintptr(unsafe.Pointer(lookupNameUtf16Ptr)),
		uintptr(unsafe.Pointer(dataPtr)),
		uintptr(len(data)),
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardWriteCache() 1st call returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// GetReaderIcon is a wrapper around SCardGetReaderIcon.
//
// This function gets an icon of the smart card reader
// for a given reader's name.
// This function does not affect the state of the
// card reader.
func (c *Context) GetReaderIcon(
	readerName string,
) (icon []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var iconLen dword
	var readerNameUtf16Ptr *uint16

	logger.Infof("GetReaderIcon, IN : (context=0x%X, readerName=%v)",
		c.ctx, readerName)
	defer func() {
		logger.Infof("GetReaderIcon, OUT: (context=0x%X, readerName=%v, icon=%v)",
			c.ctx, readerName, icon)
	}()

	if scardGetReaderIconProc == nil {
		err = fmt.Errorf("scardGetReaderIcon() not found in winscard.dll")
		return
	}

	if readerName != "" {
		readerNameUtf16Ptr, err = stringToUtf16Ptr(readerName)
		if err != nil {
			err = fmt.Errorf("failed to parse reader name \"%s\" (%v)", readerName, err)
			return
		}
	}

	r, _, msg := scardGetReaderIconProc.Call(
		uintptr(c.ctx),
		uintptr(unsafe.Pointer(readerNameUtf16Ptr)),
		uintptr(0),
		uintptr(unsafe.Pointer(&iconLen)),
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardGetReaderIcon() 1st call returned 0x%X [%v]", r, msg)
		return
	}

	if iconLen > 0 {
		icon = make([]byte, iconLen)
		r, _, msg = scardGetReaderIconProc.Call(
			uintptr(c.ctx),
			uintptr(unsafe.Pointer(readerNameUtf16Ptr)),
			uintptr(unsafe.Pointer(&icon[0])),
			uintptr(unsafe.Pointer(&iconLen)),
		)
		if r != 0 {
			if winErr := maybePcscErr(r); winErr != nil {
				msg = winErr
			}
			icon = nil
			ret = uint64(r)
			err = fmt.Errorf("scardGetReaderIcon() 2nd call returned 0x%X [%v]", r, msg)
			return
		}

		if iconLen > 0 && icon != nil {
			icon = icon[:iconLen]
		}
	}

	return
}

// GetDeviceTypeId is a wrapper around SCardGetDeviceTypeId.
//
// This function gets the device type identifier of the
// card reader for the given reader name.
// This function does not affect the state of the reader.
func (c *Context) GetDeviceTypeId(
	readerName string,
) (scardReaderType SCardReaderType, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var readerNameUtf16Ptr *uint16

	logger.Infof("GetDeviceTypeId, IN : (context=0x%X, readerName=%v)",
		c.ctx, readerName)
	defer func() {
		logger.Infof("GetDeviceTypeId, OUT: (context=0x%X, readerName=%v, scardReaderType=%v)",
			c.ctx, readerName, scardReaderType.String())
	}()

	if scardGetDeviceTypeIdProc == nil {
		err = fmt.Errorf("scardGetDeviceTypeId() not found in winscard.dll")
		return
	}

	if readerName != "" {
		readerNameUtf16Ptr, err = stringToUtf16Ptr(readerName)
		if err != nil {
			err = fmt.Errorf("failed to parse reader name \"%s\" (%v)", readerName, err)
			return
		}
	}

	r, _, msg := scardGetDeviceTypeIdProc.Call(
		uintptr(c.ctx),
		uintptr(unsafe.Pointer(readerNameUtf16Ptr)),
		uintptr(unsafe.Pointer(&scardReaderType)),
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		scardReaderType = 0
		ret = uint64(r)
		err = fmt.Errorf("scardGetDeviceTypeId() returned 0x%X [%v]", r, msg)
		return
	}

	return
}

// GetReaderDeviceInstanceId is a wrapper around
// SCardGetReaderDeviceInstanceId.
//
// This function gets the device instance identifier
// of the card reader for the given reader name.
// This function does not affect the state of the reader.
func (c *Context) GetReaderDeviceInstanceId(
	readerName string,
) (deviceInstanceId string, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var deviceInstanceIdUtf16 []uint16
	var deviceInstanceIdUtf16Len dword
	var readerNameUtf16Ptr *uint16

	logger.Infof("GetReaderDeviceInstanceId, IN : (context=0x%X, readerName=%v)",
		c.ctx, readerName)
	defer func() {
		logger.Infof("GetReaderDeviceInstanceId, OUT: (context=0x%X, readerName=%v, deviceInstanceId=%v)",
			c.ctx, readerName, deviceInstanceId)
	}()

	if scardGetReaderDeviceInstanceIdProc == nil {
		err = fmt.Errorf("scardGetReaderDeviceInstanceId() not found in winscard.dll")
		return
	}

	if readerName != "" {
		readerNameUtf16Ptr, err = stringToUtf16Ptr(readerName)
		if err != nil {
			err = fmt.Errorf("failed to parse reader name \"%s\" (%v)", readerName, err)
			return
		}
	}

	r, _, msg := scardGetReaderDeviceInstanceIdProc.Call(
		uintptr(c.ctx),
		uintptr(unsafe.Pointer(readerNameUtf16Ptr)),
		uintptr(0),
		uintptr(unsafe.Pointer(&deviceInstanceIdUtf16Len)),
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardGetReaderDeviceInstanceId() 1st call returned 0x%X [%v]", r, msg)
		return
	}

	if deviceInstanceIdUtf16Len > 0 {
		deviceInstanceIdUtf16 = make([]uint16, deviceInstanceIdUtf16Len)
		r, _, msg = scardGetReaderIconProc.Call(
			uintptr(c.ctx),
			uintptr(unsafe.Pointer(readerNameUtf16Ptr)),
			uintptr(unsafe.Pointer(&deviceInstanceIdUtf16[0])),
			uintptr(unsafe.Pointer(&deviceInstanceIdUtf16Len)),
		)
		if r != 0 {
			if winErr := maybePcscErr(r); winErr != nil {
				msg = winErr
			}
			ret = uint64(r)
			err = fmt.Errorf("scardGetReaderDeviceInstanceId() 2nd call returned 0x%X [%v]", r, msg)
			return
		}

		if deviceInstanceIdUtf16Len > 0 && deviceInstanceIdUtf16 != nil {
			deviceInstanceIdUtf16 = deviceInstanceIdUtf16[:deviceInstanceIdUtf16Len]
			deviceInstanceId, err = utf16ToString(deviceInstanceIdUtf16)
			if err != nil {
				deviceInstanceId = ""
				err = fmt.Errorf("failed to parse device instance id %v (%v)", deviceInstanceIdUtf16, err)
				return
			}
		}

	}

	return
}

// ListReadersWithDeviceInstanceId is a wrapper around
// SCardListReadersWithDeviceInstanceId.
//
// This function gets the list of readers that have
// provided a device instance identifier.
// This function does not affect the state of the reader.
func (c *Context) ListReadersWithDeviceInstanceId(
	deviceInstanceId string,
) (readersNames []string, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var readersNamesUtf16 []uint16
	var readersNamesUtf16Len dword
	var deviceInstanceIdUtf16Ptr *uint16

	logger.Infof("ListReadersWithDeviceInstanceId, IN : (context=0x%X, deviceInstanceId=%v)",
		c.ctx, deviceInstanceId)
	defer func() {
		logger.Infof("ListReadersWithDeviceInstanceId, OUT: (context=0x%X, deviceInstanceId=%v, readersNames=%v)",
			c.ctx, deviceInstanceId, readersNames)
	}()

	if scardListReadersWithDeviceInstanceIdProc == nil {
		err = fmt.Errorf("scardListReadersWithDeviceInstanceId() not found in winscard.dll")
		return
	}

	if deviceInstanceId != "" {
		deviceInstanceIdUtf16Ptr, err = stringToUtf16Ptr(deviceInstanceId)
		if err != nil {
			err = fmt.Errorf("failed to parse device instance id \"%s\" (%v)", deviceInstanceId, err)
			return
		}
	}

	r, _, msg := scardListReadersWithDeviceInstanceIdProc.Call(
		uintptr(c.ctx),
		uintptr(unsafe.Pointer(deviceInstanceIdUtf16Ptr)),
		uintptr(0),
		uintptr(unsafe.Pointer(&readersNamesUtf16Len)),
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardListReadersWithDeviceInstanceId() 1st call returned 0x%X [%v]", r, msg)
		return
	}

	if readersNamesUtf16Len > 0 {
		readersNamesUtf16 = make([]uint16, readersNamesUtf16Len)
		r, _, msg = scardGetReaderIconProc.Call(
			uintptr(c.ctx),
			uintptr(unsafe.Pointer(deviceInstanceIdUtf16Ptr)),
			uintptr(unsafe.Pointer(&readersNamesUtf16[0])),
			uintptr(unsafe.Pointer(&readersNamesUtf16Len)),
		)
		if r != 0 {
			if winErr := maybePcscErr(r); winErr != nil {
				msg = winErr
			}
			ret = uint64(r)
			err = fmt.Errorf("scardListReadersWithDeviceInstanceId() 2nd call returned 0x%X [%v]", r, msg)
			return
		}

		if readersNamesUtf16Len > 0 && readersNamesUtf16 != nil {
			readersNamesUtf16 = readersNamesUtf16[:readersNamesUtf16Len]
			readersNames, err = multiUtf16StringToStrings(readersNamesUtf16)
			if err != nil {
				readersNames = nil
				err = fmt.Errorf("failed to parse readers names %v (%v)", readersNamesUtf16, err)
				return
			}
		}
	}

	return
}

// This function is a wrapper around SCardAudit.
func (c *Context) Audit(
	event SCardAuditEvent,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("Audit, IN : (context=0x%X, event=%v)", c.ctx, event.String())
	defer func() { logger.Infof("Audit, OUT: (context=0x%X, event=%v)", c.ctx, event.String()) }()

	if scardAuditProc == nil {
		err = fmt.Errorf("scardAudit() not found in winscard.dll")
		return
	}

	r, _, msg := scardAuditProc.Call(
		uintptr(c.ctx),
		uintptr(event),
	)
	if r != 0 {
		if winErr := maybePcscErr(r); winErr != nil {
			msg = winErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardAudit() returned 0x%X [%v]", r, msg)
		return
	}

	return
}
