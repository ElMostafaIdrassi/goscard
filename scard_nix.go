//go:build linux || darwin
// +build linux darwin

package goscard

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
)

//////////////////////////////////////////////////////////////////////////////////////
// Misc.
//////////////////////////////////////////////////////////////////////////////////////

func hexStringToByteArray(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func byteArrayToHexString(data []byte) string {
	return hex.EncodeToString(data)
}

// multiByteStringToStrings splits a []byte, which contains one or
// more UTF-8 char strings separated with \0 (multi-string),
// into separate UTF-8 strings and returns them in as a string
// array.
func multiByteStringToStrings(multiByteString []byte) []string {
	var strings []string
	for len(multiByteString) > 0 && multiByteString[0] != 0 {
		i := 0
		for i = range multiByteString {
			if multiByteString[i] == 0 {
				break
			}
		}
		str := string(multiByteString[:i])
		strings = append(strings, str)
		multiByteString = multiByteString[i+1:]
	}

	return strings
}

// stringsToMultiByteString creates a UTF-8 char multi-string
// from the passed string array. The char strings are
// separated with \0, and the whole multi-string is terminated
// with a double \0.
func stringsToMultiByteString(strings []string) []byte {
	var multiByteString []byte
	for _, str := range strings {
		byteString := []byte(str)
		byteString = append(byteString, 0x00)
		multiByteString = append(multiByteString, byteString...)
	}
	multiByteString = append(multiByteString, 0x00) // Add terminating \0 to get a double trailing zero.

	return multiByteString
}

//////////////////////////////////////////////////////////////////////////////////////
// PCSC headers content.
//
// Linux:
// 	From https://github.com/LudovicRousseau/PCSC/blob/master/src/PCSC/pcsclite.h.in
// 		 https://github.com/LudovicRousseau/PCSC/blob/master/src/PCSC/winscard.h,
// 		 https://github.com/LudovicRousseau/PCSC/blob/master/src/PCSC/reader.h and
//		 https://salsa.debian.org/rousseau/CCID/-/blob/master/src/ccid_ifdhandler.h.
//
// MaxOSX:
// 	From /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/
//		SDKs/MacOSX.sdk/System/Library/Frameworks/PCSC.framework/Headers/
// 		{pcsclite.h, winscard.h, wintypes.h}
// 	From https://github.com/apple-oss-distributions/SmartCardServices/blob/main/src/PCSC/reader.h
// 	From https://github.com/apple-oss-distributions/SmartcardCCID/blob/main/ccid/ccid/src/ccid_ifdhandler.h
//////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////
// pcsclite.h
//////////////////////////////////////////////////////////////////////////////////////

type SCardContext hnd
type SCardHandle hnd

const invalidHandleValue = ^hnd(0)
const scardAutoAllocate = ^dword(0)
const maxAtrSize = 33

// This is the actual golang equivalent of pcsc's SCardReaderState.
//
// Note that Apple's SCardReaderState is packed, unlike Linux's.
// In Go, there is no direct equivalent of a packed C struct, as Go does
// not provide explicit control over padding or memory alignment for struct
// fields.
// This means that if we try to use scardReaderState struct
// directly, the same way we did on Linux, we would end up with crashes
// as the pcsc C code expects a packed struct and we're feeding it an
// unpacked one
// (it expects a 61 byte long struct and we're feeding it a 64 byte long one).
// That is why we need Encode / Decode functions to ensure we get a byte
// array that actually corresponds to the memory layout and alignment
// that the pcsc C code expects. This is the only way I know of that can
// mimic a packed struct on Go.
type scardReaderState struct {
	Reader       *byte            // reader name
	UserData     unsafe.Pointer   // user defined data
	CurrentState SCardState       // current state of reader at time of call
	EventState   SCardState       // state of reader after state change
	AtrLen       dword            // Number of bytes in the returned ATR
	Atr          [maxAtrSize]byte // Atr of inserted card
}

func (rs *scardReaderState) encode() ([]byte, error) {
	var err error
	buf := new(bytes.Buffer)

	if unsafe.Sizeof(uintptr(0)) == 8 {
		err = binary.Write(buf, binary.LittleEndian, uint64(uintptr(unsafe.Pointer(rs.Reader))))
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.LittleEndian, uint64(uintptr(rs.UserData)))
		if err != nil {
			return nil, err
		}
	} else {
		err = binary.Write(buf, binary.LittleEndian, uint32(uintptr(unsafe.Pointer(rs.Reader))))
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.LittleEndian, uint32(uintptr(rs.UserData)))
		if err != nil {
			return nil, err
		}
	}

	err = binary.Write(buf, binary.LittleEndian, rs.CurrentState)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, rs.EventState)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, rs.AtrLen)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(rs.Atr[:])
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
func (rs *scardReaderState) decode(data []byte) error {
	var err error
	buf := bytes.NewReader(data)

	if unsafe.Sizeof(uintptr(0)) == 8 {
		var Reader, UserData uint64
		err = binary.Read(buf, binary.LittleEndian, &Reader)
		if err != nil {
			return err
		}
		err = binary.Read(buf, binary.LittleEndian, &UserData)
		if err != nil {
			return err
		}
		rs.Reader = (*byte)(unsafe.Pointer(uintptr(Reader)))
		rs.UserData = unsafe.Pointer(uintptr(UserData))
	} else {
		var Reader, UserData uint32
		err = binary.Read(buf, binary.LittleEndian, &Reader)
		if err != nil {
			return err
		}
		err = binary.Read(buf, binary.LittleEndian, &UserData)
		if err != nil {
			return err
		}
		rs.Reader = (*byte)(unsafe.Pointer(uintptr(Reader)))
		rs.UserData = unsafe.Pointer(uintptr(UserData))
	}

	err = binary.Read(buf, binary.LittleEndian, &rs.CurrentState)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &rs.EventState)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &rs.AtrLen)
	if err != nil {
		return err
	}
	_, err = buf.Read(rs.Atr[:])
	if err != nil {
		return err
	}

	return nil
}
func encodeReaderStateArray(rsArray []scardReaderState) ([]byte, error) {
	buf := new(bytes.Buffer)

	for _, rs := range rsArray {
		encoded, err := rs.encode()
		if err != nil {
			return nil, err
		}
		_, err = buf.Write(encoded)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
func decodeReaderStateArray(data []byte, itemCount int) ([]scardReaderState, error) {
	// Calculate the item size from an encoded instance
	itemSize := len(data) / itemCount
	if len(data)%itemCount != 0 {
		return nil, errors.New("input data length does not match expected array size")
	}

	rsArray := make([]scardReaderState, itemCount)
	for i := 0; i < itemCount; i++ {
		err := rsArray[i].decode(data[i*itemSize : (i+1)*itemSize])
		if err != nil {
			return nil, err
		}
	}

	return rsArray, nil
}

type SCardReaderState struct {
	Reader       string         // reader name
	UserData     unsafe.Pointer // user defined data
	CurrentState SCardState     // current state of reader at time of call
	EventState   SCardState     // state of reader after state change
	Atr          string         // Atr of inserted card
}

func (s *SCardReaderState) fromInternal(internalReaderState scardReaderState, readerNameLen int) {
	readerNameChars := (*[1 << 30]byte)(unsafe.Pointer(internalReaderState.Reader))[:readerNameLen:readerNameLen]
	s.Reader = string(readerNameChars)
	s.UserData = internalReaderState.UserData
	s.CurrentState = internalReaderState.CurrentState
	s.EventState = internalReaderState.EventState
	if internalReaderState.AtrLen > 0 {
		s.Atr = byteArrayToHexString(internalReaderState.Atr[:internalReaderState.AtrLen])
	}
}

func (s *SCardReaderState) toInternal() (scardReaderState, int, error) {
	var atr [maxAtrSize]byte
	var atrLen dword
	readerNameChars := []byte(s.Reader)
	readerNameLen := len(readerNameChars)
	if len(s.Atr) > 0 {
		atrBytes, err := hexStringToByteArray(s.Atr)
		if err != nil {
			return scardReaderState{}, 0, fmt.Errorf("failed to parse atr \"%s\" (%w)", s.Atr, err)
		}
		copy(atr[:], atrBytes)
		atrLen = dword(len(atrBytes))
		if len(atrBytes) > maxAtrSize {
			atrLen = maxAtrSize
		}
	}
	return scardReaderState{
		Reader:       &readerNameChars[0],
		UserData:     s.UserData,
		CurrentState: s.CurrentState,
		EventState:   s.EventState,
		AtrLen:       atrLen,
		Atr:          atr,
	}, readerNameLen, nil
}

// Protocol Control Information (PCI)
type SCardIORequest struct {
	Protocol  dword // Protocol identifier
	PciLength dword // Protocol Control Information Length
}

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
	}
)

func maybePcscErr(errNo dword) error {
	if code, known := scardErrNums[uint64(errNo)]; known {
		return fmt.Errorf("scard failure: 0x%.8X (%s) (%s)", errNo, code, PcscStringifyError(uint64(errNo)))
	} else {
		return fmt.Errorf("errno code: 0x%.8X (%s)", errNo, syscall.Errno(errNo).Error())
	}
}

type SCardScope dword

const (
	// Scope in user space
	SCardScopeUser SCardScope = 0x0000
	// Scope in terminal
	SCardScopeTerminal SCardScope = 0x0001
	// Scope in system
	SCardScopeSystem SCardScope = 0x0002
	// Scope is global
	SCardScopeGlobal SCardScope = 0x0003
)

func (s *SCardScope) String() string {
	switch *s {
	case SCardScopeUser:
		return "User"
	case SCardScopeTerminal:
		return "Terminal"
	case SCardScopeSystem:
		return "System"
	case SCardScopeGlobal:
		return "Global"
	default:
		return "N/A"
	}
}

type SCardProtocol dword

const (
	SCardProtocolUndefined SCardProtocol = 0x0000                            // protocol not set
	SCardProtocolUnset     SCardProtocol = SCardProtocolUndefined            // backward compat
	SCardProtocolT0        SCardProtocol = 0x0001                            // T=0 active protocol.
	SCardProtocolT1        SCardProtocol = 0x0002                            // T=1 active protocol.
	SCardProtocolRaw       SCardProtocol = 0x0004                            // Raw active protocol.
	SCardProtocolT15       SCardProtocol = 0x0008                            // T=15 protocol.
	SCardProtocolAny       SCardProtocol = SCardProtocolT0 | SCardProtocolT1 // IFD determines prot.
)

func (s SCardProtocol) String() string {
	output := ""

	if s == SCardProtocolUndefined {
		output += "Undefined"
	} else {
		if s&SCardProtocolT0 == SCardProtocolT0 {
			output += "T0;"
		}
		if s&SCardProtocolT1 == SCardProtocolT1 {
			output += "T1;"
		}
		if s&SCardProtocolRaw == SCardProtocolRaw {
			output += "Raw;"
		}
		if s&SCardProtocolT15 == SCardProtocolT15 {
			output += "T15;"
		}

		if len(output) > 0 {
			output = output[:len(output)-1] // Remove last ';'
		}
	}

	return output
}

type SCardShareMode dword

const (
	// Exclusive mode only
	SCardShareExclusive SCardShareMode = 0x0001
	// Shared mode only
	SCardShareShared SCardShareMode = 0x0002
	// Raw mode only
	SCardShareDirect SCardShareMode = 0x0003
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
	// Do nothing on close
	SCardLeaveCard SCardDisposition = 0x0000
	// Reset on close
	SCardResetCard SCardDisposition = 0x0001
	// Power down on close
	SCardUnpowerCard SCardDisposition = 0x0002
	// Eject on close
	SCardEjectCard SCardDisposition = 0x0003
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

type ReaderState dword

const (
	SCardUnknown    ReaderState = 0x0001 // Unknown state
	SCardAbsent     ReaderState = 0x0002 // Card is absent
	SCardPresent    ReaderState = 0x0004 // Card is present
	SCardSwallowed  ReaderState = 0x0008 // Card not powered
	SCardPowered    ReaderState = 0x0010 // Card is powered
	SCardNegotiable ReaderState = 0x0020 // Ready for PTS
	SCardSpecific   ReaderState = 0x0040 // PTS has been set
)

func (s *ReaderState) String() string {
	output := ""

	if *s&SCardUnknown == SCardUnknown {
		output += "Unknown;"
	}
	if *s&SCardAbsent == SCardAbsent {
		output += "Absent;"
	}
	if *s&SCardPresent == SCardPresent {
		output += "Present;"
	}
	if *s&SCardSwallowed == SCardSwallowed {
		output += "Swallowed;"
	}
	if *s&SCardPowered == SCardPowered {
		output += "Powered;"
	}
	if *s&SCardNegotiable == SCardNegotiable {
		output += "Negotiable;"
	}
	if *s&SCardSpecific == SCardSpecific {
		output += "Specific;"
	}

	if len(output) > 0 {
		output = output[:len(output)-1] // Remove last ';'
	}

	return output
}

type SCardState dword

const (
	// App wants status
	SCardStateUnaware SCardState = 0x0000
	// Ignore this reader
	SCardStateIgnore SCardState = 0x0001
	// State has changed
	SCardStateChanged SCardState = 0x0002
	// Reader unknown
	SCardStateUnknown SCardState = 0x0004
	// Status unavailable
	SCardStateUnavailable SCardState = 0x0008
	// Card removed
	SCardStateEmpty SCardState = 0x0010
	// Card inserted
	SCardStatePresent SCardState = 0x0020
	// ATR matches card
	SCardStateAtrmatch SCardState = 0x0040
	// Exclusive Mode
	SCardStateExclusive SCardState = 0x0080
	// Shared Mode
	SCardStateInuse SCardState = 0x0100
	// Unresponsive card
	SCardStateMute SCardState = 0x0200
	// Unpowered card
	SCardStateUnpowered SCardState = 0x0400
)

func (s *SCardState) String() string {
	output := ""

	if *s == SCardStateUnaware {
		output += "Unaware"
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

		if len(output) > 0 {
			output = output[:len(output)-1] // Remove last ';'
		}
	}

	return output
}

const (
	infiniteTimeout            dword = 0xFFFFFFFF
	pcscLiteMaxReadersContexts dword = 16 // Maximum readers context (a slot is count as a reader)
	maxReaderName              dword = 128
	scardAtrLength             dword = maxAtrSize // Maximum ATR size
	maxBufferSize              dword = 264        // Maximum Tx/Rx Buffer for short APDU
)

//////////////////////////////////////////////////////////////////////////////////////
// reader.h
//////////////////////////////////////////////////////////////////////////////////////

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
	case SCardClassSystem:
		return "System"
	default:
		return "N/A"
	}
}

var (
	SCardAttrVendorName           SCardAttr = scardAttrValue(SCardClassVendorInfo, 0x0100)
	SCardAttrVendorIFDType        SCardAttr = scardAttrValue(SCardClassVendorInfo, 0x0101)
	SCardAttrVendorIFDVersion     SCardAttr = scardAttrValue(SCardClassVendorInfo, 0x0102)
	SCardAttrVendorIFDSerialNo    SCardAttr = scardAttrValue(SCardClassVendorInfo, 0x0103)
	SCardAttrChannelID            SCardAttr = scardAttrValue(SCardClassCommunications, 0x0110)
	SCardAttrAsyncProtocolTypes   SCardAttr = scardAttrValue(SCardClassProtocol, 0x0120)
	SCardAttrDefaultClk           SCardAttr = scardAttrValue(SCardClassProtocol, 0x0121)
	SCardAttrMaxClk               SCardAttr = scardAttrValue(SCardClassProtocol, 0x0122)
	SCardAttrDefaultDataRate      SCardAttr = scardAttrValue(SCardClassProtocol, 0x0123)
	SCardAttrMaxDataRate          SCardAttr = scardAttrValue(SCardClassProtocol, 0x0124)
	SCardAttrMaxIFSD              SCardAttr = scardAttrValue(SCardClassProtocol, 0x0125)
	SCardAttrSyncProtocolTypes    SCardAttr = scardAttrValue(SCardClassProtocol, 0x0126)
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

	SCardAttrESCReset       SCardAttr = scardAttrValue(SCardClassVendorDefined, 0xA000)
	SCardAttrESCCancel      SCardAttr = scardAttrValue(SCardClassVendorDefined, 0xA003)
	SCardAttrESCAuthRequest SCardAttr = scardAttrValue(SCardClassVendorDefined, 0xA005)
	SCardAttrMaxInput       SCardAttr = scardAttrValue(SCardClassVendorDefined, 0xA007)

	SCardAttrDeviceUnit           SCardAttr = scardAttrValue(SCardClassSystem, 0x0001)
	SCardAttrDeviceInUse          SCardAttr = scardAttrValue(SCardClassSystem, 0x0002)
	SCardAttrDeviceFriendlyNameA  SCardAttr = scardAttrValue(SCardClassSystem, 0x0003)
	SCardAttrDeviceSystemNameA    SCardAttr = scardAttrValue(SCardClassSystem, 0x0004)
	SCardAttrDeviceFriendlyNameW  SCardAttr = scardAttrValue(SCardClassSystem, 0x0005)
	SCardAttrDeviceSystemNameW    SCardAttr = scardAttrValue(SCardClassSystem, 0x0006)
	SCardAttrSuppressT1IFSRequest SCardAttr = scardAttrValue(SCardClassSystem, 0x0007)

	SCardAttrDeviceFriendlyName SCardAttr = SCardAttrDeviceFriendlyNameA
	SCardAttrDeviceSystemName   SCardAttr = SCardAttrDeviceSystemNameA
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
	}
	return "N/A"
}

type SCardCtlCode dword

func scardCtlCodeFunc(code dword) SCardCtlCode {
	return SCardCtlCode(0x42000000 + code)
}

type Feature dword

const (
	FeatureVerifyPinStart       Feature = 0x01
	FeatureVerifyPinFinish      Feature = 0x02
	FeatureModifyPinStart       Feature = 0x03
	FeatureModifyPinFinish      Feature = 0x04
	FeatureGetKeyPressed        Feature = 0x05
	FeatureVerifyPinDirect      Feature = 0x06
	FeatureModifyPinDirect      Feature = 0x07
	FeatureMctReaderDirect      Feature = 0x08
	FeatureMctUniversal         Feature = 0x09
	FeatureIfdPinProperties     Feature = 0x0A
	FeatureAbort                Feature = 0x0B
	FeatureSetSPEMessage        Feature = 0x0C
	FeatureVerifyPinDirectAppID Feature = 0x0D
	FeatureModifyPinDirectAppID Feature = 0x0E
	FeatureWriteDisplay         Feature = 0x0F
	FeatureGetKey               Feature = 0x10
	FeatureIfdDisplayProperties Feature = 0x11
	FeatureGetTlvProperties     Feature = 0x12
	FeatureCcidEscCommand       Feature = 0x13
)

type PcscTlvStructure struct {
	Tag    uint8
	Length uint8
	Value  uint32 // This value is always in BIG ENDIAN format as documented in PCSC v2 part 10 ch 2.2 page 2. You can use ntohl() for example
}

// Structure used with FEATURE_VERIFY_PIN_DIRECT
type PinVerifyStructure struct {
	TimerOut                 uint8    // timeout is seconds (00 means use default timeout)
	TimerOut2                uint8    // timeout in seconds after first key stroke
	FormatString             uint8    // formatting options
	PINBlockString           uint8    // bits 7-4 bit size of PIN length in APDU, bits 3-0 PIN block size in bytes after justification and formatting
	PINLengthFormat          uint8    // bits 7-5 RFU, bit 4 set if system units are bytes, clear if system units are bits, bits 3-0 PIN length position in system units
	PINMaxExtraDigit         uint16   // 0xXXYY where XX is minimum PIN size in digits, and YY is maximum PIN size in digits
	EntryValidationCondition uint8    // Conditions under which PIN entry should be considered complete
	NumberMessage            uint8    // Number of messages to display for PIN verification
	LangId                   uint16   // Language for messages. https://docs.microsoft.com/en-us/windows/win32/intl/language-identifier-constants-and-strings
	MsgIndex                 uint8    // Message index (should be 00)
	TeoPrologue              [3]uint8 // T=1 block prologue field to use (fill with 00)
	DataLength               uint32   // length of Data to be sent to the ICC
	Data                     []uint8  // Data to send to the ICC
}

// Structure used with FEATURE_MODIFY_PIN_DIRECT
type PinModifyStructure struct {
	TimerOut                 uint8    // timeout is seconds (00 means use default timeout)
	TimerOut2                uint8    // timeout in seconds after first key stroke
	FormatString             uint8    // formatting options
	PINBlockString           uint8    // bits 7-4 bit size of PIN length in APDU, bits 3-0 PIN block size in bytes after justification and formatting
	PINLengthFormat          uint8    // bits 7-5 RFU, bit 4 set if system units are bytes, clear if system units are bits, bits 3-0 PIN length position in system units
	InsertionOffsetOld       uint8    // Insertion position offset in bytes for the current PIN
	InsertionOffsetNew       uint8    // Insertion position offset in bytes for the new PIN
	PINMaxExtraDigit         uint16   // 0xXXYY where XX is minimum PIN size in digits, and YY is maximum PIN size in digits
	ConfirmPIN               uint8    // Flags governing need for confirmation of new PIN
	EntryValidationCondition uint8    // Conditions under which PIN entry should be considered complete
	NumberMessage            uint8    // Number of messages to display for PIN verification*/
	LangId                   uint16   // Language for messages. https://docs.microsoft.com/en-us/windows/win32/intl/language-identifier-constants-and-strings
	MsgIndex1                uint8    // index of 1st prompting message
	MsgIndex2                uint8    // index of 2d prompting message
	MsgIndex3                uint8    // index of 3d prompting message
	TeoPrologue              [3]uint8 // T=1 block prologue field to use (fill with 00)
	DataLength               uint32   // length of Data to be sent to the ICC
	Data                     []uint8  // Data to send to the ICC
}

// Structure used with FEATURE_IFD_PIN_PROPERTIES
type PinPropertiesStructure struct {
	LcdLayout                uint16 // display characteristics
	EntryValidationCondition uint8
	TimeOut2                 uint8
}

//////////////////////////////////////////////////////////////////////////////////////
// ccid_ifdhandler.h
//////////////////////////////////////////////////////////////////////////////////////

var (
	class2IoctlMagic                dword        = 0x330000
	IoctlSmartCardVendorIfdExchange SCardCtlCode = scardCtlCodeFunc(1)
	IoctlFeatureVerifyPinDirect     SCardCtlCode = scardCtlCodeFunc(dword(FeatureVerifyPinDirect) + class2IoctlMagic)
	IoctlFeatureModifyPinDirect     SCardCtlCode = scardCtlCodeFunc(dword(FeatureModifyPinDirect) + class2IoctlMagic)
	IoctlFeatureMctReaderDirect     SCardCtlCode = scardCtlCodeFunc(dword(FeatureMctReaderDirect) + class2IoctlMagic)
	IoctlFeatureIfdPinProperties    SCardCtlCode = scardCtlCodeFunc(dword(FeatureIfdPinProperties) + class2IoctlMagic)
	IoctlFeatureGetTlvProperties    SCardCtlCode = scardCtlCodeFunc(dword(FeatureGetTlvProperties) + class2IoctlMagic)
)

const ccidDriverMaxReaders dword = 16

//////////////////////////////////////////////////////////////////////////////////////
// winscard.h
//////////////////////////////////////////////////////////////////////////////////////

const (
	SCardAllReaders     = "SCard$AllReaders"
	SCardDefaultReaders = "SCard$DefaultReaders"
	SCardLocalReaders   = "SCard$LocalReaders"
	SCardSystemReaders  = "SCard$SystemReaders"
)

////////////////////////////////////////////////////////////////////
// The following functions are common to both Linux and MacOSX.
////////////////////////////////////////////////////////////////////

type pcscStringifyError func(pcscError scardRet) string

type scardEstablishContext func(
	dwScope SCardScope, // in
	pvReserved1 uintptr, // in
	pvReserved2 uintptr, // in
	phContext *SCardContext, // out
) dword

type scardReleaseContext func(
	hContext SCardContext, // in
) dword

type scardIsValidContext func(
	hContext SCardContext, // in
) dword

type scardConnect func(
	hContext SCardContext, // in
	szReader string, // in
	dwShareMode SCardShareMode, // in
	dwPreferredProtocols SCardProtocol, // in
	phCard *SCardHandle, // out
	pdwActiveProtocol *SCardProtocol, // out
) dword

type scardReconnect func(
	hCard SCardHandle, // in
	dwShareMode SCardShareMode, // in
	dwPreferredProtocols SCardProtocol, // in
	dwInitialization SCardDisposition, // in
	pdwActiveProtocol *SCardProtocol, // out
) dword

type scardDisconnect func(
	hCard SCardHandle, // in
	dwDisposition SCardDisposition, // in
) dword

type scardBeginTransaction func(
	hCard SCardHandle, // in
) dword

type scardEndTransaction func(
	hCard SCardHandle, // in
	dwDisposition SCardDisposition, // in
) dword

type scardStatus func(
	hCard SCardHandle, // in
	szReaderName str, // in, out
	pcchReaderLen *dword, // in, out
	pdwState *ReaderState, // out
	pdwProtocol *SCardProtocol, // out
	pbAtr *byte, // out
	pcbAtrLen *dword, // out
) dword

type scardTransmit func(
	hCard SCardHandle, // in
	pioSendPci *SCardIORequest, // in
	pbSendBuffer *byte, // in
	cbSendLength dword, // in
	pioRecvPci *SCardIORequest, // in, out
	pbRecvBuffer *byte, // out
	pcbRecvLength *dword, // in, out
) dword

type scardListReaderGroups func(
	hContext SCardContext, // in
	mszGroups str, // out
	pcchGroups *dword, // in, out
) dword

type scardListReaders func(
	hContext SCardContext, // in
	mszGroups str, // in
	mszReaders str, // out
	pcchReaders *dword, // in, out
) dword

type scardFreeMemory func(
	hContext SCardContext, // in
	pvMem unsafe.Pointer, // in
) dword

type scardCancel func(
	hContext SCardContext, // in
) dword

type scardGetAttrib func(
	hCard SCardHandle, // in
	dwAttrId SCardAttr, // in
	pbAttr *byte, // out
	pcbAttrLen *dword, // in, out
) dword

type scardSetAttrib func(
	hCard SCardHandle, // in
	dwAttrId SCardAttr, // in
	pbAttr *byte, // in
	cbAttrLen dword, // in
) dword

// scardGetStatusChange and scardControl are defined
// differently on Linux and MacOSX, so they are not
// defined here.

////////////////////////////////////////////////////////////////////
// The following functions are only defined on MacOSX.
////////////////////////////////////////////////////////////////////

type scardCancelTransaction func(
	hCard SCardHandle, // in
) dword

type scardControl132 func(
	hCard SCardHandle, // in
	dwControlCode SCardCtlCode, // in
	pbSendBuffer *byte, // in
	cbSendLength dword, // in
	pbRecvBuffer *byte, // out
	cbRecvLength dword, // in
	lpBytesReturned *dword, // out
) dword

type scardSetTimeout func(
	hContext SCardContext, // in
	dwTimeout dword, // in
) dword

type scardUnload func() dword

//////////////////////////////////////////////////////////////////////////////////////
// SCard functions.
//////////////////////////////////////////////////////////////////////////////////////

var (
	pcscLib uintptr

	////////////////////////////////////////////////////////////////////
	// The following functions are common to both Linux and MacOSX.
	////////////////////////////////////////////////////////////////////

	pcscStringifyErrorProc    pcscStringifyError
	scardBeginTransactionProc scardBeginTransaction
	scardCancelProc           scardCancel
	scardConnectProc          scardConnect
	scardControlProc          scardControl
	scardDisconnectProc       scardDisconnect
	scardEndTransactionProc   scardEndTransaction
	scardEstablishContextProc scardEstablishContext
	scardFreeMemoryProc       scardFreeMemory
	scardGetAttribProc        scardGetAttrib
	scardGetStatusChangeProc  scardGetStatusChange
	scardIsValidContextProc   scardIsValidContext
	scardListReaderGroupsProc scardListReaderGroups
	scardListReadersProc      scardListReaders
	scardReconnectProc        scardReconnect
	scardReleaseContextProc   scardReleaseContext
	scardSetAttribProc        scardSetAttrib
	scardStatusProc           scardStatus
	scardTransmitProc         scardTransmit
	scardPciT0                uintptr
	scardPciT1                uintptr
	scardPciRaw               uintptr

	SCardIoRequestT0  SCardIORequest
	SCardIoRequestT1  SCardIORequest
	SCardIoRequestRaw SCardIORequest

	////////////////////////////////////////////////////////////////////
	// The following functions are only defined on MacOSX.
	////////////////////////////////////////////////////////////////////

	scardCancelTransactionProc scardCancelTransaction
	scardControl132Proc        scardControl132
	scardSetTimeoutProc        scardSetTimeout
	scardUnloadProc            scardUnload
)

var (
	pcscLibProcs = []string{
		"pcsc_stringify_error",
		"SCardBeginTransaction",
		"SCardCancel",
		"SCardCancelTransaction",
		"SCardConnect",
		"SCardControl",
		"SCardControl132",
		"SCardDisconnect",
		"SCardEndTransaction",
		"SCardEstablishContext",
		"SCardFreeMemory",
		"SCardGetAttrib",
		"SCardGetStatusChange",
		"SCardIsValidContext",
		"SCardListReaderGroups",
		"SCardListReaders",
		"SCardReconnect",
		"SCardReleaseContext",
		"SCardSetAttrib",
		"SCardSetTimeout",
		"SCardStatus",
		"SCardTransmit",
		"SCardUnload",
		"g_rgSCardT0Pci",
		"g_rgSCardT1Pci",
		"g_rgSCardRawPci",
	}
)

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
// winscard in its usual places. Otherwise, the specified paths will be used.
func Initialize(customLogger Logger, scardLibPaths ...string) (errRet error) {
	if pcscLib == 0 {
		// Set logger.
		if customLogger != nil {
			logger = customLogger
		}

		defer func() {
			if errRet != nil {
				logger.Error(errRet)
			}
		}()

		// Construct the pcsc lib paths.
		pcscLibPaths := scardLibPaths

		if pcscLibPaths == nil {
			// We first rely on the default search paths of the linker.
			// See https://man7.org/linux/man-pages/man8/ld.so.8.html.
			if runtime.GOOS == "linux" {
				pcscLibPaths = []string{
					"libpcsclite.so",
					"libpcsclite.so.1",
					"libpcsclite.so.1.0.0",
					"/usr/lib64/libpcsclite.so.1.0.0",                // CentOS 7 x86_64, RHEL 7 x86_64, openSUSE x86_64, SLES x86_64
					"/usr/lib/x86_64-linux-gnu/libpcsclite.so.1.0.0", // Debian amd64
					"/usr/lib/libpcsclite.so.1.0.0",                  // CentOS 7 x86, RHEL 7 x86, CentOS 8 / 9 x86_64, RHEL 8 / 9 x86_64
					"/usr/lib/i386-linux-gnu/libpcsclite.so.1.0.0",   // Debian i386
				}
			} else if runtime.GOOS == "darwin" {
				pcscLibPaths = []string{"/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC"}
			}
		}

		// Load pcsc lib..
		var err error
		for _, pcscLibPath := range pcscLibPaths {
			logger.Debugf("Loading PCSC library at \"%s\"", pcscLibPath)
			pcscLib, err = purego.Dlopen(pcscLibPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
			if err != nil {
				logger.Errorf("Failed to load PCSC library at \"%s\" (%v)", pcscLibPath, err)
			} else if pcscLib == 0 {
				logger.Errorf("PCSC library loaded at \"%s\" is nil (%v)", pcscLibPath, err)
			} else {
				break
			}
		}
		if pcscLib == 0 {
			errRet = fmt.Errorf("could not load PCSC library")
			return
		}

		// Find scard functions.
		for _, pcscProcName := range pcscLibProcs {
			sym, err := purego.Dlsym(pcscLib, pcscProcName)
			if err != nil {
				logger.Errorf("Failed to find \"%s\" (%v)", pcscProcName, err)
			} else {
				if pcscProcName == "g_rgSCardT0Pci" {
					scardPciT0 = sym
				} else if pcscProcName == "g_rgSCardT1Pci" {
					scardPciT1 = sym
				} else if pcscProcName == "g_rgSCardRawPci" {
					scardPciRaw = sym
				} else {
					switch pcscProcName {
					case "pcsc_stringify_error":
						purego.RegisterFunc(&pcscStringifyErrorProc, sym)
					case "SCardBeginTransaction":
						purego.RegisterFunc(&scardBeginTransactionProc, sym)
					case "SCardCancel":
						purego.RegisterFunc(&scardCancelProc, sym)
					case "SCardCancelTransaction":
						purego.RegisterFunc(&scardCancelTransactionProc, sym)
					case "SCardConnect":
						purego.RegisterFunc(&scardConnectProc, sym)
					case "SCardControl":
						purego.RegisterFunc(&scardControlProc, sym)
					case "SCardControl132":
						purego.RegisterFunc(&scardControl132Proc, sym)
					case "SCardDisconnect":
						purego.RegisterFunc(&scardDisconnectProc, sym)
					case "SCardEndTransaction":
						purego.RegisterFunc(&scardEndTransactionProc, sym)
					case "SCardEstablishContext":
						purego.RegisterFunc(&scardEstablishContextProc, sym)
					case "SCardFreeMemory":
						purego.RegisterFunc(&scardFreeMemoryProc, sym)
					case "SCardGetAttrib":
						purego.RegisterFunc(&scardGetAttribProc, sym)
					case "SCardGetStatusChange":
						purego.RegisterFunc(&scardGetStatusChangeProc, sym)
					case "SCardIsValidContext":
						purego.RegisterFunc(&scardIsValidContextProc, sym)
					case "SCardListReaderGroups":
						purego.RegisterFunc(&scardListReaderGroupsProc, sym)
					case "SCardListReaders":
						purego.RegisterFunc(&scardListReadersProc, sym)
					case "SCardReconnect":
						purego.RegisterFunc(&scardReconnectProc, sym)
					case "SCardReleaseContext":
						purego.RegisterFunc(&scardReleaseContextProc, sym)
					case "SCardSetAttrib":
						purego.RegisterFunc(&scardSetAttribProc, sym)
					case "SCardSetTimeout":
						purego.RegisterFunc(&scardSetTimeoutProc, sym)
					case "SCardStatus":
						purego.RegisterFunc(&scardStatusProc, sym)
					case "SCardTransmit":
						purego.RegisterFunc(&scardTransmitProc, sym)
					case "SCardUnload":
						purego.RegisterFunc(&scardUnloadProc, sym)
					}
				}
			}
		}
		if scardPciT0 != 0 {
			SCardIoRequestT0St := unsafe.Slice((*SCardIORequest)(unsafe.Pointer(scardPciT0)), 1)
			if len(SCardIoRequestT0St) == 1 {
				SCardIoRequestT0 = SCardIoRequestT0St[0]
			}
		} else {
			// If, for some reason, we're not able to gather SCardIoRequestT0 from pcsclite,
			// we set it manually.
			SCardIoRequestT0 = SCardIORequest{
				Protocol:  dword(SCardProtocolT0),
				PciLength: dword(unsafe.Sizeof(SCardIORequest{})),
			}
		}
		if scardPciT1 != 0 {
			SCardIoRequestT1St := unsafe.Slice((*SCardIORequest)(unsafe.Pointer(scardPciT1)), 1)
			if len(SCardIoRequestT1St) == 1 {
				SCardIoRequestT1 = SCardIoRequestT1St[0]
			}
		} else {
			// If, for some reason, we're not able to gather SCardIoRequestT1 from pcsclite,
			// we set it manually.
			SCardIoRequestT1 = SCardIORequest{
				Protocol:  dword(SCardProtocolT1),
				PciLength: dword(unsafe.Sizeof(SCardIORequest{})),
			}
		}
		if scardPciRaw != 0 {
			SCardIoRequestRawSt := unsafe.Slice((*SCardIORequest)(unsafe.Pointer(scardPciRaw)), 1)
			if len(SCardIoRequestRawSt) == 1 {
				SCardIoRequestRaw = SCardIoRequestRawSt[0]
			}
		} else {
			// If, for some reason, we're not able to gather SCardIoRequestRaw from pcsclite,
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
// on the library. It ensures that the previously loaded
// pcsc library and functions are unloaded.
func Finalize() {
	if pcscLib != 0 {
		purego.Dlclose(pcscLib)
		pcscLib = 0

		pcscStringifyErrorProc = nil
		scardBeginTransactionProc = nil
		scardCancelProc = nil
		scardConnectProc = nil
		scardControlProc = nil
		scardDisconnectProc = nil
		scardEndTransactionProc = nil
		scardEstablishContextProc = nil
		scardFreeMemoryProc = nil
		scardGetAttribProc = nil
		scardGetStatusChangeProc = nil
		scardIsValidContextProc = nil
		scardListReaderGroupsProc = nil
		scardListReadersProc = nil
		scardReconnectProc = nil
		scardReleaseContextProc = nil
		scardSetAttribProc = nil
		scardStatusProc = nil
		scardTransmitProc = nil
		scardPciT0 = 0
		scardPciT1 = 0
		scardPciRaw = 0
		scardCancelTransactionProc = nil
		scardControl132Proc = nil
		scardSetTimeoutProc = nil
		scardUnloadProc = nil
	}
}

// NewContext is a wrapper around SCardEstablichContext.
//
// This function ccreates an Application Context to the PC/SC Resource Manager.
// This must be the first WinSCard function called in a PC/SC application.
// Each thread of an application shall use its own SCardContext,
// unless calling SCardCancel(), which MUST be called with the same context
// as the context used to call SCardGetStatusChange().
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
	defer func() {
		logger.Infof("NewContext, OUT: (context=0x%.8X, ret=0x%.8X)", scardContext, ret)
	}()

	if scardEstablishContextProc == nil {
		err = fmt.Errorf("scardEstablishContext() not found in pcsc")
		return
	}

	r := scardEstablishContextProc(
		scope,              /* DWORD */
		uintptr(reserved1), /* LPCVOID */
		uintptr(reserved2), /* LPCVOID */
		&scardContext,      /* LPSCARDCONTEXT */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardEstablishContext() returned 0x%.8X [%w]", r, msg)
		return
	}

	context.ctx = scardContext

	return
}

// Release function is a wrapper around SCardReleaseContext.
//
// This function destroys a communication context to the
// PC/SC Resource Manager.
// This must be the last function called in a PC/SC application.
func (c *Context) Release() (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("Release, IN : (context=0x%.8X)", c.ctx)
	defer func() {
		logger.Infof("Release, OUT : (context=0x%.8X, ret=0x%.8X)", c.ctx, ret)
	}()

	if scardReleaseContextProc == nil {
		err = fmt.Errorf("scardReleaseContext() not found in pcsc")
		return
	}

	r := scardReleaseContextProc(
		c.ctx, /* SCARDCONTEXT */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardReleaseContext() returned 0x%.8X [%w]", r, msg)
		return
	}

	c.ctx = SCardContext(invalidHandleValue)

	return
}

// IsValid is a wrapper around SCardIsValidContext.
//
// This function checks if a SCardContext is valid.
// Call this function to determine whether a smart card context
// handle is still valid. After a smart card context handle has
// been returned by SCardEstablishContext(), it may become invalid
// if the resource manager service has been shut down.
func (c *Context) IsValid() (isValid bool, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("IsValid, IN : (context=0x%.8X)", c.ctx)
	defer func() {
		logger.Infof("IsValid, OUT: (context=0x%.8X, isValid=%v, ret=0x%.8X)", c.ctx, isValid, ret)
	}()

	if scardIsValidContextProc == nil {
		err = fmt.Errorf("scardIsValidContext() not found in pcsc")
		return
	}

	r := scardIsValidContextProc(
		c.ctx, /* SCARDCONTEXT */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardIsValidContext() returned 0x%.8X [%w]", r, msg)
		return
	}

	isValid = true
	return
}

// ListReaders is a wrapper around SCardListReaders.
//
// This function returns a list of currently available readers on the system.
func (c *Context) ListReaders(
	groups []string,
) (readers []string, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var groupsChars []byte
	var groupsCharsPtr *byte
	var readersChars []byte
	var readersCharsLen dword

	logger.Infof("ListReaders, IN : (context=0x%.8X, groups=%v)", c.ctx, groups)
	defer func() {
		logger.Infof("ListReaders, OUT: (context=0x%.8X, readers=%v, ret=0x%.8X)", c.ctx, readers, ret)
	}()

	if scardListReadersProc == nil {
		err = fmt.Errorf("scardListReaders() not found in pcsc")
		return
	}

	if len(groups) > 0 {
		groupsChars = stringsToMultiByteString(groups)
		groupsCharsPtr = &groupsChars[0]
	}

	r := scardListReadersProc(
		c.ctx,            /* SCARDCONTEXT */
		groupsCharsPtr,   /* LPCSTR */
		nil,              /* LPSTR */
		&readersCharsLen, /* LPDWORD */
	)
	if r != 0 {
		ret = uint64(r)
		if r != 0x8010002E && r != 0x8010001E { // SCARD_E_NO_READERS_AVAILABLE / SCARD_E_SERVICE_STOPPED
			var msg error
			if pcscErr := maybePcscErr(r); pcscErr != nil {
				msg = pcscErr
			}
			err = fmt.Errorf("scardListReaders() 1st call returned 0x%.8X [%w]", r, msg)
		}
		return
	}

	if readersCharsLen > 0 {
		readersChars = make([]byte, readersCharsLen)
		r = scardListReadersProc(
			c.ctx,            /* SCARDCONTEXT */
			groupsCharsPtr,   /* LPCSTR */
			&readersChars[0], /* LPSTR */
			&readersCharsLen, /* LPDWORD */
		)
		if r != 0 {
			ret = uint64(r)
			if r != 0x8010002E && r != 0x8010001E { // SCARD_E_NO_READERS_AVAILABLE / SCARD_E_SERVICE_STOPPED
				var msg error
				if pcscErr := maybePcscErr(r); pcscErr != nil {
					msg = pcscErr
				}
				err = fmt.Errorf("scardListReaders() 2nd call returned 0x%.8X [%w]", r, msg)
			}
			return
		}

		if readersCharsLen > 0 {
			readersChars = readersChars[:readersCharsLen]
			readers = multiByteStringToStrings(readersChars)
		}
	}

	return
}

// ListReadersWithCardPresent is a wrapper around SCardListReaders,
// but only returns readers with a card present and its ATR.
//
// This function returns a list of currently available readers on the system
// which have a card present.
func (c *Context) ListReadersWithCardPresent(
	groups []string,
) (readers []string, atrs []string, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("ListReadersWithCardPresent, IN : (context=0x%.8X, groups=%v)", c.ctx, groups)
	defer func() {
		logger.Infof("ListReadersWithCardPresent, OUT: (context=0x%.8X, readers=%v, atrs=%v, ret=0x%.8X)", c.ctx, readers, atrs, ret)
	}()

	var allReaders []string

	allReaders, ret, err = c.ListReaders(groups)
	if err != nil {
		return
	}

	for _, reader := range allReaders {
		states := make([]SCardReaderState, 1)
		states[0].Reader = reader
		ret, err = c.GetStatusChange(NewTimeout(0), states)
		if err != nil {
			logger.Errorf("GetStatusChange failed for reader %s (%v). Skipping it...", reader, err)
		} else {
			if states[0].EventState&SCardStatePresent == SCardStatePresent && states[0].EventState&SCardStateMute == 0 {
				readers = append(readers, reader)
				atrs = append(atrs, states[0].Atr)
			}
		}
	}

	return
}

// FreeMemory is a wrapper around SCardFreeMemory.
//
// This function releases memory that has been returned from the
// resource manager using the scardAutoAllocate
// length designator.
func (c *Context) FreeMemory(
	mem unsafe.Pointer,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("FreeMemory, IN : (context=0x%.8X, mem=%p)", c.ctx, mem)
	defer func() {
		logger.Infof("FreeMemory, OUT: (context=0x%.8X, mem=%p, ret=0x%.8X)", c.ctx, mem, ret)
	}()

	if scardFreeMemoryProc == nil {
		err = fmt.Errorf("scardFreeMemory() not found in pcsc")
		return
	}

	r := scardFreeMemoryProc(
		c.ctx, /* SCARDCONTEXT */
		mem,   /* LPCVOID */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardFreeMemory() returned 0x%.8X [%w]", r, msg)
		return
	}

	return
}

// Cancel is a wrapper around SCardCancel.
//
// This function cancels a specific blocking SCardGetStatusChange() function.
// MUST be called with the same scardContext as SCardGetStatusChange().
func (c *Context) Cancel() (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("Cancel, IN : (context=0x%.8X)", c.ctx)
	defer func() {
		logger.Infof("Cancel, OUT: (context=0x%.8X, ret=0x%.8X)", c.ctx, ret)
	}()

	if scardCancelProc == nil {
		err = fmt.Errorf("scardCancel() not found in pcsc")
		return
	}

	r := scardCancelProc(
		c.ctx, /* SCARDCONTEXT */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardCancel() returned 0x%.8X [%w]", r, msg)
		return
	}

	return
}

// Connect is a wrapper around SCardConnect.
//
// This function establishes a connection to the reader
// specified in readerName.
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
	card.handle = SCardHandle(invalidHandleValue)

	logger.Infof("Connect, IN : (context=0x%.8X, readerName=%s, shareMode=%s, preferredProtocols=%s)",
		c.ctx, readerName, shareMode.String(), preferredProtocols.String())
	defer func() {
		logger.Infof("Connect, OUT: (context=0x%.8X, handle=0x%.8X, protocol=%s, ret=0x%.8X)",
			c.ctx, card.handle, card.activeProtocol.String(), ret)
	}()

	if scardConnectProc == nil {
		err = fmt.Errorf("scardConnect() not found in pcsc")
		return
	}

	r := scardConnectProc(
		c.ctx,              /* SCARDCONTEXT */
		readerName,         /* LPCSTR */
		shareMode,          /* DWORD */
		preferredProtocols, /* DWORD */
		&scardHandle,       /* LPSCARDHANDLE */
		&activeProtocol,    /* LPDWORD */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardConnect() returned 0x%.8X [%w]", r, msg)
		return
	}

	card.handle = scardHandle
	card.activeProtocol = activeProtocol

	return
}

// Reconnect is a wrapper around SCardReconnect.
//
// This function reestablishes a connection to a reader that was previously
// connected to using SCardConnect().
// In a multi application environment, it is possible for an
// application to reset the card in shared mode.
// When this occurs, any other application trying to access
// certain commands will be returned the value SCARD_W_RESET_CARD.
// When this occurs, SCardReconnect() must be called in order to
// acknowledge that the card was reset and allow it to change
// its state accordingly.
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

	logger.Infof("Reconnect, IN : (handle=0x%.8X, shareMode=%s, preferredProtocols=%s, initialization=%s)",
		c.handle, shareMode.String(), preferredProtocols.String(), initialization.String())
	defer func() {
		logger.Infof("Reconnect, OUT: (handle=0x%.8X, protocol=%s, ret=0x%.8X)", c.handle, c.activeProtocol.String(), ret)
	}()

	if scardReconnectProc == nil {
		err = fmt.Errorf("scardReconnect() not found in pcsc")
		return
	}

	r := scardReconnectProc(
		c.handle,           /* SCARDHANDLE */
		shareMode,          /* DWORD */
		preferredProtocols, /* DWORD */
		initialization,     /* DWORD */
		&activeProtocol,    /* LPDWORD */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardReconnect() returned 0x%.8X [%w]", r, msg)
		return
	}

	c.activeProtocol = activeProtocol

	return
}

// Disconnect is a wrapper around SCardDisconnect.
//
// This function terminates a connection made through SCardConnect().
func (c *Card) Disconnect(
	scardDisposition SCardDisposition,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("Disconnect, IN : (handle=0x%.8X, scardDisposition=%s)",
		c.handle, scardDisposition.String())
	defer func() {
		logger.Infof("Disconnect, OUT: (handle=0x%.8X, ret=0x%.8X)", c.handle, ret)
	}()

	if scardDisconnectProc == nil {
		err = fmt.Errorf("scardDisconnect() not found in pcsc")
		return
	}

	r := scardDisconnectProc(
		c.handle,         /* SCARDHANDLE */
		scardDisposition, /* DWORD */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardDisconnect() returned 0x%.8X [%w]", r, msg)
		return
	}

	return
}

// BeginTransaction is a wrapper around SCardBeginTransaction.
//
// This function establishes a temporary exclusive access mode for
// doing a series of commands in a transaction.
// You might want to use this when you are selecting
// a few files and then writing a large file so you
// can make sure that another application will not
// change the current file. If another application
// has a lock on this reader or this application is
// in SCardShareExclusive there will be no action taken.
func (c *Card) BeginTransaction() (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("BeginTransaction, IN : (handle=0x%.8X)", c.handle)
	defer func() {
		logger.Infof("BeginTransaction, OUT: (handle=0x%.8X, ret=0x%.8X)", c.handle, ret)
	}()

	if scardBeginTransactionProc == nil {
		err = fmt.Errorf("scardBeginTransaction() not found in pcsc")
		return
	}

	r := scardBeginTransactionProc(
		c.handle, /* SCARDHANDLE */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardBeginTransaction() returned 0x%.8X [%w]", r, msg)
		return
	}

	return
}

// EndTransaction is a wrapper around SCardEndTransaction.
//
// This function ends a previously begun transaction.
// The calling application must be the
// owner of the previously begun transaction
// or an error will occur.
func (c *Card) EndTransaction(
	scardDisposition SCardDisposition,
) (ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	logger.Infof("EndTransaction, IN : (handle=0x%.8X, scardDisposition=%s)",
		c.handle, scardDisposition.String())
	defer func() {
		logger.Infof("EndTransaction, OUT : (handle=0x%.8X, scardDisposition=%s, ret=0x%.8X)",
			c.handle, scardDisposition.String(), ret)
	}()

	if scardEndTransactionProc == nil {
		err = fmt.Errorf("scardEndTransaction() not found in pcsc")
		return
	}

	r := scardEndTransactionProc(
		c.handle,         /* SCARDHANDLE */
		scardDisposition, /* DWORD */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardEndTransaction() returned 0x%.8X [%w]", r, msg)
		return
	}

	return
}

// Status is a wrapper around SCardStatus.
//
// This function returns the current status of the reader
// connected to by scardHandle.
// Its friendly name will be returned.
//
// N.B: The PCSCLite project defines SCardStatus as returning only one string.
// That being said, and to keep the same definition as on Windows,
// we're returning a string array that'll always include at most one element.
func (c *Card) Status() (cardStatus CardStatus, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var readerNames []string
	var readerState ReaderState
	var scardProtocol SCardProtocol
	var readerNameChars []byte
	var readerNameCharsLen dword
	var readerNameCharsPtr *byte
	var atrBytes []byte
	var atrBytesLen dword
	var atrBytesPtr *byte

	logger.Infof("Status, IN : (handle=0x%.8X)", c.handle)
	defer func() {
		logger.Infof("Status, OUT: (handle=0x%.8X, status=%+v, ret=0x%.8X)", c.handle, cardStatus, ret)
	}()

	if scardStatusProc == nil {
		err = fmt.Errorf("scardStatus() not found in pcsc")
		return
	}

	r := scardStatusProc(
		c.handle,            /* SCARDHANDLE */
		nil,                 /* LPCSTR */
		&readerNameCharsLen, /* LPDWORD */
		&readerState,        /* LPDWORD */
		&scardProtocol,      /* LPDWORD */
		nil,                 /* LPBYTE */
		&atrBytesLen,        /* LPDWORD */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardStatus() returned 0x%.8X [%w]", r, msg)
		return
	}
	if readerNameCharsLen > 0 || atrBytesLen > 0 {
		if readerNameCharsLen > 0 {
			readerNameChars = make([]byte, readerNameCharsLen)
			readerNameCharsPtr = &readerNameChars[0]
		}
		if atrBytesLen > 0 {
			atrBytes = make([]byte, atrBytesLen)
			atrBytesPtr = &atrBytes[0]
		}

		r = scardStatusProc(
			c.handle,            /* SCARDHANDLE */
			readerNameCharsPtr,  /* LPCSTR */
			&readerNameCharsLen, /* LPDWORD */
			&readerState,        /* LPDWORD */
			&scardProtocol,      /* LPDWORD */
			atrBytesPtr,         /* LPBYTE */
			&atrBytesLen,        /* LPDWORD */
		)

		if r != 0 {
			var msg error
			if pcscErr := maybePcscErr(r); pcscErr != nil {
				msg = pcscErr
			}
			ret = uint64(r)
			err = fmt.Errorf("scardStatus() returned 0x%.8X [%w]", r, msg)
			return
		}

		if readerNameCharsLen > 0 && readerNameChars != nil {
			readerNameChars = readerNameChars[:readerNameCharsLen]
			readerNames = multiByteStringToStrings(readerNameChars)

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
// This function sends an APDU to the smart card contained in
// the reader connected to by SCardConnect().
// The card responds from the APDU and stores
// this response in recvBuffer.
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

	logger.Infof("Transmit, IN : (handle=0x%.8X, sendBuffer=%X)", c.handle, sendBuffer)
	defer func() {
		logger.Infof("Transmit, OUT: (handle=0x%.8X, sendBuffer=%X, recvBuffer=%X, ret=0x%.8X)", c.handle, sendBuffer, recvBuffer, ret)
	}()

	if scardTransmitProc == nil {
		err = fmt.Errorf("scardTransmit() not found in pcsc")
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
	r := scardTransmitProc(
		c.handle,               /* SCARDHANDLE */
		ioSendPci,              /* LPCSCARD_IO_REQUEST */
		sendBufferPtr,          /* LPCBYTE */
		dword(len(sendBuffer)), /* DWORD */
		ioRecvPci,              /* LPCSCARD_IO_REQUEST */
		recvBufferPtr,          /* LPBYTE */
		&recvLength,            /* LPDWORD */
	)
	if r == 0x80100008 && recvLength > 0 { // SCARD_E_INSUFFICIENT_BUFFER
		recvBuffer = make([]byte, recvLength)
		recvBufferPtr = &recvBuffer[0]
		r = scardTransmitProc(
			c.handle,               /* SCARDHANDLE */
			ioSendPci,              /* LPCSCARD_IO_REQUEST */
			sendBufferPtr,          /* LPCBYTE */
			dword(len(sendBuffer)), /* DWORD */
			ioRecvPci,              /* LPCSCARD_IO_REQUEST */
			recvBufferPtr,          /* LPBYTE */
			&recvLength,            /* LPDWORD */
		)
	}
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		recvBuffer = nil
		ret = uint64(r)
		err = fmt.Errorf("scardTransmit() returned 0x%.8X [%w]", r, msg)
		return
	}

	if recvLength > 0 && recvBuffer != nil {
		recvBuffer = recvBuffer[:recvLength]
	}

	return
}

// GetAttrib is a wrapper around SCardGetAttrib.
//
// This function gets an attribute from the IFD Handler (reader driver).
func (c *Card) GetAttrib(
	attrId SCardAttr,
) (attrBytes []byte, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var attrBytesLen dword

	logger.Infof("GetAttrib, IN : (handle=0x%.8X, attrId=%v)", c.handle, attrId.String())
	defer func() {
		logger.Infof("GetAttrib, OUT: (handle=0x%.8X, attrId=%v, attrBytes=%X, ret=0x%.8X)", c.handle, attrId.String(), attrBytes, ret)
	}()

	if scardGetAttribProc == nil {
		err = fmt.Errorf("scardGetAttrib() not found in pcsc")
		return
	}

	r := scardGetAttribProc(
		c.handle,      /* SCARDHANDLE */
		attrId,        /* DWORD */
		nil,           /* LPBYTE */
		&attrBytesLen, /* LPDWORD */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardGetAttrib() 1st call returned 0x%.8X [%w]", r, msg)
		return
	}

	if attrBytesLen > 0 {
		attrBytes = make([]byte, attrBytesLen)
		r = scardGetAttribProc(
			c.handle,      /* SCARDHANDLE */
			attrId,        /* DWORD */
			&attrBytes[0], /* LPBYTE */
			&attrBytesLen, /* LPDWORD */
		)
		if r != 0 {
			var msg error
			if pcscErr := maybePcscErr(r); pcscErr != nil {
				msg = pcscErr
			}
			ret = uint64(r)
			err = fmt.Errorf("scardGetAttrib() 2nd call returned 0x%.8X [%w]", r, msg)
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
// This function sets an attribute of the IFD Handler.
// The list of attributes you can set is
// dependent on the IFD Handler you are using.
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

	logger.Infof("SetAttrib, IN : (handle=0x%.8X, attrId=%v, attr=%X)", c.handle, attrId, attr)
	defer func() {
		logger.Infof("SetAttrib, OUT: (handle=0x%.8X, attrId=%v, attr=%X, ret=0x%.8X)", c.handle, attrId, attr, ret)
	}()

	if scardSetAttribProc == nil {
		err = fmt.Errorf("scardSetAttrib() not found in pcsc")
		return
	}

	if len(attr) > 0 {
		attrPtr = &attr[0]
	}

	r := scardSetAttribProc(
		c.handle, /* SCARDHANDLE */
		attrId,   /* DWORD */
		attrPtr,
		dword(len(attr)),
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardSetAttrib() returned 0x%.8X [%w]", r, msg)
		return
	}

	return
}

// ListReaderGroups is a wrapper around SCardListReaderGroups.
//
// This function returns a list of currently available reader groups on the system.
func (c *Context) ListReaderGroups() (groups []string, ret uint64, err error) {
	defer func() {
		if err != nil {
			logger.Error(err)
		}
	}()

	var groupsChars []byte
	var groupsCharsLen dword

	logger.Infof("ListReaderGroups, IN : (context=0x%.8X)", c.ctx)
	defer func() {
		logger.Infof("ListReaderGroups, OUT: (context=0x%.8X, groups=%v, ret=0x%.8X)", c.ctx, groups, ret)
	}()

	if scardListReaderGroupsProc == nil {
		err = fmt.Errorf("scardListReaderGroups() not found in pcsc")
		return
	}

	r := scardListReaderGroupsProc(
		c.ctx,           /* SCARDCONTEXT */
		nil,             /* LPSTR */
		&groupsCharsLen, /* LPDWORD */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardListReaderGroups() 1st call returned 0x%.8X [%w]", r, msg)
		return
	}

	if groupsCharsLen > 0 {
		groupsChars = make([]byte, groupsCharsLen)
		r = scardListReaderGroupsProc(
			c.ctx,           /* SCARDCONTEXT */
			&groupsChars[0], /* LPSTR */
			&groupsCharsLen, /* LPDWORD */
		)
		if r != 0 {
			var msg error
			if pcscErr := maybePcscErr(r); pcscErr != nil {
				msg = pcscErr
			}
			ret = uint64(r)
			err = fmt.Errorf("scardListReaderGroups() 2nd call returned 0x%.8X [%w]", r, msg)
			return
		}

		if groupsCharsLen > 0 {
			groupsChars = groupsChars[:groupsCharsLen]
			groups = multiByteStringToStrings(groupsChars)
		}
	}

	return
}

// Returns a human readable text for the
// given PC/SC error code.
func PcscStringifyError(ret uint64) string {
	return pcscStringifyErrorProc(scardRet(ret))
}
