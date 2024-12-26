//go:build linux
// +build linux

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
	"fmt"
	"unsafe"
)

type hnd int
type dword uint
type scardRet int
type str *byte

//////////////////////////////////////////////////////////////////////////////////////
// pcsclite.h.in
//////////////////////////////////////////////////////////////////////////////////////

const maxBufferSizeExtended dword = (4 + 3 + (1 << 16) + 3 + 2) // Enhanced (64K + APDU + Lc + Le + SW) Tx/Rx Buffer

//////////////////////////////////////////////////////////////////////////////////////
// reader.h
//////////////////////////////////////////////////////////////////////////////////////

const (
	FeatureExecutePACE Feature = 0x20
)

type PcscV2Part10Property dword

// Properties returned by FEATURE_GET_TLV_PROPERTIES
const (
	PcscV2Part10Property_wLcdLayout                PcscV2Part10Property = 1
	PcscV2Part10Property_bEntryValidationCondition PcscV2Part10Property = 2
	PcscV2Part10Property_bTimeOut2                 PcscV2Part10Property = 3
	PcscV2Part10Property_wLcdMaxCharacters         PcscV2Part10Property = 4
	PcscV2Part10Property_wLcdMaxLines              PcscV2Part10Property = 5
	PcscV2Part10Property_bMinPINSize               PcscV2Part10Property = 6
	PcscV2Part10Property_bMaxPINSize               PcscV2Part10Property = 7
	PcscV2Part10Property_sFirmwareID               PcscV2Part10Property = 8
	PcscV2Part10Property_bPPDUSupport              PcscV2Part10Property = 9
	PcscV2Part10Property_dwMaxAPDUDataSize         PcscV2Part10Property = 10
	PcscV2Part10Property_wIdVendor                 PcscV2Part10Property = 11
	PcscV2Part10Property_wIdProduct                PcscV2Part10Property = 12
)

var cmIoctlGetFeatureRequest SCardCtlCode = scardCtlCodeFunc(3400)

//////////////////////////////////////////////////////////////////////////////////////
// ccid_ifdhandler.h
//////////////////////////////////////////////////////////////////////////////////////

type DriverOption dword

const (
	DriverOptionCcidExchangeAuthorized DriverOption = 1
	DriverOptionGempcTwinKeyApdu       DriverOption = 2
	DriverOptionUseBogusFirmware       DriverOption = 4
	DriverOptionDisablePinRetries      DriverOption = (1 << 6)
)

//////////////////////////////////////////////////////////////////////////////////////
// winscard.h
//////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////
// DLL references.
//////////////////////////////////////////////////////////////////////////////////////

type scardGetStatusChange func(
	hContext SCardContext, // in
	dwTimeout dword, // in
	rgReaderStates *scardReaderState, // in, out
	cReaders dword, // in
) dword

type scardControl func(
	hCard SCardHandle, // in
	dwControlCode SCardCtlCode, // in
	pbSendBuffer *byte, // in
	cbSendLength dword, // in
	pbRecvBuffer *byte, // out
	cbRecvLength dword, // in
	lpBytesReturned *dword, // out
) dword

// GetStatusChange is a wrapper around SCardGetStatusChange.
//
// This function blocks execution until the current availability of
// the cards in a specific set of readers changes.
// This function receives a structure or list of structures
// containing reader names. It then blocks waiting for a
// change in state to occur for a maximum blocking time of
// timeout or forever if InfiniteTimeout is used.
// The new event state will be contained in EventState.
// A status change might be a card insertion or removal event,
// a change in ATR, etc.
// EventState also contains a number of events in the upper
// 16 bits (EventState & 0xFFFF0000). This number of events
// is incremented for each card insertion or removal in the
// specified reader. This can be used to detect a card
// removal/insertion between two calls to SCardGetStatusChange()
// To wait for a reader event (reader added or removed) you may
// use the special reader name "\\?PnP?\Notification".
// If a reader event occurs the state of this reader will change
// and the bit SCardStateChanged will be set.
// To cancel the ongoing call, use SCardCancel() with the same
// SCardContext.
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
	var readersNamesLen []int // need to keep the length of the reader name to be able to convert the *byte back to a string

	logger.Infof("GetStatusChange, IN : (context=0x%.8X, timeout=%vms, readerStates=%+v)",
		c.ctx, timeout.Milliseconds(), readerStates)
	defer func() {
		logger.Infof("GetStatusChange, OUT: (context=0x%.8X, readerStates=%+v, ret=0x%.8X)", c.ctx, readerStates, ret)
	}()

	if scardGetStatusChangeProc == nil {
		err = fmt.Errorf("scardGetStatusChange() not found in pcsclite")
		return
	}

	// We need to convert back and forth between
	// SCardReaderState and scardReaderStateInternal.
	if len(readerStates) > 0 {
		internalReaderStates = make([]scardReaderState, len(readerStates))
		readersNamesLen = make([]int, len(readerStates))
		for i, readerState := range readerStates {
			internalReaderStates[i], readersNamesLen[i], err = readerState.toInternal()
			if err != nil {
				return
			}
		}
		internalReaderStatesPtr = (*scardReaderState)(unsafe.Pointer(&internalReaderStates[0]))
	}

	r := scardGetStatusChangeProc(
		c.ctx,                         /* SCARDCONTEXT */
		dword(timeout.Milliseconds()), /* DWORD */
		internalReaderStatesPtr,       /* LPSCARD_READERSTATEW */
		dword(len(readerStates)),      /* DWORD */
	)
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		ret = uint64(r)
		err = fmt.Errorf("scardGetStatusChange() returned 0x%.8X [%w]", r, msg)
		return
	}

	for i, internalReaderState := range internalReaderStates {
		readerStates[i].fromInternal(internalReaderState, readersNamesLen[i])
	}

	return
}

// Control is a wrapper around SCardControl.
//
// This function sends a command directly to the IFD Handler
// (reader driver) to be processed by the reader.
// This is useful for creating client side reader
// drivers for functions like PIN pads, biometrics,
// or other extensions to the normal smart card
// reader that are not normally handled by PC/SC.
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

	logger.Infof("Control, IN : (handle=0x%.8X, controlCode=0x%.8X, inBuffer=%X)", c.handle, scardControlCode, inBuffer)
	defer func() {
		logger.Infof("Control, OUT: (handle=0x%.8X, controlCode=0x%.8X, inBuffer=%X, outBuffer=%X, ret=0x%.8X)", c.handle, scardControlCode, inBuffer, outBuffer, ret)
	}()

	if scardControlProc == nil {
		err = fmt.Errorf("scardControl() not found in pcsclite")
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
	r := scardControlProc(
		c.handle,         /* SCARDHANDLE */
		scardControlCode, /* DWORD */
		inBufferPtr,
		dword(len(inBuffer)),
		outBufferPtr,
		outBufferSize,
		&bytesReturned,
	)
	if r == 0x80100008 && bytesReturned > 0 { // SCARD_E_INSUFFICIENT_BUFFER
		outBuffer = make([]byte, bytesReturned)
		outBufferPtr = &outBuffer[0]
		r = scardControlProc(
			c.handle,         /* SCARDHANDLE */
			scardControlCode, /* DWORD */
			inBufferPtr,
			dword(len(inBuffer)),
			outBufferPtr,
			outBufferSize,
			&bytesReturned,
		)
	}
	if r != 0 {
		var msg error
		if pcscErr := maybePcscErr(r); pcscErr != nil {
			msg = pcscErr
		}
		outBuffer = nil
		ret = uint64(r)
		err = fmt.Errorf("scardControl() returned 0x%.8X [%w]", r, msg)
		return
	}

	if bytesReturned > 0 && outBuffer != nil {
		outBuffer = outBuffer[:bytesReturned]
	}

	return
}
