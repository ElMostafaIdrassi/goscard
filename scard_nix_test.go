//go:build linux || darwin
// +build linux darwin

// Copyright (c) 2023-2024, El Mostafa IDRASSI.
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
	"flag"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// N.B: These tests require there is at least one Yubikey set up.

var (
	verbose    bool
	testLogger Logger

	yubikeyAtr    []byte = []byte{0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40}
	yubikeyAtrStr string = "3BFD1300008131FE158073C021C057597562694B657940"
	// On Linux, the yubikey reader name is "Yubico YubiKey OTP+FIDO+CCID 00 00",
	// while it is just "Yubico YubiKey OTP+FIDO+CCID" on MacOSX.
	yubikeyReaderNameLinux  string = "Yubico YubiKey OTP+FIDO+CCID 00 00"
	yubikeyReaderNameMacOSX string = "Yubico YubiKey OTP+FIDO+CCID"
	selectPivAppletAPDU     []byte = []byte{0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00}
)

func TestMain(m *testing.M) {
	flag.BoolVar(&verbose, "verbose", false, "Run tests in verbose mode")
	flag.Parse()

	logFilePath := "scard_nix_test.log"
	logFile, err := os.OpenFile(logFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		testLogger = NewDefaultStdoutLogger(LogLevelError)
		testLogger.Errorf("Log file creation failed: %v", err)
		os.Exit(1)
	}

	if verbose {
		testLogger = NewDefaultFileLogger(LogLevelDebug, logFile)
	} else {
		testLogger = NewDefaultFileLogger(LogLevelNone, logFile)
	}

	err = Initialize(testLogger)
	if err != nil {
		testLogger.Errorf("Initialize failed: %v", err)
		os.Exit(1)
	}

	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestEstablishValidContext(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardIsValidContextProc)
	require.NotNil(t, scardReleaseContextProc)

	t.Run("UserContext", func(t *testing.T) {
		context, r, err := NewContext(SCardScopeUser, nil, nil)
		require.NoError(t, err)
		require.NotEqual(t, context.SCardContext(), SCardContext(invalidHandleValue))
		require.Equal(t, uint64(0), r)
		defer context.Release()

		scardContextValid, r, err := context.IsValid()
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		require.True(t, scardContextValid)
	})

	t.Run("TerminalContext", func(t *testing.T) {
		context, r, err := NewContext(SCardScopeTerminal, nil, nil)
		require.NoError(t, err)
		require.NotEqual(t, context.SCardContext(), SCardContext(invalidHandleValue))
		require.Equal(t, uint64(0), r)
		defer context.Release()

		scardContextValid, r, err := context.IsValid()
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		require.True(t, scardContextValid)
	})

	t.Run("SystemContext", func(t *testing.T) {
		context, r, err := NewContext(SCardScopeSystem, nil, nil)
		require.NoError(t, err)
		require.NotEqual(t, context.SCardContext(), SCardContext(invalidHandleValue))
		require.Equal(t, uint64(0), r)
		defer context.Release()

		scardContextValid, r, err := context.IsValid()
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		require.True(t, scardContextValid)
	})

	t.Run("GlobalContext", func(t *testing.T) {
		context, r, err := NewContext(SCardScopeGlobal, nil, nil)
		require.NoError(t, err)
		require.NotEqual(t, context.SCardContext(), SCardContext(invalidHandleValue))
		require.Equal(t, uint64(0), r)
		defer context.Release()

		scardContextValid, r, err := context.IsValid()
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		require.True(t, scardContextValid)
	})
}

func TestListReaderGroups(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardListReaderGroupsProc)

	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			groups, r, err := testContext.ListReaderGroups()
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			if len(groups) == 0 {
				t.Fatal("No reader groups found")
			}
			for _, group := range groups {
				t.Log(group)
			}
		})
	}
}

func TestListReaders(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardListReadersProc)

	yubikeyReaderName := yubikeyReaderNameLinux
	if runtime.GOOS == "darwin" {
		yubikeyReaderName = yubikeyReaderNameMacOSX
	}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	// We don't use SCardLocalReaders and SCardSystemReaders groups,
	// as those are legacy special groups that do not contain our reader.
	readerGroupsArray := make([][]string, 4)
	readerGroupsArray[0] = nil
	readerGroupsArray[1] = []string{SCardAllReaders}
	readerGroupsArray[2] = []string{SCardDefaultReaders}
	readerGroupsArray[3] = []string{SCardAllReaders, SCardDefaultReaders}
	testNames := make([]string, 4)
	testNames[0] = "NoGroups"
	testNames[1] = "AllReadersGroup"
	testNames[2] = "DefaultReadersGroup"
	testNames[3] = "AllReadersGroup+DefaultReadersGroup"

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			for i, readerGroups := range readerGroupsArray {
				t.Run(testNames[i], func(t *testing.T) {
					readers, r, err := testContext.ListReaders(readerGroups)
					require.Equal(t, uint64(0), r)
					require.NoError(t, err)
					if len(readers) == 0 {
						t.Fatal("No readers found")
					}
					bFound := false
					for _, reader := range readers {
						t.Log(reader)
						if reader == yubikeyReaderName {
							bFound = true
						}
					}
					if !bFound {
						t.Fatal("Yubikey reader not found")
					}
				})
			}
		})
	}
}

func TestListReadersWithCardPresent(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardListReadersProc)

	yubikeyReaderName := yubikeyReaderNameLinux
	if runtime.GOOS == "darwin" {
		yubikeyReaderName = yubikeyReaderNameMacOSX
	}

	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 2)
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	// We don't use SCardLocalReaders and SCardSystemReaders groups,
	// as those are legacy special groups that do not contain our reader.
	readerGroupsArray := make([][]string, 4)
	readerGroupsArray[0] = nil
	readerGroupsArray[1] = []string{SCardAllReaders}
	readerGroupsArray[2] = []string{SCardDefaultReaders}
	readerGroupsArray[3] = []string{SCardAllReaders, SCardDefaultReaders}
	testNames := make([]string, 4)
	testNames[0] = "NoGroups"
	testNames[1] = "AllReadersGroup"
	testNames[2] = "DefaultReadersGroup"
	testNames[3] = "AllReadersGroup+DefaultReadersGroup"

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			for i, readerGroups := range readerGroupsArray {
				t.Run(testNames[i], func(t *testing.T) {
					readers, atrs, r, err := testContext.ListReadersWithCardPresent(readerGroups)
					require.Equal(t, uint64(0), r)
					require.NoError(t, err)
					if len(readers) == 0 {
						t.Fatal("No readers found")
					}
					bFound := false
					for i, reader := range readers {
						t.Log(reader)
						if reader == yubikeyReaderName && strings.EqualFold(atrs[i], yubikeyAtrStr) {
							bFound = true
						}
					}
					if !bFound {
						t.Fatal("Yubikey reader not found")
					}
				})
			}
		})
	}
}

func TestGetStatusChange(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardListReadersProc)
	require.NotNil(t, scardGetStatusChangeProc)

	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			readers, r, err := testContext.ListReaders(nil)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			if len(readers) == 0 {
				t.Fatal("No readers found")
			}
			scardReaderStates := make([]SCardReaderState, len(readers))
			for i, reader := range readers {
				scardReaderStates[i] = SCardReaderState{
					Reader: reader,
				}
			}

			r, err = testContext.GetStatusChange(
				NewTimeout(0),
				scardReaderStates,
			)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)

			for _, scardReaderState := range scardReaderStates {
				reader := scardReaderState.Reader
				t.Logf("Reader \"%v\" state: %v", reader, scardReaderState.EventState.String())
			}
		})
	}
}

func TestConnectReconnectDisconnect(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardConnectProc)
	require.NotNil(t, scardDisconnectProc)
	require.NotNil(t, scardReconnectProc)

	yubikeyReaderName := yubikeyReaderNameLinux
	if runtime.GOOS == "darwin" {
		yubikeyReaderName = yubikeyReaderNameMacOSX
	}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			scard, r, err := testContext.Connect(
				yubikeyReaderName,
				SCardShareShared,
				SCardProtocolT0|SCardProtocolT1,
			)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			require.Equal(t, SCardProtocolT1, scard.ActiveProtocol())
			defer scard.Disconnect(SCardLeaveCard)

			t.Logf("Card in reader \"%v\" connected with active protocol \"%v\"", yubikeyReaderName, scard.ActiveProtocol().String())

			r, err = scard.Reconnect(
				SCardShareShared,
				SCardProtocolT1,
				SCardResetCard,
			)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			require.Equal(t, SCardProtocolT1, scard.ActiveProtocol())

			t.Logf("Card in reader \"%v\" reconnected with active protocol \"%v\"", yubikeyReaderName, scard.ActiveProtocol().String())
		})
	}
}

func TestStatus(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardConnectProc)
	require.NotNil(t, scardDisconnectProc)
	require.NotNil(t, scardStatusProc)

	yubikeyReaderName := yubikeyReaderNameLinux
	if runtime.GOOS == "darwin" {
		yubikeyReaderName = yubikeyReaderNameMacOSX
	}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			scard, r, err := testContext.Connect(
				yubikeyReaderName,
				SCardShareShared,
				SCardProtocolT0|SCardProtocolT1,
			)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			require.Equal(t, SCardProtocolT1, scard.ActiveProtocol())
			defer scard.Disconnect(SCardLeaveCard)

			cardStatus, r, err := scard.Status()
			require.NoError(t, err)
			require.NotNil(t, cardStatus.ReaderNames)
			require.Equal(t, uint64(0), r)
			require.Equal(t, SCardProtocolT1, cardStatus.ActiveProtocol)
			require.Equal(t, strings.ToLower(yubikeyAtrStr), strings.ToLower(cardStatus.Atr))
			require.Equal(t, yubikeyReaderName, cardStatus.ReaderNames[0])

			t.Logf("Card in reader \"%v\" connected with state \"%v\" (ATR=%s)", yubikeyReaderName, cardStatus.State.String(), cardStatus.Atr)
		})
	}
}

func TestTransmit(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardConnectProc)
	require.NotNil(t, scardDisconnectProc)
	require.NotNil(t, scardBeginTransactionProc)
	require.NotNil(t, scardEndTransactionProc)
	require.NotNil(t, scardTransmitProc)
	require.NotNil(t, SCardIoRequestT1)

	yubikeyReaderName := yubikeyReaderNameLinux
	if runtime.GOOS == "darwin" {
		yubikeyReaderName = yubikeyReaderNameMacOSX
	}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			scard, r, err := testContext.Connect(
				yubikeyReaderName,
				SCardShareShared,
				SCardProtocolT0|SCardProtocolT1,
			)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			require.Equal(t, SCardProtocolT1, scard.ActiveProtocol())
			defer scard.Disconnect(SCardLeaveCard)

			r, err = scard.BeginTransaction()
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			defer scard.EndTransaction(SCardLeaveCard)

			var ioSendPci SCardIORequest = SCardIoRequestT1
			recvBuffer, r, err := scard.Transmit(
				&ioSendPci,
				selectPivAppletAPDU,
				nil,
			)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			require.NotNil(t, recvBuffer)
			t.Logf("Select PIV Applet returned: %X", recvBuffer)
			require.Equal(t, []byte{0x90, 0x00}, recvBuffer[len(recvBuffer)-2:])
		})
	}
}

func TestControl(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardConnectProc)
	require.NotNil(t, scardDisconnectProc)
	require.NotNil(t, scardControlProc)

	yubikeyReaderName := yubikeyReaderNameLinux
	if runtime.GOOS == "darwin" {
		yubikeyReaderName = yubikeyReaderNameMacOSX
	}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			scard, r, err := testContext.Connect(
				yubikeyReaderName,
				SCardShareShared,
				SCardProtocolT0|SCardProtocolT1,
			)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			require.Equal(t, SCardProtocolT1, scard.ActiveProtocol())
			defer scard.Disconnect(SCardLeaveCard)

			r, err = scard.BeginTransaction()
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			defer scard.EndTransaction(SCardLeaveCard)

			var ioSendPci SCardIORequest = SCardIoRequestT1
			var ioSendPciByteBuffer bytes.Buffer
			var ctlTransmitData []byte
			binary.Write(&ioSendPciByteBuffer, binary.LittleEndian, ioSendPci.Protocol)
			binary.Write(&ioSendPciByteBuffer, binary.LittleEndian, ioSendPci.PciLength)
			ctlTransmitData = append(ctlTransmitData, ioSendPciByteBuffer.Bytes()...)
			ctlTransmitData = append(ctlTransmitData, selectPivAppletAPDU...)
			recvBuffer, r, err := scard.Control(
				IoctlFeatureGetTlvProperties,
				ctlTransmitData)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			require.NotNil(t, recvBuffer)

			t.Logf("Control returned: %X", recvBuffer)
		})
	}
}

func TestGetAttrib(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardConnectProc)
	require.NotNil(t, scardDisconnectProc)
	require.NotNil(t, scardGetAttribProc)

	yubikeyReaderName := yubikeyReaderNameLinux
	if runtime.GOOS == "darwin" {
		yubikeyReaderName = yubikeyReaderNameMacOSX
	}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			scard, r, err := testContext.Connect(
				yubikeyReaderName,
				SCardShareShared,
				SCardProtocolT0|SCardProtocolT1,
			)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			require.Equal(t, SCardProtocolT1, scard.ActiveProtocol())
			defer scard.Disconnect(SCardLeaveCard)

			r, err = scard.BeginTransaction()
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			defer scard.EndTransaction(SCardLeaveCard)

			recvBuffer, r, err := scard.GetAttrib(
				SCardAttrATRString)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			require.NotNil(t, recvBuffer)
			require.Equal(t, yubikeyAtr, recvBuffer)
		})
	}
}

func TestPcscStringifyError(t *testing.T) {
	require.NotNil(t, pcscStringifyErrorProc)

	t.Run("InvalidHandle", func(t *testing.T) {
		ret := uint64(0x80100003)

		retStr := PcscStringifyError(ret)
		require.Equal(t, "Invalid handle.", retStr)
	})
}
