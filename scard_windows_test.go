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
	"crypto/rand"
	"encoding/binary"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// N.B: These tests require there is at least one Yubikey set up.

var (
	verbose    bool
	testLogger Logger

	yubikeyAtr            []byte = []byte{0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40}
	yubikeyAtrStr         string = "3BFD1300008131FE158073C021C057597562694B657940"
	yubikeyAtrMask        []byte = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	yubikeyAtrMaskStr     string = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	yubikeyName           string = "Identity Device (NIST SP 800-73 [PIV])"
	yubikeyReaderName     string = "Yubico YubiKey OTP+FIDO+CCID 0"
	yubikeyCSPName        string = "Microsoft Base Smart Card Crypto Provider"
	yubikeyKSPName        string = "Microsoft Smart Card Key Storage Provider"
	yubikeyCardModuleName string = "C:\\Windows\\System32\\msclmd.dll"
	selectPivAppletAPDU   []byte = []byte{0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00}

	myCustomCardName                string
	myCustomCardPrimaryProviderGuid windows.GUID
	myCustomCardInterfaceGuid       windows.GUID
	myCustomCardAtr                 []byte = []byte{0x3B, 0x02, 0x14, 0x58}
	myCustomCardAtrStr              string = "3B021458"
	myCustomCardAtrMask             []byte = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	myCustomCardAtrMaskStr          string = "FFFFFFFF"
	myCustomCardCSPName             string = "My Custom Card CSP"
	myCustomCardKSPName             string = "My Custom Card KSP"
	myCustomCardModule              string = "MyCustomCardModule.dll"

	myCustomReaderGroupName  string
	myCustomReaderName       string
	myCustomReaderUtf16Name  []uint16
	myCustomReaderDeviceName string
)

func newRandomGUID() (windows.GUID, error) {
	var guid windows.GUID

	// Generate 16 random bytes
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return guid, err
	}

	// Populate GUID fields with random bytes
	guid.Data1 = binary.LittleEndian.Uint32(randomBytes[0:4])
	guid.Data2 = binary.LittleEndian.Uint16(randomBytes[4:6])
	guid.Data3 = binary.LittleEndian.Uint16(randomBytes[6:8])
	copy(guid.Data4[:], randomBytes[8:16])

	// Set the version (4) and variant (10) according to RFC4122
	guid.Data3 = (guid.Data3 & 0x0FFF) | (0x4 << 12)
	guid.Data4[0] = (guid.Data4[0] & 0x3F) | 0x80

	return guid, nil
}

func TestMain(m *testing.M) {
	flag.BoolVar(&verbose, "verbose", false, "Run tests in verbose mode")
	flag.Parse()

	logFilePath := "scard_windows_test.log"
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
	defer Finalize()

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
}

func TestListReaderGroups(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardListReaderGroupsProc)

	noContext := Context{}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["NoContext"] = noContext
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

	noContext := Context{}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["NoContext"] = noContext
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

func TestListCards(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardListCardsProc)

	noContext := Context{}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["NoContext"] = noContext
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	atrs := make([]string, 4)
	atrs[0] = ""
	atrs[1] = yubikeyAtrStr
	atrs[2] = ""
	atrs[3] = yubikeyAtrStr
	testNames := make([]string, 4)
	testNames[0] = "NoAtrNoGuid"
	testNames[1] = "YubikeyATRNoGuid"
	testNames[2] = "NoATRYubikeyGuid"
	testNames[3] = "YubikeyATRAndGuid"

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			for i := 0; i < len(testNames); i++ {
				t.Run(testNames[i], func(t *testing.T) {
					if i >= 2 {
						// Yubikeys do not seem to have Interface GUIDs,
						// so there is no way to test that: we skip those tests.
						t.Skip()
					}
					cards, r, err := testContext.ListCards(atrs[i], nil)
					require.NoError(t, err)
					require.Equal(t, uint64(0), r)
					if len(cards) == 0 {
						t.Fatal("No cards found")
					}
					bFound := false
					for _, card := range cards {
						t.Log(card)
						if card == yubikeyName {
							bFound = true
						}
					}
					if !bFound {
						t.Fatal("Yubikey not found")
					}
				})
			}
		})
	}
}

func TestListInterfaces(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardListInterfacesProc)

	noContext := Context{}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["NoContext"] = noContext
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			// Yubikey does not seem to have an Interface GUID,
			// Which means the SCardListInterfaces call will return nil.
			guidInterfaces, r, err := testContext.ListInterfaces(yubikeyName)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			if len(guidInterfaces) == 0 {
				t.Log("No interface GUIDs found")
			}
			for _, guidInterface := range guidInterfaces {
				t.Log(guidInterface)
			}
		})
	}
}

func TestGetProviderId(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardGetProviderIdProc)

	noContext := Context{}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["NoContext"] = noContext
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			// Yubikey does not seem to have an Interface GUID,
			// Which means the SCardGetProviderId call will return (80100005) SCARD_E_INVALID_TARGET.
			providerName, r, err := testContext.GetProviderId(yubikeyName)
			require.Contains(t, []uint64{0, 0x80100005}, r)
			if r == 0 {
				require.NoError(t, err)
				t.Log(providerName)
			} else {
				t.Log("Card GUID not found")
			}
		})
	}
}

func TestGetCardTypeProviderName(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardGetCardTypeProviderNameProc)

	noContext := Context{}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["NoContext"] = noContext
	tests["UserContext"] = userContext
	tests["SystemContext"] = systemContext

	providerIds := make([]SCardProviderType, 4)
	providerIds[0] = SCardProviderPrimary
	providerIds[1] = SCardProviderCSP
	providerIds[2] = SCardProviderKSP
	providerIds[3] = SCardProviderCardModule
	providerIdsExpectedValues := make([]string, 4)
	providerIdsExpectedValues[0] = "" // No GUID
	providerIdsExpectedValues[1] = yubikeyCSPName
	providerIdsExpectedValues[2] = yubikeyKSPName
	providerIdsExpectedValues[3] = yubikeyCardModuleName
	testNames := make([]string, 4)
	testNames[0] = "GUID"
	testNames[1] = "CSP"
	testNames[2] = "KSP"
	testNames[3] = "CardModule"

	for testName, testContext := range tests {
		t.Run(testName, func(t *testing.T) {
			for i, providerId := range providerIds {
				t.Run(testNames[i], func(t *testing.T) {
					providerName, r, err := testContext.GetCardTypeProviderName(yubikeyName, providerId)
					// Yubikey does not seem to have interface GUID,
					// so SCardGetCardTypeProviderName returns (0x02) ERROR_FILE_NOT_FOUND
					// when called using SCardProviderPrimary.
					if i == 0 {
						require.Contains(t, []uint64{0, 0x02}, r)
						t.Log("Card GUID not found")
					} else {
						require.Equal(t, uint64(0), r)
						require.NoError(t, err)
						t.Log(providerName)
						require.Equal(t, providerIdsExpectedValues[i], providerName)
					}
				})
			}
		})
	}
}

// Since introducing a reader group using a system context requires admin
// privileges, we only test with user context. Also, reader groups
// added to the user context are not visible to the system context
// and vice versa. Finally, in order for a reader group to be
// actually added to the database and visible when listing, a reader must
// be added to that group beforehand.
// As a result, this tests all 6 following functions:
// SCardIntroduceReaderGroup, SCardForgetReaderGroup, SCardIntroduceReader,
// SCardForgetReader, SCardAddReaderToGroup and SCardRemoveReaderFromGroup.
//
// N.B: We cannot test whether SCardIntroduceReader was successful because
// SCardListReaders only lists actual readers that are connected and
// available for use, which is not our case here.
func TestIntroduceForgetReaderGroup(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardListReaderGroupsProc)
	require.NotNil(t, scardIntroduceReaderGroupProc)
	require.NotNil(t, scardForgetReaderGroupProc)
	require.NotNil(t, scardIntroduceReaderProc)
	require.NotNil(t, scardForgetReaderProc)
	require.NotNil(t, scardAddReaderToGroupProc)
	require.NotNil(t, scardRemoveReaderFromGroupProc)

	//////////////////////////////////////
	// User Context Only
	//////////////////////////////////////

	t.Run("UserContext", func(t *testing.T) {
		context, _, _ := NewContext(SCardScopeUser, nil, nil)
		defer context.Release()

		myCustomReaderGroupNameRandom, err := uuid.NewRandom()
		require.NoError(t, err)
		myCustomReaderNameRandom, err := uuid.NewRandom()
		require.NoError(t, err)
		myCustomReaderDeviceNameRandom, err := uuid.NewRandom()
		require.NoError(t, err)

		myCustomReaderGroupName = "MyCustomReaderGroupv1-" + myCustomReaderGroupNameRandom.String()
		myCustomReaderName = "MyCustomReaderv1-" + myCustomReaderNameRandom.String()
		myCustomReaderUtf16Name, err = stringToUtf16(myCustomReaderName)
		myCustomReaderDeviceName = "MyCustomReaderDevicev1-" + myCustomReaderDeviceNameRandom.String()
		require.NoError(t, err)

		r, err := context.IntroduceReaderGroup(
			myCustomReaderGroupName,
		)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		defer context.ForgetReaderGroup(myCustomReaderGroupName)

		r, err = context.IntroduceReader(
			myCustomReaderName,
			myCustomReaderDeviceName,
		)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		defer context.ForgetReader(myCustomReaderName)

		r, err = context.AddReaderToGroup(
			myCustomReaderName,
			myCustomReaderGroupName,
		)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		defer context.RemoveReaderFromGroup(myCustomReaderName, myCustomReaderGroupName)

		groups, r, err := context.ListReaderGroups()
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		if len(groups) == 0 {
			t.Fatal("No reader groups found")
		}
		bFound := false
		for _, group := range groups {
			if group == myCustomReaderGroupName {
				bFound = true
				break
			}
		}
		if !bFound {
			t.Fatal("Custom reader group not added")
		}

		r, err = context.ForgetReaderGroup(
			myCustomReaderGroupName,
		)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)

		groups, r, err = context.ListReaderGroups()
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		if len(groups) != 0 {
			bFound := false
			for _, group := range groups {
				if group == myCustomReaderGroupName {
					bFound = true
					break
				}
			}
			if bFound {
				t.Fatal("Custom reader group not forgotten")
			}
		}
	})
}

func TestIntroduceForgetCardType(t *testing.T) {
	require.NotNil(t, scardIntroduceCardTypeProc)
	require.NotNil(t, scardSetCardTypeProviderNameProc)
	require.NotNil(t, scardForgetCardTypeProc)

	//////////////////////////////////////
	// User Context Only
	//////////////////////////////////////

	t.Run("UserContext", func(t *testing.T) {
		context, _, _ := NewContext(SCardScopeUser, nil, nil)

		myCustomCardNameRandom, err := uuid.NewRandom()
		require.NoError(t, err)
		myCustomCardPrimaryProviderGuid, err = newRandomGUID()
		require.NoError(t, err)
		myCustomCardInterfaceGuid, err = newRandomGUID()
		require.NoError(t, err)

		myCustomCardName = "MyCustomCardv1-" + myCustomCardNameRandom.String()

		r, err := context.IntroduceCardType(
			myCustomCardName,
			&myCustomCardPrimaryProviderGuid,
			[]windows.GUID{myCustomCardInterfaceGuid},
			myCustomCardAtrStr,
			myCustomCardAtrMaskStr)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		defer context.ForgetCardType(myCustomCardName)

		r, err = context.SetCardTypeProviderName(
			myCustomCardName,
			SCardProviderCSP,
			myCustomCardCSPName,
		)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		r, err = context.SetCardTypeProviderName(
			myCustomCardName,
			SCardProviderKSP,
			myCustomCardKSPName,
		)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		r, err = context.SetCardTypeProviderName(
			myCustomCardName,
			SCardProviderCardModule,
			myCustomCardModule,
		)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)

		providerName, r, err := context.GetCardTypeProviderName(myCustomCardName, SCardProviderPrimary)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		require.Equal(t, myCustomCardPrimaryProviderGuid.String(), providerName)

		providerName, r, err = context.GetCardTypeProviderName(myCustomCardName, SCardProviderCSP)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		require.Equal(t, myCustomCardCSPName, providerName)

		providerName, r, err = context.GetCardTypeProviderName(myCustomCardName, SCardProviderKSP)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		require.Equal(t, myCustomCardKSPName, providerName)

		providerName, r, err = context.GetCardTypeProviderName(myCustomCardName, SCardProviderCardModule)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
		require.Equal(t, myCustomCardModule, providerName)

		atrs := make([]string, 4)
		atrs[0] = ""
		atrs[1] = myCustomCardAtrStr
		atrs[2] = ""
		atrs[3] = myCustomCardAtrStr
		guids := make([][]windows.GUID, 4)
		guids[0] = nil
		guids[1] = nil
		guids[2] = []windows.GUID{myCustomCardInterfaceGuid}
		guids[3] = []windows.GUID{myCustomCardInterfaceGuid}
		testNames := make([]string, 4)
		testNames[0] = "NoAtrNoGuid-Introduce"
		testNames[1] = "MyCustomCardATRNoGuid-Introduce"
		testNames[2] = "NoATRMyCustomCardGuid-Introduce"
		testNames[3] = "MyCustomCardATRAndGuid-Introduce"

		for i := 0; i < len(testNames); i++ {
			t.Run(testNames[i], func(t *testing.T) {
				cards, r, err := context.ListCards(atrs[i], guids[i])
				require.NoError(t, err)
				require.Equal(t, uint64(0), r)
				if len(cards) == 0 {
					t.Fatal("No cards found")
				}
				bFound := false
				for _, card := range cards {
					if card == myCustomCardName {
						bFound = true
					}
				}
				if !bFound {
					t.Fatal("Custom card not found")
				}
			})
		}

		r, err = context.ForgetCardType(myCustomCardName)
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)

		testNames[0] = "NoAtrNoGuid-Forget"
		testNames[1] = "MyCustomCardATRNoGuid-Forget"
		testNames[2] = "NoATRMyCustomCardGuid-Forget"
		testNames[3] = "MyCustomCardATRAndGuid-Forget"

		for i := 0; i < len(testNames); i++ {
			t.Run(testNames[i], func(t *testing.T) {
				cards, r, err := context.ListCards(atrs[i], guids[i])
				require.NoError(t, err)
				require.Equal(t, uint64(0), r)
				if len(cards) != 0 {
					bFound := false
					for _, card := range cards {
						if card == myCustomCardName {
							bFound = true
						}
					}
					if bFound {
						t.Fatal("Custom card not forgotten")
					}
				}
			})
		}
	})
}

func TestAccessStartedEvent(t *testing.T) {
	require.NotNil(t, scardAccessStartedEventProc)
	require.NotNil(t, scardReleaseStartedEventProc)

	t.Run("SuccessfulAccessStartedEvent", func(t *testing.T) {
		event, r, err := AccessStartedEvent()
		require.NoError(t, err)
		require.NotEqual(t, event, windows.Handle(invalidHandleValue))
		require.Equal(t, uint64(0), r)

		waitEvent, err := windows.WaitForSingleObject(event, 0)
		require.NoError(t, err)
		if waitEvent == windows.WAIT_OBJECT_0 {
			t.Log("Smart card resource manager is started")
		} else {
			t.Log("Smart card resource manager is not started")
		}

		r, err = ReleaseStartedEvent()
		require.NoError(t, err)
		require.Equal(t, uint64(0), r)
	})
}

func TestLocateCards(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardListReadersProc)
	require.NotNil(t, scardLocateCardsProc)

	noContext := Context{}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["NoContext"] = noContext
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

			r, err = testContext.LocateCards(
				[]string{yubikeyName},
				scardReaderStates,
			)
			if testName == "NoContext" {
				require.Equal(t, uint32(r), uint32(0x06)) // ERROR_INVALID_HANDLE because context is 0
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, uint64(0), r)

				bFoundCardReader := false
				for _, scardReaderState := range scardReaderStates {
					if scardReaderState.EventState&SCardStateAtrmatch == SCardStateAtrmatch {
						t.Logf("Card \"%v\" found in reader \"%v\"", yubikeyName, scardReaderState.Reader)
						bFoundCardReader = true
					}
				}
				if !bFoundCardReader {
					t.Fatalf("Card \"%v\" not found in any reader", yubikeyName)
				}
			}
		})
	}
}

func TestLocateCardsByATR(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardListReadersProc)
	require.NotNil(t, scardLocateCardsByATRProc)

	noContext := Context{}
	userContext, _, _ := NewContext(SCardScopeUser, nil, nil)
	systemContext, _, _ := NewContext(SCardScopeSystem, nil, nil)
	defer userContext.Release()
	defer systemContext.Release()
	tests := make(map[string]Context, 3)
	tests["NoContext"] = noContext
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

			atrMasks := make([]SCardAtrMask, 1)
			atrMasks[0].Atr = yubikeyAtrStr
			atrMasks[0].Mask = yubikeyAtrMaskStr
			r, err = testContext.LocateCardsByATR(
				atrMasks,
				scardReaderStates,
			)
			if testName == "NoContext" {
				require.Equal(t, uint32(r), uint32(0x06)) // ERROR_INVALID_HANDLE because context is 0
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, uint64(0), r)

				bFoundCardReader := false
				for _, scardReaderState := range scardReaderStates {
					if scardReaderState.EventState&SCardStateAtrmatch == SCardStateAtrmatch {
						t.Logf("Card \"%v\" found in reader \"%v\"", yubikeyName, scardReaderState.Reader)
						bFoundCardReader = true
					}
				}
				if !bFoundCardReader {
					t.Fatalf("Card \"%v\" not found in any reader", yubikeyName)
				}
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
	require.NotNil(t, scardGetTransmitCountProc)
	require.NotNil(t, SCardIoRequestT1)

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

			transmitCount, r, err := scard.GetTransmitCount()
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)

			t.Logf("Transmit count: %d", transmitCount)
		})
	}
}

func TestControl(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardConnectProc)
	require.NotNil(t, scardDisconnectProc)
	require.NotNil(t, scardControlProc)

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
				IoctlSmartCardTransmit,
				ctlTransmitData)
			require.NoError(t, err)
			require.Equal(t, uint64(0), r)
			require.NotNil(t, recvBuffer)
			require.Equal(t, []byte{0x90, 0x00}, recvBuffer[len(recvBuffer)-2:])

			t.Logf("Control Transmit Select PIV Applet returned: %X", recvBuffer)
		})
	}
}

func TestGetAttrib(t *testing.T) {
	require.NotNil(t, scardEstablishContextProc)
	require.NotNil(t, scardReleaseContextProc)
	require.NotNil(t, scardConnectProc)
	require.NotNil(t, scardDisconnectProc)
	require.NotNil(t, scardGetAttribProc)

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

// TODO:
// SCardAudit
// SCardListReadersWithDeviceInstanceId
// SCardGetReaderDeviceInstanceId
// SCardGetDeviceTypeId
// SCardGetReaderIcon
// SCardWriteCache
// SCardReadCache
