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

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/ElMostafaIdrassi/goscard"
)

func main() {
	var chosenReaderIndex int
	var chosenReader string
	var ioSendPci goscard.SCardIORequest
	var selectPivAppletAPDU []byte = []byte{0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00}

	logFilePath := "pcsc_example.log"
	logFile, err := os.OpenFile(logFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Printf("\nERROR: Log file creation failed (err=%v)\n", err)
		os.Exit(1)
	}

	err = goscard.Initialize(goscard.NewDefaultFileLogger(goscard.LogLevelDebug, logFile))
	if err != nil {
		fmt.Printf("\nERROR: Initialize failed (err=%v)\n", err)
		os.Exit(1)
	}
	defer goscard.Finalize()

	fmt.Printf("- NewContext(SYSTEM)...")
	context, r, err := goscard.NewContext(goscard.SCardScopeSystem, nil, nil)
	if err != nil {
		fmt.Printf("\nERROR: NewContext failed (ret=0x%.8X) (err=%v)\n", r, err)
		os.Exit(1)
	}
	defer context.Release()
	fmt.Printf("OK\n")

	fmt.Printf("- ListReaders()...")
	readers, r, err := context.ListReaders(nil)
	if err != nil {
		fmt.Printf("\nERROR: ListReaders failed (ret=0x%.8X) (err=%v)\n", r, err)
		os.Exit(1)
	}
	if len(readers) == 0 {
		fmt.Printf("\nNo readers found\n")
		return
	}
	fmt.Printf("OK\n")
	fmt.Printf("Found the following readers:\n")
	for i, reader := range readers {
		fmt.Printf("%d- %s\n", i+1, reader)
	}
	fmt.Printf("\n")

	fmt.Printf("- Enter the index of the reader to connect to: ")
	_, err = fmt.Scanf("%d", &chosenReaderIndex)
	if err != nil {
		log.Fatalf("\nERROR: %v\n", err)
	}
	fmt.Printf("\n")
	if chosenReaderIndex <= 0 || chosenReaderIndex > len(readers) {
		fmt.Printf("\nERROR: Index out of range\n")
		os.Exit(1)
	}
	chosenReader = readers[chosenReaderIndex-1]
	fmt.Printf("Using reader \"%s\"\n", chosenReader)

	fmt.Printf("- Connect()...")
	card, r, err := context.Connect(
		chosenReader,
		goscard.SCardShareShared,
		goscard.SCardProtocolT0|goscard.SCardProtocolT1,
	)
	if err != nil {
		fmt.Printf("\nERROR: Connect failed (ret=0x%.8X) (err=%v)\n", r, err)
		os.Exit(1)
	}
	defer card.Disconnect(goscard.SCardLeaveCard)
	fmt.Printf("OK\n")
	fmt.Printf("--- Active Protocol: %v\n", card.ActiveProtocol())

	fmt.Printf("- Status()...")
	status, r, err := card.Status()
	if err != nil {
		fmt.Printf("\nERROR: Status failed (ret=0x%.8X) (err=%v)\n", r, err)
		os.Exit(1)
	}
	fmt.Printf("OK\n")
	fmt.Printf("--- Reader Names   : \n")
	for _, readerName := range status.ReaderNames {
		fmt.Printf("     * %s\n", readerName)
	}
	fmt.Printf("--- Reader State   : 0x%.8X (%s)\n", status.State, status.State.String())
	fmt.Printf("--- Protocol       : %d (%s)\n", status.ActiveProtocol, status.ActiveProtocol.String())
	fmt.Printf("--- ATR            : %s\n", status.Atr)

	if status.ActiveProtocol == goscard.SCardProtocolT0 {
		ioSendPci = goscard.SCardIoRequestT0
	} else if status.ActiveProtocol == goscard.SCardProtocolT1 {
		ioSendPci = goscard.SCardIoRequestT1
	} else if status.ActiveProtocol == goscard.SCardProtocolRaw {
		ioSendPci = goscard.SCardIoRequestRaw
	} else {
		fmt.Printf("\nERROR: Unknown protocol %d\n", status.ActiveProtocol)
		os.Exit(1)
	}

	fmt.Printf("- BeginTransaction()...")
	r, err = card.BeginTransaction()
	if err != nil {
		fmt.Printf("\nERROR: BeginTransaction failed (ret=0x%.8X) (err=%v)\n", r, err)
		os.Exit(1)
	}
	fmt.Printf("OK\n")
	defer card.EndTransaction(goscard.SCardLeaveCard)

	fmt.Printf("- Transmit(SELECT_PIV_APPLET)...")
	recvBuffer, r, err := card.Transmit(&ioSendPci, selectPivAppletAPDU, nil)
	if err != nil {
		fmt.Printf("\nERROR: Transmit failed (ret=0x%.8X) (err=%v)\n", r, err)
		os.Exit(1)
	}
	fmt.Printf("OK\n")
	fmt.Printf("--- Response       : %X\n", recvBuffer)

	fmt.Printf("- GetStatusChange()...")
	scardReaderStates := make([]goscard.SCardReaderState, len(readers))
	for i, reader := range readers {
		scardReaderStates[i] = goscard.SCardReaderState{
			Reader: reader,
		}
	}
	r, err = context.GetStatusChange(goscard.NewTimeout(0), scardReaderStates)
	if err != nil {
		fmt.Printf("\nERROR: GetStatusChange failed (ret=0x%.8X) (err=%v)\n", r, err)
		os.Exit(1)
	}
	fmt.Printf("OK\n")
	for _, scardReaderState := range scardReaderStates {
		fmt.Printf("-- Reader \"%s\"\n", scardReaderState.Reader)
		fmt.Printf("---- Current State: 0x%.8X (%s)\n", scardReaderState.CurrentState, scardReaderState.CurrentState.String())
		fmt.Printf("---- Event State  : 0x%.8X (%s)\n", scardReaderState.EventState, scardReaderState.EventState.String())
	}
}
