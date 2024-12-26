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
	"time"
)

// Context is a wrapper around a SCardContext.
type Context struct {
	ctx SCardContext
}

// SCardContext returns the underlying SCardContext.
func (c *Context) SCardContext() SCardContext {
	return c.ctx
}

// Card is a wrapper around a SCardHandle and
// its SCardProtocol.
type Card struct {
	handle         SCardHandle
	activeProtocol SCardProtocol
}

// SCardHandle returns the underlying SCardContext.
func (c *Card) SCardHandle() SCardHandle {
	return c.handle
}

// ActiveProtocol returns the underlying protocol.
func (c *Card) ActiveProtocol() SCardProtocol {
	return c.activeProtocol
}

// CardStatus is a wrapper around the information
// that SCardStatus returns.
type CardStatus struct {
	ReaderNames    []string
	State          ReaderState
	ActiveProtocol SCardProtocol
	Atr            string
}

// Timeout represents the timeout to be used
// with SCard related function.
type Timeout struct {
	timeout dword
}

// NewTimeout creates a new Timeout from
// the passed time.Duration.
//
// If the passed duration is negative,
// the function returns a null timeout.
// If the passed duration exceeds InfiniteTimeout,
// the functions returns InfiniteTimeout.
func NewTimeout(timeout time.Duration) Timeout {
	if timeout < 0 {
		return Timeout{timeout: 0}
	} else if timeout > time.Duration(infiniteTimeout)*time.Millisecond {
		return Timeout{timeout: infiniteTimeout}
	} else {
		return Timeout{timeout: dword(timeout.Milliseconds())}
	}
}

// NewInfiniteTimeout creates a new Timeout
// with the InifiniteTimeout duration.
func NewInfiniteTimeout() Timeout {
	return Timeout{timeout: infiniteTimeout}
}

// Milliseconds returns the timeout duration
// as an integer millisecond count.
func (t *Timeout) Milliseconds() dword {
	return t.timeout
}
