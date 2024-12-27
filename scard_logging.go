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
	"fmt"
	"log"
	"os"
)

var logger Logger = NewDefaultStdoutLogger(LogLevelInfo)

type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelNone
)

type Logger interface {
	Debugf(format string, v ...interface{})
	Debug(v ...interface{})
	Debugln(v ...interface{})
	Infof(format string, v ...interface{})
	Info(v ...interface{})
	Infoln(v ...interface{})
	Warnf(format string, v ...interface{})
	Warn(v ...interface{})
	Warnln(v ...interface{})
	Errorf(format string, v ...interface{})
	Error(v ...interface{})
	Errorln(v ...interface{})
}

type defaultLogger struct {
	*log.Logger
	Level LogLevel
}

func NewDefaultStdoutLogger(level LogLevel) Logger {
	return &defaultLogger{
		Logger: log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds|log.LUTC),
		Level:  level,
	}
}

func NewDefaultFileLogger(level LogLevel, file *os.File) Logger {
	return &defaultLogger{
		Logger: log.New(file, "", log.LstdFlags|log.Lmicroseconds|log.LUTC),
		Level:  level,
	}
}

func NewDefaultLogger(level LogLevel) Logger {
	return NewDefaultStdoutLogger(level)
}

func (l *defaultLogger) Debugf(format string, v ...interface{}) {
	if l.Logger != nil && l.Level <= LogLevelDebug {
		l.Logger.Printf("[DEBU] %s\n", fmt.Sprintf(format, v...))
	}
}

func (l *defaultLogger) Debug(v ...interface{}) {
	if l.Logger != nil && l.Level <= LogLevelDebug {
		l.Logger.Print(append([]interface{}{"[DEBU] "}, v...)...)
	}
}

func (l *defaultLogger) Debugln(v ...interface{}) {
	if l.Logger != nil && l.Level <= LogLevelDebug {
		l.Logger.Println(append([]interface{}{"[DEBU] "}, v...)...)
	}
}

func (l *defaultLogger) Infof(format string, v ...interface{}) {
	if l.Logger != nil && l.Level <= LogLevelInfo {
		l.Logger.Printf("[INFO] %s\n", fmt.Sprintf(format, v...))
	}
}

func (l *defaultLogger) Info(v ...interface{}) {
	if l.Logger != nil && l.Level <= LogLevelInfo {
		l.Logger.Print(append([]interface{}{"[INFO] "}, v...)...)
	}
}

func (l *defaultLogger) Infoln(v ...interface{}) {
	if l.Logger != nil && l.Level <= LogLevelInfo {
		l.Logger.Println(append([]interface{}{"[INFO] "}, v...)...)
	}
}

func (l *defaultLogger) Warnf(format string, v ...interface{}) {
	if l.Level <= LogLevelWarn {
		l.Logger.Printf("[WARN] %s\n", fmt.Sprintf(format, v...))
	}
}

func (l *defaultLogger) Warn(v ...interface{}) {
	if l.Logger != nil && l.Level <= LogLevelWarn {
		l.Logger.Print(append([]interface{}{"[WARN] "}, v...)...)
	}
}

func (l *defaultLogger) Warnln(v ...interface{}) {
	if l.Logger != nil && l.Level <= LogLevelWarn {
		l.Logger.Println(append([]interface{}{"[WARN] "}, v...)...)
	}
}

func (l *defaultLogger) Errorf(format string, v ...interface{}) {
	if l.Level <= LogLevelError {
		l.Logger.Printf("[ERRO] %s\n", fmt.Sprintf(format, v...))
	}
}

func (l *defaultLogger) Error(v ...interface{}) {
	if l.Logger != nil && l.Level <= LogLevelError {
		l.Logger.Print(append([]interface{}{"[ERRO] "}, v...)...)
	}
}

func (l *defaultLogger) Errorln(v ...interface{}) {
	if l.Logger != nil && l.Level <= LogLevelError {
		l.Logger.Println(append([]interface{}{"[ERRO] "}, v...)...)
	}
}
