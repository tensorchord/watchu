package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/phuslu/log"
)

func SetUpLogger(debug bool, logPath string) (io.Closer, error) {
	if logPath == "" {
		if debug {
			log.DefaultLogger = log.Logger{
				Level:  log.DebugLevel,
				Caller: 1,
				Writer: &log.ConsoleWriter{
					ColorOutput:    true,
					QuoteString:    true,
					EndWithMessage: true,
				},
			}
		} else {
			log.DefaultLogger = log.Logger{
				Level:        log.InfoLevel,
				TimeField:    "timestamp",
				TimeLocation: time.UTC,
			}
		}
		return nil, nil
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return nil, fmt.Errorf("create log parent dir for %q: %w", logPath, err)
	}
	level := log.InfoLevel
	if debug {
		level = log.DebugLevel
	}
	writer := &log.AsyncWriter{
		ChannelSize:   4096,
		DiscardOnFull: false,
		Writer: &log.FileWriter{
			Filename:     logPath,
			FileMode:     0o644,
			EnsureFolder: true,
			LocalTime:    false,
		},
	}

	log.DefaultLogger = log.Logger{
		Level:        level,
		Caller:       1,
		TimeField:    "timestamp",
		TimeLocation: time.UTC,
		Writer:       writer,
	}
	return writer, nil
}
