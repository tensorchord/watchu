package proc

import (
	"bytes"
	"os"
)

const bunFooterNumSize = 8

var (
	bunSentinel     = []byte("\n---- Bun! ----\n")
	bunSentinelSize = int64(len(bunSentinel))
	bunFooterSize   = bunFooterNumSize + bunSentinelSize
)

func isBunBundlePackage(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	stats, err := file.Stat()
	if err != nil {
		return false, err
	}
	if stats.Size() < bunFooterSize {
		return false, nil
	}
	footerStart := stats.Size() - bunFooterSize
	buffer := make([]byte, bunSentinelSize)
	if _, err := file.ReadAt(buffer, footerStart); err != nil {
		return false, err
	}

	if bytes.Equal(bunSentinel, buffer) {
		return true, nil
	}
	return false, nil
}
