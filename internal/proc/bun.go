package proc

import (
	"bytes"
	debugelf "debug/elf"
	"encoding/binary"
	"os"
)

const bunFooterNumSize = 8

var (
	bunSentinel     = []byte("\n---- Bun! ----\n")
	bunSentinelSize = len(bunSentinel)
	bunFooterSize   = bunFooterNumSize + bunSentinelSize
)

func isBunBundlePackage(path string) (bool, error) {
	ok, err := isBunBundleELF(path)
	if err == nil {
		return ok, nil
	}

	return isBunBundleLegacyFooter(path)
}

// changed to this since the following comit:
// https://github.com/oven-sh/bun/commit/66f7c41412e8a41c9686b0f4524b778a5f69b40e
func isBunBundleELF(path string) (bool, error) {
	file, err := debugelf.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	section := file.Section(".bun")
	if section == nil {
		return false, nil
	}

	data, err := section.Data()
	if err != nil {
		return false, err
	}
	return isBunBundlePayload(data), nil
}

func isBunBundlePayload(data []byte) bool {
	if len(data) < bunFooterNumSize {
		return false
	}

	payloadLen := binary.LittleEndian.Uint64(data[:bunFooterNumSize])
	if payloadLen < uint64(bunFooterSize) || payloadLen > uint64(len(data)-bunFooterNumSize) {
		return false
	}

	payload := data[bunFooterNumSize : bunFooterNumSize+int(payloadLen)]
	footerStart := len(payload) - bunFooterSize
	return bytes.Equal(bunSentinel, payload[footerStart:footerStart+bunSentinelSize])
}

func isBunBundleLegacyFooter(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	stats, err := file.Stat()
	if err != nil {
		return false, err
	}
	if stats.Size() < int64(bunFooterSize) {
		return false, nil
	}
	footerStart := stats.Size() - int64(bunFooterSize)
	buffer := make([]byte, bunSentinelSize)
	if _, err := file.ReadAt(buffer, footerStart); err != nil {
		return false, err
	}

	return bytes.Equal(bunSentinel, buffer), nil
}
