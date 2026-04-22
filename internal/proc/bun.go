package proc

import (
	"bytes"
	debugelf "debug/elf"
	"encoding/binary"
	"io"
	"os"
)

const bunFooterNumSize = 8

var (
	bunSentinel     = []byte("\n---- Bun! ----\n")
	bunSentinelSize = len(bunSentinel)
	bunFooterSize   = bunFooterNumSize + bunSentinelSize
)

type bunStandaloneOffsets struct {
	ByteCount          uint64
	ModulesPtrData     uint64
	ModulesPtrLen      uint64
	EntryPointID       uint32
	CompileArgvPtrData uint64
	CompileArgvPtrLen  uint64
	Flags              uint32
}

func isBunBundlePackage(path string) (bool, error) {
	if ok, err := isBunBundleELF(path); err != nil {
		return false, err
	} else if ok {
		return true, nil
	}
	return isBunBundleLegacyFooter(path)
}

// changed to this since the following commit:
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

	return isBunBundleSection(section.Open(), section.Size)
}

func isBunBundleSection(r io.ReadSeeker, sectionSize uint64) (bool, error) {
	minPayloadLen := uint64(binary.Size(bunStandaloneOffsets{})) + uint64(bunSentinelSize)
	if sectionSize < bunFooterNumSize+minPayloadLen {
		return false, nil
	}

	var payloadLenBuf [bunFooterNumSize]byte
	if _, err := io.ReadFull(r, payloadLenBuf[:]); err != nil {
		return false, err
	}
	payloadLen := binary.LittleEndian.Uint64(payloadLenBuf[:])
	if payloadLen < minPayloadLen || payloadLen > sectionSize-bunFooterNumSize {
		return false, nil
	}

	footerOffset := int64(bunFooterNumSize + payloadLen - uint64(bunSentinelSize))
	if _, err := r.Seek(footerOffset, io.SeekStart); err != nil {
		return false, err
	}

	footer := make([]byte, bunSentinelSize)
	if _, err := io.ReadFull(r, footer); err != nil {
		return false, err
	}

	return bytes.Equal(bunSentinel, footer), nil
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
