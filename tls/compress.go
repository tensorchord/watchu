package tls

import (
	"io"
	"strings"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/internal/tool"
)

const (
	EncodingGZip    = "gzip"
	EncodingDeflate = "deflate"
	EncodingZstd    = "zstd"
)

func readDecodeBytes(body io.ReadCloser, encoding string) ([]byte, error) {
	encodings := parseEncodings(encoding)
	if len(encodings) == 0 {
		return tool.ReadCloserToBytes(body)
	}

	reader := io.Reader(body)
	closers := []func() error{body.Close}
	// https://www.rfc-editor.org/rfc/rfc9110.html#name-content-encoding
	// If one or more encodings have been applied to a representation, the sender that
	// applied the encodings MUST generate a Content-Encoding header field that lists
	// the content codings in the order in which they were applied.
	for idx := len(encodings) - 1; idx >= 0; idx-- {
		switch encodings[idx] {
		case EncodingGZip:
			gzipReader, err := gzip.NewReader(reader)
			if err != nil {
				closeAll(closers)
				return nil, err
			}
			reader = gzipReader
			closers = append(closers, gzipReader.Close)
		case EncodingDeflate:
			deflateReader := flate.NewReader(reader)
			reader = deflateReader
			closers = append(closers, deflateReader.Close)
		case EncodingZstd:
			zstdReader, err := zstd.NewReader(reader)
			if err != nil {
				closeAll(closers)
				return nil, err
			}
			reader = zstdReader
			closers = append(closers, func() error {
				zstdReader.Close()
				return nil
			})
		default:
			log.Warn().Str("encoding", encodings[idx]).Strs("encodings", encodings).Msg("unsupported content-encoding, stop decoding remaining layers")
			return readAllAndClose(reader, closers)
		}
	}
	return readAllAndClose(reader, closers)
}

func parseEncodings(encoding string) []string {
	parts := strings.Split(encoding, ",")
	encodings := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		if len(part) == 0 {
			continue
		}
		encodings = append(encodings, part)
	}
	return encodings
}

func readAllAndClose(reader io.Reader, closers []func() error) ([]byte, error) {
	defer closeAll(closers)

	return io.ReadAll(reader)
}

func closeAll(closers []func() error) {
	for idx := len(closers) - 1; idx >= 0; idx-- {
		if err := closers[idx](); err != nil {
			log.Error().Err(err).Msg("failed to close ReadCloser")
		}
	}
}
