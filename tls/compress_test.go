package tls

import (
	"bytes"
	"io"
	"testing"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

func TestReadDecodeBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		encoding string
	}{
		{
			name:     "gzip",
			encoding: EncodingGZip,
		},
		{
			name:     "deflate",
			encoding: EncodingDeflate,
		},
		{
			name:     "gzip then deflate",
			encoding: "gzip, deflate",
		},
		{
			name:     "zstd",
			encoding: EncodingZstd,
		},
		{
			name:     "gzip then zstd",
			encoding: "gzip, zstd",
		},
		{
			name:     "deflate then gzip with spaces and case",
			encoding: " Deflate , GZIP ",
		},
		{
			name:     "zstd then gzip with spaces and case",
			encoding: " ZSTD , GZIP ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			want := []byte(`{"message":"hello layered encoding"}`)
			body := io.NopCloser(bytes.NewReader(encodeBody(t, want, parseEncodings(tt.encoding))))

			got, err := readDecodeBytes(body, tt.encoding)
			if err != nil {
				t.Fatalf("readDecodeBytes() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("readDecodeBytes() = %q, want %q", got, want)
			}
		})
	}
}

func TestReadDecodeBytesUnknownEncodingReturnsPartialBody(t *testing.T) {
	t.Parallel()

	body := io.NopCloser(bytes.NewReader([]byte("payload")))
	got, err := readDecodeBytes(body, "br")
	if err != nil {
		t.Fatalf("readDecodeBytes() error = %v", err)
	}
	if !bytes.Equal(got, []byte("payload")) {
		t.Fatalf("readDecodeBytes() = %q, want %q", got, "payload")
	}
}

func encodeBody(t *testing.T, body []byte, encodings []string) []byte {
	t.Helper()

	encoded := body
	for _, encoding := range encodings {
		var buf bytes.Buffer
		var err error

		switch encoding {
		case EncodingGZip:
			writer := gzip.NewWriter(&buf)
			_, err = writer.Write(encoded)
			if closeErr := writer.Close(); err == nil {
				err = closeErr
			}
		case EncodingDeflate:
			writer, writerErr := flate.NewWriter(&buf, flate.DefaultCompression)
			if writerErr != nil {
				t.Fatalf("flate.NewWriter() error = %v", writerErr)
			}
			_, err = writer.Write(encoded)
			if closeErr := writer.Close(); err == nil {
				err = closeErr
			}
		case EncodingZstd:
			writer, writerErr := zstd.NewWriter(&buf)
			if writerErr != nil {
				t.Fatalf("zstd.NewWriter() error = %v", writerErr)
			}
			_, err = writer.Write(encoded)
			if closeErr := writer.Close(); err == nil {
				err = closeErr
			}
		default:
			t.Fatalf("unsupported encoding in test: %s", encoding)
		}
		if err != nil {
			t.Fatalf("encodeBody() error = %v", err)
		}

		encoded = buf.Bytes()
	}

	return encoded
}
