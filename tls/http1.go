package tls

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/phuslu/log"
)

const (
	HTTP1DelimiterLen = 4
	CRLFLen           = 2
)

type HTTP1Parser struct{}

// HTTP/1 parsing assumes a single in-flight request/response pair per TLS connection.
// HTTP/1.1 pipelining is intentionally unsupported.
func (h1 *HTTP1Parser) ParseRequest(record *SSLRecord) (*ParsedRequest, int, error) {
	reader := bytes.NewReader(record.Stream)
	br := bufio.NewReader(reader)
	req, err := http.ReadRequest(br)
	if err != nil {
		// should wait for more data if it's unexpected EOF
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, 0, nil
		}
		// trim to the `\r\n\r\n`
		if idx := bytes.Index(record.Stream, HTTP1Delimiter); idx != -1 {
			return nil, idx + HTTP1DelimiterLen, err
		}
		// have to throw away to avoid infinite loop
		return nil, len(record.Stream), err
	}
	// find the end of the body
	idx := bytes.Index(record.Stream, HTTP1Delimiter)
	if idx == -1 {
		req.Body.Close()
		return &ParsedRequest{Request: req}, len(record.Stream), fmt.Errorf("cannot find the end of HTTP header")
	}
	// check if the body is fully received
	lengthToConsume := idx + HTTP1DelimiterLen + int(req.ContentLength)
	if req.ContentLength >= 0 && lengthToConsume > len(record.Stream) {
		// when the data is too large to be handled, returned the truncated body
		if lengthToConsume > SSLMaxDataSize && len(record.Stream)+SSLMaxEventSize > SSLMaxDataSize {
			log.Debug().Int("content_length", int(req.ContentLength)).Int("received", len(record.Stream)-idx-HTTP1DelimiterLen).Msg("truncate HTTP/1 request body")
			record.EndOfStream = true
			lengthToConsume = min(SSLMaxDataSize, len(record.Stream))
			return &ParsedRequest{Request: req}, lengthToConsume, nil
		}
		// wait for more data, do not return the half-received request body
		log.Debug().Int("content_length", int(req.ContentLength)).Int("received", len(record.Stream)-idx-HTTP1DelimiterLen).Msg("incomplete HTTP request body, wait for more data")
		req.Body.Close()
		record.EndOfStream = false
		return nil, 0, nil
	}
	record.EndOfStream = true
	return &ParsedRequest{Request: req}, lengthToConsume, nil
}

func parseStream(data []uint8) ([]uint8, uint64, error) {
	if idx := bytes.Index(data, CRLF); idx != -1 {
		length, err := strconv.ParseUint(string(data[:idx]), 16, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse stream length: %w", err)
		}
		consumed := uint64(idx) + CRLFLen + length + CRLFLen
		if consumed > uint64(len(data)) {
			// wait for more data
			return nil, 0, nil
		}
		return data[idx+CRLFLen : idx+CRLFLen+int(length)], consumed, nil
	}
	return nil, 0, fmt.Errorf("failed to parse stream length: no CRLF found")
}

func isChunkedEncoding(resp *http.Response) bool {
	encodingLen := len(resp.TransferEncoding)
	return encodingLen > 0 && resp.TransferEncoding[encodingLen-1] == ChunkedEncodingValue
}

// HTTP/1 parsing assumes a single in-flight request/response pair per TLS connection.
// HTTP/1.1 pipelining is intentionally unsupported.
func (h1 *HTTP1Parser) ParseResponse(record *SSLRecord) (*ParsedResponse, int, error) {
	// streaming response, handle the chunked transfer encoding
	if record.LastResp != nil && isChunkedEncoding(record.LastResp) {
		stream, consumed, err := parseStream(record.Stream)
		if err != nil || consumed == 0 {
			return nil, 0, err
		}
		switch consumed {
		case StreamEndChunkLength:
			// end of the stream
			record.EndOfStream = true
		default:
			record.EndOfStream = false
			chunk := append([]byte(nil), stream...)
			record.LastResp.Body = io.NopCloser(io.MultiReader(record.LastResp.Body, bytes.NewReader(chunk)))
		}
		return &ParsedResponse{Response: record.LastResp}, int(consumed), nil
	}

	reader := bytes.NewReader(record.Stream)
	br := bufio.NewReader(reader)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		// should wait for more data if it's unexpected EOF
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, 0, nil
		}
		// trim to the `\r\n\r\n`
		if idx := bytes.Index(record.Stream, HTTP1Delimiter); idx != -1 {
			return nil, idx + HTTP1DelimiterLen, err
		}
		// have to throw away to avoid infinite loop
		return nil, len(record.Stream), err
	}
	// find the end of the header
	idx := bytes.Index(record.Stream, HTTP1Delimiter)
	if idx == -1 {
		resp.Body.Close()
		return &ParsedResponse{Response: resp}, len(record.Stream), fmt.Errorf("cannot find the end of HTTP header")
	}
	// update the last response
	record.LastResp = resp

	contentLength := resp.ContentLength
	// Receiving stream, leave the body for the next round
	if isChunkedEncoding(resp) {
		resp.Body.Close()
		record.EndOfStream = false
		contentLength = 0
		resp.Body = io.NopCloser(bytes.NewReader([]byte{})) // change to empty body, so next time will handle the chunk
	} else {
		// Non-Streaming response should end here if the body has been fully received
		consumed := idx + HTTP1DelimiterLen + int(contentLength)
		if consumed > len(record.Stream) {
			// wait for more data
			log.Debug().Int("consumed", consumed).Int("len_stream", len(record.Stream)).Msg("wait for more data to fill this response")
			resp.Body.Close()
			return nil, 0, nil
		}
		record.EndOfStream = true
	}
	return &ParsedResponse{Response: resp}, idx + HTTP1DelimiterLen + int(contentLength), nil
}
