package tls

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/phuslu/log"
)

const (
	HTTP2FrameHeaderLen = 9
	HTTP2FrameMaxCode   = 0x9
	HTTP2FlagsMask      = 0x1 | 0x4 | 0x8 | 0x20
)

type HTTP2Parser struct {
	dec *hpack.Decoder
}

func NewHTTP2Parser() *HTTP2Parser {
	return &HTTP2Parser{
		dec: hpack.NewDecoder(4096, nil),
	}
}

func (h2 *HTTP2Parser) parse(record *SSLRecord) (headers []hpack.HeaderField, body bytes.Buffer, lastPos int, err error) {
	data := record.Stream
	if bytes.HasPrefix(record.Stream, HTTP2Preface) {
		lastPos += HTTP2PrefaceLen
		data = data[HTTP2PrefaceLen:]
	}

	reader := bytes.NewReader(data)
	framer := http2.NewFramer(nil, reader)
	var frame http2.Frame
	var hbStreamID uint32
	var hbBuf []byte
	var hbOpen bool

	for !record.EndOfStream {
		frame, err = framer.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// wait for more data, suppress the EOF error
				err = nil
				log.Trace().Int("len", len(data)).Str("buf", hex.EncodeToString(data)).Msg("HTTP/2 parsing reaches EOF")
				return
			}
			err = fmt.Errorf("failed to read HTTP/2 frame: %w", err)
			return
		}
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			if hbOpen && hbStreamID != f.Header().StreamID {
				err = fmt.Errorf("protocol error: new HEADERS on %d while block open on %d", f.Header().StreamID, hbStreamID)
				return
			}
			if !hbOpen {
				hbOpen = true
				hbStreamID = f.Header().StreamID
				hbBuf = hbBuf[:0]
			}
			hbBuf = append(hbBuf, f.HeaderBlockFragment()...)
			if f.HeadersEnded() {
				var hdrs []hpack.HeaderField
				hdrs, err = h2.dec.DecodeFull(hbBuf)
				if err != nil {
					err = fmt.Errorf("failed to decode HTTP/2 headers: %w", err)
					return
				}
				headers = append(headers, hdrs...)
				hbOpen = false
			}
			if f.StreamEnded() {
				record.EndOfStream = true
			}
		case *http2.ContinuationFrame:
			if !hbOpen {
				err = fmt.Errorf("protocol error: unexpected CONTINUATION on %d without HEADER block open", f.Header().StreamID)
				return
			}
			if hbOpen && hbStreamID != f.Header().StreamID {
				err = fmt.Errorf("protocol error: CONTINUATION on %d while block open on %d", f.Header().StreamID, hbStreamID)
				return
			}
			hbBuf = append(hbBuf, f.HeaderBlockFragment()...)
			if f.HeadersEnded() {
				var hdrs []hpack.HeaderField
				hdrs, err = h2.dec.DecodeFull(hbBuf)
				if err != nil {
					err = fmt.Errorf("failed to decode HTTP/2 headers: %w", err)
					return
				}
				headers = append(headers, hdrs...)
				hbOpen = false
			}
		case *http2.DataFrame:
			body.Write(f.Data())
			if f.StreamEnded() {
				record.EndOfStream = true
			}
		case *http2.RSTStreamFrame:
			record.EndOfStream = true
		case *http2.GoAwayFrame:
			record.EndOfStream = true
		default:
			// ignore other connection-level frames
			log.Trace().Bool("EOS", record.EndOfStream).Any("info", &record.Info).Str("frame", fmt.Sprintf("%T", f)).Msg("ignoring non-header/data frame")
		}
		lastPos += int(frame.Header().Length) + HTTP2FrameHeaderLen
		log.Trace().Bool("EOS", record.EndOfStream).Any("info", &record.Info).Int("lastPos", lastPos).Any("type", frame).Msg("parsed another HTTP/2 frame")
	}
	return
}

func (h2 *HTTP2Parser) ParseRequest(record *SSLRecord) (*http.Request, int, error) {
	headers, body, lastPos, err := h2.parse(record)
	if err != nil {
		return nil, lastPos, err
	}

	if !record.EndOfStream && lastPos+SSLMaxEventSize > SSLMaxDataSize {
		// truncate the request body
		log.Debug().Int("lastPos", lastPos).Msg("truncate HTTP/2 request body")
		record.EndOfStream = true
	}
	if !record.EndOfStream {
		// wait for more data
		return nil, 0, nil
	}
	// could be a GoAwayFrame, no need to record this one
	if len(headers) == 0 && body.Len() == 0 {
		return nil, lastPos, nil
	}
	// convert headers to http.Request
	hdrs := http.Header{}
	var method, scheme, path, authority string
	for _, hf := range headers {
		switch hf.Name {
		case ":method":
			method = hf.Value
		case ":scheme":
			scheme = hf.Value
		case ":path":
			path = hf.Value
		case ":authority":
			authority = hf.Value
		default:
			hdrs.Add(hf.Name, hf.Value)
		}
	}
	url := &url.URL{
		Scheme: scheme,
		Host:   authority,
		Path:   path,
	}
	req := &http.Request{
		Method:     method,
		URL:        url,
		Header:     hdrs,
		Host:       authority,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Body:       io.NopCloser(&body),
	}
	return req, lastPos, nil
}

func (h2 *HTTP2Parser) ParseResponse(record *SSLRecord) (*http.Response, int, error) {
	headers, body, lastPos, err := h2.parse(record)
	if err != nil {
		return nil, lastPos, err
	}

	// create a new Response
	if record.LastResp == nil {
		// convert headers to http.Response
		hdrs := http.Header{}
		var code int
		for _, hf := range headers {
			switch hf.Name {
			case ":status":
				code, err = strconv.Atoi(hf.Value)
				if err != nil {
					return nil, lastPos, fmt.Errorf("invalid status code: %s", hf.Value)
				}
			default:
				hdrs.Add(hf.Name, hf.Value)
			}
		}
		record.LastResp = &http.Response{
			Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
			StatusCode: code,
			Header:     hdrs,
			Proto:      "HTTP/2.0",
			ProtoMajor: 2,
			ProtoMinor: 0,
			Body:       io.NopCloser(&body),
		}
	} else {
		record.LastResp.Body = io.NopCloser(io.MultiReader(record.LastResp.Body, &body))
	}
	return record.LastResp, lastPos, nil
}
