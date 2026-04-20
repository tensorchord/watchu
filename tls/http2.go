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

type ParsedRequest struct {
	StreamID uint32
	Request  *http.Request
}

type ParsedResponse struct {
	StreamID      uint32
	Response      *http.Response
	DiscardStream bool
}

type HTTP2Parser struct{}

type HTTP2State struct {
	PrefaceConsumed bool
	Decoder         *hpack.Decoder // HPACK dynamic tables are scoped to one HTTP/2 connection direction.
	HeaderStreamID  uint32
	HeaderBlockBuf  []byte
	Streams         map[uint32]*HTTP2StreamState
}

type HTTP2StreamState struct {
	HeadersReady bool
	Ended        bool
	Headers      []hpack.HeaderField
	Body         bytes.Buffer
}

type HTTP2ParsedMessage struct {
	StreamID uint32
	Headers  []hpack.HeaderField
	Body     []byte
	Canceled bool
}

func (record *SSLRecord) ensureHTTP2State() *HTTP2State {
	if record.HTTP2 == nil {
		record.HTTP2 = &HTTP2State{
			Decoder: hpack.NewDecoder(4096, nil),
			Streams: make(map[uint32]*HTTP2StreamState),
		}
	}
	return record.HTTP2
}

func (state *HTTP2State) ensureStream(streamID uint32) *HTTP2StreamState {
	stream, ok := state.Streams[streamID]
	if !ok {
		stream = &HTTP2StreamState{}
		state.Streams[streamID] = stream
	}
	return stream
}

func (state *HTTP2State) tryCompleteStream(streamID uint32) *HTTP2ParsedMessage {
	stream, ok := state.Streams[streamID]
	if !ok || !stream.HeadersReady || !stream.Ended {
		return nil
	}

	message := &HTTP2ParsedMessage{
		StreamID: streamID,
		Headers:  stream.Headers,
		Body:     stream.Body.Bytes(),
	}
	delete(state.Streams, streamID)
	return message
}

func (h2 *HTTP2Parser) parse(record *SSLRecord) (*HTTP2ParsedMessage, int, error) {
	record.EndOfStream = false
	state := record.ensureHTTP2State()
	data := record.Stream
	consumed := 0

	if !state.PrefaceConsumed && bytes.HasPrefix(data, HTTP2Preface) {
		state.PrefaceConsumed = true
		consumed += HTTP2PrefaceLen
		data = data[HTTP2PrefaceLen:]
	}

	reader := bytes.NewReader(data)
	framer := http2.NewFramer(nil, reader)

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Trace().Int("len", len(data)).Str("buf", hex.EncodeToString(data)).Msg("HTTP/2 parsing reaches EOF")
				return nil, consumed, nil
			}
			return nil, consumed, fmt.Errorf("failed to read HTTP/2 frame: %w", err)
		}

		frameLen := int(frame.Header().Length) + HTTP2FrameHeaderLen
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			if state.HeaderStreamID != 0 && state.HeaderStreamID != f.Header().StreamID {
				return nil, consumed, fmt.Errorf("protocol error: new HEADERS on %d while block open on %d", f.Header().StreamID, state.HeaderStreamID)
			}
			if state.HeaderStreamID == 0 {
				state.HeaderStreamID = f.Header().StreamID
				state.HeaderBlockBuf = state.HeaderBlockBuf[:0]
			}
			stream := state.ensureStream(f.Header().StreamID)
			state.HeaderBlockBuf = append(state.HeaderBlockBuf, f.HeaderBlockFragment()...)
			if f.HeadersEnded() {
				headers, err := state.Decoder.DecodeFull(state.HeaderBlockBuf)
				if err != nil {
					return nil, consumed, fmt.Errorf("failed to decode HTTP/2 headers: %w", err)
				}
				stream.Headers = append(stream.Headers, headers...)
				stream.HeadersReady = true
				state.HeaderStreamID = 0
				state.HeaderBlockBuf = state.HeaderBlockBuf[:0]
			}
			if f.StreamEnded() {
				stream.Ended = true
			}
			consumed += frameLen
			log.Trace().Bool("EOS", stream.Ended).Any("info", &record.Info).Int("lastPos", consumed).Any("type", frame).Msg("parsed another HTTP/2 frame")
			if message := state.tryCompleteStream(f.Header().StreamID); message != nil {
				record.EndOfStream = true
				return message, consumed, nil
			}
		case *http2.ContinuationFrame:
			if state.HeaderStreamID == 0 {
				return nil, consumed, fmt.Errorf("protocol error: unexpected CONTINUATION on %d without HEADER block open", f.Header().StreamID)
			}
			if state.HeaderStreamID != f.Header().StreamID {
				return nil, consumed, fmt.Errorf("protocol error: CONTINUATION on %d while block open on %d", f.Header().StreamID, state.HeaderStreamID)
			}
			stream := state.ensureStream(f.Header().StreamID)
			state.HeaderBlockBuf = append(state.HeaderBlockBuf, f.HeaderBlockFragment()...)
			if f.HeadersEnded() {
				headers, err := state.Decoder.DecodeFull(state.HeaderBlockBuf)
				if err != nil {
					return nil, consumed, fmt.Errorf("failed to decode HTTP/2 headers: %w", err)
				}
				stream.Headers = append(stream.Headers, headers...)
				stream.HeadersReady = true
				state.HeaderStreamID = 0
				state.HeaderBlockBuf = state.HeaderBlockBuf[:0]
			}
			consumed += frameLen
			log.Trace().Bool("EOS", stream.Ended).Any("info", &record.Info).Int("lastPos", consumed).Any("type", frame).Msg("parsed another HTTP/2 frame")
			if message := state.tryCompleteStream(f.Header().StreamID); message != nil {
				record.EndOfStream = true
				return message, consumed, nil
			}
		case *http2.DataFrame:
			stream := state.ensureStream(f.Header().StreamID)
			stream.Body.Write(f.Data())
			if f.StreamEnded() {
				stream.Ended = true
			}
			consumed += frameLen
			log.Trace().Bool("EOS", stream.Ended).Any("info", &record.Info).Int("lastPos", consumed).Any("type", frame).Msg("parsed another HTTP/2 frame")
			if message := state.tryCompleteStream(f.Header().StreamID); message != nil {
				record.EndOfStream = true
				return message, consumed, nil
			}
		case *http2.RSTStreamFrame:
			delete(state.Streams, f.Header().StreamID)
			if state.HeaderStreamID == f.Header().StreamID {
				state.HeaderStreamID = 0
				state.HeaderBlockBuf = state.HeaderBlockBuf[:0]
			}
			consumed += frameLen
			record.EndOfStream = true
			log.Trace().Any("info", &record.Info).Int("lastPos", consumed).Any("type", frame).Msg("reset HTTP/2 stream")
			return &HTTP2ParsedMessage{StreamID: f.Header().StreamID, Canceled: true}, consumed, nil
		case *http2.GoAwayFrame:
			consumed += frameLen
			log.Trace().Any("info", &record.Info).Int("lastPos", consumed).Any("type", frame).Msg("received HTTP/2 GOAWAY frame")
		default:
			consumed += frameLen
			log.Trace().Any("info", &record.Info).Int("lastPos", consumed).Str("frame", fmt.Sprintf("%T", f)).Msg("ignoring non-header/data frame")
		}
	}
}

func (h2 *HTTP2Parser) ParseRequest(record *SSLRecord) (*ParsedRequest, int, error) {
	message, consumed, err := h2.parse(record)
	if err != nil {
		return nil, consumed, err
	}
	if message == nil {
		return nil, consumed, nil
	}
	if message.Canceled {
		return nil, consumed, nil
	}

	hdrs := http.Header{}
	var method, scheme, path, authority string
	for _, hf := range message.Headers {
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
		Body:       io.NopCloser(bytes.NewReader(message.Body)),
	}
	return &ParsedRequest{
		StreamID: message.StreamID,
		Request:  req,
	}, consumed, nil
}

func (h2 *HTTP2Parser) ParseResponse(record *SSLRecord) (*ParsedResponse, int, error) {
	message, consumed, err := h2.parse(record)
	if err != nil {
		return nil, consumed, err
	}
	if message == nil {
		return nil, consumed, nil
	}
	if message.Canceled {
		return &ParsedResponse{
			StreamID:      message.StreamID,
			DiscardStream: true,
		}, consumed, nil
	}

	hdrs := http.Header{}
	var code int
	for _, hf := range message.Headers {
		switch hf.Name {
		case ":status":
			code, err = strconv.Atoi(hf.Value)
			if err != nil {
				return nil, consumed, fmt.Errorf("invalid status code: %s", hf.Value)
			}
		default:
			hdrs.Add(hf.Name, hf.Value)
		}
	}

	resp := &http.Response{
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		StatusCode: code,
		Header:     hdrs,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Body:       io.NopCloser(bytes.NewReader(message.Body)),
	}
	return &ParsedResponse{
		StreamID: message.StreamID,
		Response: resp,
	}, consumed, nil
}
