package tls

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/maypok86/otter/v2"
	"github.com/phuslu/log"
	"golang.org/x/net/http2"

	"github.com/tensorchord/watchu/export"
	"github.com/tensorchord/watchu/internal/tool"
)

const (
	// SSL
	SSLMaxEventSize = 64 * 1024            // 64 KiB
	SSLMaxDataSize  = 64 * SSLMaxEventSize // 4 MiB
	SSLRwRead       = 4
	SSLRwWrite      = 2

	// HTTP
	ChunkedEncodingValue = "chunked"
	StreamEndChunkLength = uint64(len("0")) + 2*CRLFLen // "0\r\n\r\n"

	// Postgres
	PostgresStartupMessageMaxLength = 4096
)

type ProtocolType int

const (
	ProtocolHTTP1 ProtocolType = iota
	ProtocolHTTP2
	ProtocolPostgres
	ProtocolUnknown
)

var (
	// HTTP
	CRLF                = []byte("\r\n")
	HTTP1Delimiter      = []byte("\r\n\r\n")
	HTTP1ChunkEnd       = []byte("0\r\n\r\n")
	HTTP1ResponsePrefix = []byte("HTTP/")
	HTTP1RequestMethods = [][]byte{
		[]byte("GET"),
		[]byte("POST"),
		[]byte("PUT"),
		[]byte("DELETE"),
		[]byte("HEAD"),
		[]byte("OPTIONS"),
		[]byte("PATCH"),
		[]byte("TRACE"),
		[]byte("CONNECT"),
	}
	HTTP2Preface    = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	HTTP2PrefaceLen = len(HTTP2Preface)
	HeaderAPIKeys   = []string{
		"Authorization",
		"X-API-Key",
		"X-Auth-Token",
		"X-Access-Token",
		"X-Session-Token",
		"Cookie",
	}
	HeaderTokenSecret = []byte("tensorchord-watchu-sslsniff-mask-secret-c0ffee")
)

func flattenMaskedHeader(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	m := hmac.New(sha256.New, HeaderTokenSecret)
	for k, v := range h {
		value := strings.Join(v, ",")
		for _, apiKey := range HeaderAPIKeys {
			if strings.Contains(k, apiKey) {
				m.Reset()
				m.Write([]byte(value))
				value = fmt.Sprintf("masked-%s", hex.EncodeToString(m.Sum(nil)))
				break
			}
		}
		flat[k] = value
	}
	return flat
}

func isBinary(data []uint8) bool {
	for _, b := range data {
		if unicode.IsControl(rune(b)) && b != 9 && b != 10 && b != 13 {
			return true
		}
	}
	return false
}

type SSLKey struct {
	PidTgid  uint64
	UidGid   uint64
	SSLPtr   uint64
	CgroupID uint64
}

type EventInfo struct {
	TimestampNs uint64
	DataLen     uint64
	Comm        [16]int8
}

type SessionScope struct {
	Conn     SSLKey
	StreamID uint32
}

type SSLRecord struct {
	Info        []*EventInfo
	Stream      []uint8
	LastResp    *http.Response
	EndOfStream bool
	HTTP2       *HTTP2State
	LastTouched time.Time
}

func (r *SSLRecord) Append(data []uint8, info *EventInfo) {
	r.Stream = append(r.Stream, data...)
	r.Info = append(r.Info, info)
	r.LastTouched = time.Now()
}

type SSLStore struct {
	Request         map[SSLKey]*SSLRecord
	Response        map[SSLKey]*SSLRecord
	sessions        *otter.Cache[SessionScope, string]
	sessionScopes   map[SSLKey]map[SessionScope]struct{}
	protocolCache   *otter.Cache[SSLKey, ProtocolType]
	reqMu           sync.Mutex
	respMu          sync.Mutex
	sessionMu       sync.Mutex
	cleanupMu       sync.Mutex
	sessionTTL      time.Duration
	recordTTL       time.Duration
	cleanupInterval time.Duration
	nextCleanup     time.Time
	parseInterval   time.Duration
	http1Parser     *HTTP1Parser
	http2Parser     *HTTP2Parser
	postgresParser  *PostgresParser
}

func NewSSLStore() *SSLStore {
	store := &SSLStore{
		parseInterval:   time.Second,
		Request:         make(map[SSLKey]*SSLRecord),
		Response:        make(map[SSLKey]*SSLRecord),
		sessionScopes:   make(map[SSLKey]map[SessionScope]struct{}),
		sessionTTL:      10 * time.Minute,
		recordTTL:       10 * time.Minute,
		cleanupInterval: time.Minute,
		nextCleanup:     time.Now().Add(time.Minute),
		http1Parser:     &HTTP1Parser{},
		http2Parser:     &HTTP2Parser{},
		postgresParser:  &PostgresParser{},
	}
	store.protocolCache = otter.Must(&otter.Options[SSLKey, ProtocolType]{
		ExpiryCalculator: otter.ExpiryAccessingFunc(func(entry otter.Entry[SSLKey, ProtocolType]) time.Duration {
			if entry.Value == ProtocolPostgres {
				return 3 * time.Hour
			}
			return 10 * time.Minute
		}),
	})
	store.sessions = otter.Must(&otter.Options[SessionScope, string]{
		ExpiryCalculator: otter.ExpiryAccessingFunc(func(entry otter.Entry[SessionScope, string]) time.Duration {
			return store.sessionTTL
		}),
	})
	return store
}

func generateSessionKey() string {
	sessionKey, err := uuid.NewV7()
	if err != nil {
		return fmt.Sprintf("unknown-session-%d", time.Now().UnixNano())
	}
	return sessionKey.String()
}

func (s *SSLStore) ensureSessionKey(scope SessionScope) string {
	if sessionKey, ok := s.sessions.GetIfPresent(scope); ok {
		return sessionKey
	}
	sessionKey := generateSessionKey()
	s.sessions.Set(scope, sessionKey)
	s.addSessionScope(scope)
	return sessionKey
}

func (s *SSLStore) deleteSessionKey(scope SessionScope) {
	s.sessions.Invalidate(scope)
	s.removeSessionScope(scope)
}

func (s *SSLStore) deleteConnectionSessions(key SSLKey) {
	for scope := range s.sessionScopesForConn(key) {
		s.deleteSessionKey(scope)
	}
}

func sessionScopeForKey(key SSLKey, streamID uint32) SessionScope {
	return SessionScope{
		Conn:     key,
		StreamID: streamID,
	}
}

func consumeRecord(record *SSLRecord, consumed int) (timestamp uint64, comm string, consumedAll bool) {
	if consumed <= 0 || len(record.Info) == 0 {
		return 0, "", consumed == len(record.Stream)
	}
	if consumed > len(record.Stream) {
		consumed = len(record.Stream)
	}
	if consumed == len(record.Stream) {
		last := record.Info[len(record.Info)-1]
		record.Stream = record.Stream[:0]
		record.Info = record.Info[:0]
		return last.TimestampNs, tool.CharsToString(last.Comm[:]), true
	}

	record.Stream = record.Stream[consumed:]
	index := 0
	last := 0
	length := consumed
	for i, info := range record.Info {
		index = i
		if length == 0 {
			break
		} else if length >= int(info.DataLen) {
			length -= int(info.DataLen)
		} else {
			break
		}
		last = i
		if i == len(record.Info)-1 && length == 0 {
			index = len(record.Info)
		}
	}
	timestamp = record.Info[last].TimestampNs
	comm = tool.CharsToString(record.Info[last].Comm[:])
	record.Info = record.Info[index:]
	return timestamp, comm, false
}

func (s *SSLStore) addSessionScope(scope SessionScope) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	scopes, ok := s.sessionScopes[scope.Conn]
	if !ok {
		scopes = make(map[SessionScope]struct{})
		s.sessionScopes[scope.Conn] = scopes
	}
	scopes[scope] = struct{}{}
}

func (s *SSLStore) removeSessionScope(scope SessionScope) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	scopes, ok := s.sessionScopes[scope.Conn]
	if !ok {
		return
	}
	delete(scopes, scope)
	if len(scopes) == 0 {
		delete(s.sessionScopes, scope.Conn)
	}
}

func (s *SSLStore) sessionScopesForConn(key SSLKey) map[SessionScope]struct{} {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	scopes, ok := s.sessionScopes[key]
	if !ok {
		return nil
	}
	result := make(map[SessionScope]struct{}, len(scopes))
	for scope := range scopes {
		if _, ok := s.sessions.GetIfPresent(scope); !ok {
			delete(scopes, scope)
			continue
		}
		result[scope] = struct{}{}
	}
	if len(scopes) == 0 {
		delete(s.sessionScopes, key)
	}
	return result
}

func (s *SSLStore) shouldCleanup(now time.Time) bool {
	s.cleanupMu.Lock()
	defer s.cleanupMu.Unlock()

	if now.Before(s.nextCleanup) {
		return false
	}
	s.nextCleanup = now.Add(s.cleanupInterval)
	return true
}

func (s *SSLStore) cleanupStaleRequestRecords(cutoff time.Time) {
	s.reqMu.Lock()
	defer s.reqMu.Unlock()

	for key, record := range s.Request {
		if record.LastTouched.Before(cutoff) {
			delete(s.Request, key)
		}
	}
}

func (s *SSLStore) cleanupStaleResponseRecords(cutoff time.Time) {
	s.respMu.Lock()
	defer s.respMu.Unlock()

	for key, record := range s.Response {
		if record.LastTouched.Before(cutoff) {
			delete(s.Response, key)
			s.deleteConnectionSessions(key)
		}
	}
}

// detectProtocol tries to determine the protocol type based on the initial bytes of the stream.
// This assumption should be consistent throughout the lifetime of the SSL+Pid+Uid tuple.
//
// NOTE: This function is not idempotent, it will consume the stream if the Postgres StartupMessage
// is detected.
func (ss *SSLStore) detectProtocol(key SSLKey, record *SSLRecord) ProtocolType {
	pt, ok := ss.protocolCache.GetIfPresent(key)
	if ok {
		return pt
	}

	logger := log.DefaultLogger
	logger.Context = log.NewContext(nil).Str("ctx", "[Protocol]").Value()
	buf := record.Stream

	if bytes.HasPrefix(buf, HTTP2Preface) {
		logger.Trace().Msg("detect HTTP/2 preface")
		ss.protocolCache.Set(key, ProtocolHTTP2)
		return ProtocolHTTP2
	}
	if bytes.HasPrefix(buf, HTTP1ResponsePrefix) || bytes.HasPrefix(buf, HTTP1ChunkEnd) {
		logger.Trace().Msg("detect HTTP/1.x response")
		ss.protocolCache.Set(key, ProtocolHTTP1)
		return ProtocolHTTP1
	}
	for _, method := range HTTP1RequestMethods {
		if bytes.HasPrefix(buf, method) {
			logger.Trace().Str("method", string(method)).Msg("detect HTTP/1.x request method")
			ss.protocolCache.Set(key, ProtocolHTTP1)
			return ProtocolHTTP1
		}
	}
	if len(buf) > 8 {
		// detects the Postgres startup message during the init connection phase
		length := binary.BigEndian.Uint32(buf[:4])
		protocolVersion := binary.BigEndian.Uint32(buf[4:8])
		if length <= PostgresStartupMessageMaxLength && (protocolVersion>>16) == 3 {
			data := buf[8:min(length, uint32(len(buf)))]
			logger.Debug().Uint32("length", length).Uint32("protocol_version", protocolVersion).Bytes("data", data).Msg("detect Postgres startup message")
			ss.protocolCache.Set(key, ProtocolPostgres)
			// need to consume the startup message
			record.Stream = record.Stream[min(length, uint32(len(buf))):]
			return ProtocolPostgres
		}
	}
	// check if it's chunked encoding
	_, consumed, err := parseStream(buf)
	if err == nil && consumed > 0 {
		logger.Trace().Msg("detect HTTP/1.x chunked encoding")
		ss.protocolCache.Set(key, ProtocolHTTP1)
		return ProtocolHTTP1
	}
	// HTTP/1.x are text based, unless compression is used
	if !isBinary(buf) {
		logger.Trace().Msg("plain text detected, likely HTTP/1.x")
		ss.protocolCache.Set(key, ProtocolHTTP1)
		return ProtocolHTTP1
	}
	// it's very likely HTTP/2 if no HTTP/1.x signature found
	if len(buf) < HTTP2FrameHeaderLen {
		logger.Error().Str("buf", hex.EncodeToString(buf)).Msg("cannot determine the protocol version")
		return ProtocolUnknown
	}
	// try to parse the frame header according to https://datatracker.ietf.org/doc/html/rfc7540
	length := (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2]))
	frameType := buf[3]
	flags := buf[4]
	streamID := binary.BigEndian.Uint32(buf[5:]) & (1<<31 - 1)
	if length > SSLMaxDataSize || frameType > HTTP2FrameMaxCode || flags&^HTTP2FlagsMask != 0 {
		logger.Trace().Uint32("length", length).Uint8("frame", frameType).Uint8("flags", flags).Msg("invalid HTTP/2 frame header")
		return ProtocolUnknown
	}
	//nolint:staticcheck
	if streamID == 0 && !(frameType == uint8(http2.FrameSettings) || frameType == uint8(http2.FramePing) || frameType == uint8(http2.FrameGoAway) || frameType == uint8(http2.FrameWindowUpdate)) {
		logger.Trace().Uint32("stream_id", streamID).Uint8("frame", frameType).Msg("invalid HTTP/2 stream ID with non-control frame")
		return ProtocolUnknown
	}
	logger.Trace().Msg("guess HTTP2 by default")
	ss.protocolCache.Set(key, ProtocolHTTP2)
	return ProtocolHTTP2
}

func (s *SSLStore) Add(event *sslEvent) {
	key := SSLKey{
		PidTgid:  event.PidTgid,
		UidGid:   event.UidGid,
		SSLPtr:   event.SslPtr,
		CgroupID: event.CgroupId,
	}
	info := &EventInfo{
		TimestampNs: event.TimestampNs,
		DataLen:     event.DataLen,
		Comm:        event.Comm,
	}
	switch event.Rw {
	case SSLRwWrite:
		s.reqMu.Lock()
		record, ok := s.Request[key]
		if !ok {
			record = &SSLRecord{}
			s.Request[key] = record
		}
		record.Append(event.Data[:event.DataLen], info)
		s.reqMu.Unlock()
	case SSLRwRead:
		s.respMu.Lock()
		record, ok := s.Response[key]
		if !ok {
			record = &SSLRecord{}
			s.Response[key] = record
		}
		record.Append(event.Data[:event.DataLen], info)
		s.respMu.Unlock()
	}
}

func (s *SSLStore) parseRequest(reqChan chan *export.RawRequest, postgresChan chan *export.RawPostgres) {
	now := time.Now()
	if s.shouldCleanup(now) {
		s.cleanupStaleRequestRecords(now.Add(-s.recordTTL))
	}
	s.reqMu.Lock()
	defer s.reqMu.Unlock()

	var parser ProtocolParser
	for key, record := range s.Request {
		protocol := s.detectProtocol(key, record)
		switch protocol {
		case ProtocolHTTP2:
			parser = s.http2Parser
		case ProtocolHTTP1:
			parser = s.http1Parser
		case ProtocolPostgres:
			parser = s.postgresParser
		default:
			log.Warn().Any("key", &key).Msg("unknown protocol, skipping parsing")
			delete(s.Request, key)
			continue
		}
		for len(record.Stream) > 0 {
			parsed, consumed, err := parser.ParseRequest(record)
			if err != nil {
				log.Error().Any("key", &key).Bytes("buf", record.Stream[:min(len(record.Stream), consumed)]).Err(err).Msg("failed to parse TLS request")
				delete(s.Request, key)
				break
			}
			if consumed == 0 {
				break
			}

			timestamp, comm, consumedAll := consumeRecord(record, consumed)
			if consumedAll && record.EndOfStream && protocol != ProtocolHTTP2 {
				delete(s.Request, key)
			}
			if parsed == nil || parsed.Request == nil {
				record.EndOfStream = false
				continue
			}
			if !record.EndOfStream {
				continue
			}

			request := parsed.Request
			truncated := consumed >= SSLMaxDataSize
			body, err := readDecodeBytes(request.Body, request.Header.Get("Content-Encoding"))
			if err != nil {
				log.Error().Any("key", &key).Err(err).Msg("failed to read request body")
				record.EndOfStream = false
				continue
			}
			url := request.RequestURI
			if request.URL != nil {
				url = request.URL.String()
			}
			if len(request.Host) > 0 && request.Header != nil {
				request.Header.Add("Host", request.Host)
			}
			headers := flattenMaskedHeader(request.Header)
			log.Info().Uint64("timestamp", timestamp).Str("comm", comm).Int("len", consumed).Any("headers", headers).Int64("content_length", request.ContentLength).Str("url", url).Str("method", request.Method).Str("protocol", request.Proto).Bytes("body", body).Bool("truncated", truncated).Msg("TLS request")
			record.EndOfStream = false
			record.LastResp = nil

			if request.Proto == PostgresProtoRequest {
				select {
				case postgresChan <- &export.RawPostgres{
					ElapsedNs: timestamp,
					PidTGid:   key.PidTgid,
					UidGid:    key.UidGid,
					CgroupID:  key.CgroupID,
					Comm:      comm,
					Data:      body,
					MsgType:   request.Method,
				}:
				default:
					log.Warn().Msg("TLS postgres channel is full, dropping event")
				}
			} else {
				scope := sessionScopeForKey(key, parsed.StreamID)
				select {
				case reqChan <- &export.RawRequest{
					ElapsedNs:     timestamp,
					SessionKey:    s.ensureSessionKey(scope),
					PidTGid:       key.PidTgid,
					UidGid:        key.UidGid,
					CgroupID:      key.CgroupID,
					Comm:          comm,
					Method:        request.Method,
					URL:           url,
					ContentLength: request.ContentLength,
					Protocol:      request.Proto,
					Headers:       headers,
					Body:          body,
					Truncated:     truncated,
				}:
				default:
					log.Warn().Msg("TLS request channel is full, dropping event")
				}
			}
			break
		}
	}
}

func (s *SSLStore) parseResponse(channel chan *export.RawResponse) {
	now := time.Now()
	if s.shouldCleanup(now) {
		s.cleanupStaleResponseRecords(now.Add(-s.recordTTL))
	}
	s.respMu.Lock()
	defer s.respMu.Unlock()

	var parser ProtocolParser
	for key, record := range s.Response {
		protocol := s.detectProtocol(key, record)
		switch protocol {
		case ProtocolHTTP2:
			parser = s.http2Parser
		case ProtocolHTTP1:
			parser = s.http1Parser
		case ProtocolPostgres:
			parser = s.postgresParser
		default:
			log.Warn().Any("key", &key).Msg("unknown protocol, skipping parsing")
			delete(s.Response, key)
			s.deleteConnectionSessions(key)
			continue
		}
		for len(record.Stream) > 0 {
			parsed, consumed, err := parser.ParseResponse(record)
			if err != nil {
				log.Error().Any("key", &key).Bytes("buf", record.Stream[:min(len(record.Stream), consumed)]).Err(err).Msg("failed to parse TLS response")
				delete(s.Response, key)
				s.deleteConnectionSessions(key)
				break
			}
			if consumed == 0 {
				break
			}

			timestamp, comm, consumedAll := consumeRecord(record, consumed)
			if consumedAll && record.EndOfStream && protocol != ProtocolHTTP2 {
				delete(s.Response, key)
			}

			if parsed == nil {
				record.EndOfStream = false
				continue
			}
			scope := sessionScopeForKey(key, parsed.StreamID)
			if parsed.DiscardStream {
				s.deleteSessionKey(scope)
				record.EndOfStream = false
				continue
			}
			if parsed.Response == nil {
				record.EndOfStream = false
				continue
			}
			if !record.EndOfStream {
				continue
			}

			response := parsed.Response
			body, err := readDecodeBytes(response.Body, response.Header.Get("Content-Encoding"))
			if err != nil {
				log.Error().Any("key", &key).Err(err).Msg("failed to read response body")
				s.deleteSessionKey(scope)
				record.EndOfStream = false
				continue
			}
			headers := flattenMaskedHeader(response.Header)
			log.Info().Uint64("timestamp", timestamp).Str("comm", comm).Int("len", consumed).Any("headers", headers).Int64("content_length", response.ContentLength).Int("status_code", response.StatusCode).Str("protocol", response.Proto).Bytes("body", body).Bool("truncated", false).Msg("TLS response")
			record.EndOfStream = false
			record.LastResp = nil
			select {
			case channel <- &export.RawResponse{
				ElapsedNs:     timestamp,
				SessionKey:    s.ensureSessionKey(scope),
				PidTGid:       key.PidTgid,
				UidGid:        key.UidGid,
				CgroupID:      key.CgroupID,
				Comm:          comm,
				StatusCode:    response.StatusCode,
				ContentLength: response.ContentLength,
				Protocol:      response.Proto,
				Headers:       headers,
				Body:          body,
				Truncated:     false,
			}:
			default:
				log.Warn().Msg("response channel is full, dropping event")
			}
			s.deleteSessionKey(scope)
			break
		}
	}
}

func (s *SSLStore) Parse(ctx context.Context, reqChan chan *export.RawRequest, respChan chan *export.RawResponse, postgresChan chan *export.RawPostgres) {
	ticker := time.NewTicker(s.parseInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// we only collect the postgres Request events
			s.parseRequest(reqChan, postgresChan)
			s.parseResponse(respChan)
		}
	}
}

type ProtocolParser interface {
	ParseRequest(record *SSLRecord) (*ParsedRequest, int, error)
	ParseResponse(record *SSLRecord) (*ParsedResponse, int, error)
}
