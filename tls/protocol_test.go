package tls

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/tensorchord/watchu/export"
)

func TestSSLStoreSessionKeySequentialPairs(t *testing.T) {
	t.Parallel()

	store := NewSSLStore()
	key := SSLKey{
		PidTgid:  101,
		UidGid:   202,
		SSLPtr:   303,
		CgroupID: 404,
	}
	scope := sessionScopeForKey(key, 0)
	reqChan := make(chan *export.RawRequest, 2)
	respChan := make(chan *export.RawResponse, 1)
	postgresChan := make(chan *export.RawPostgres, 1)

	store.Request[key] = newTestSSLRecordFromString("GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n", 100)
	store.parseRequest(reqChan, postgresChan)

	firstReq := mustReadRequest(t, reqChan)
	if firstReq.SessionKey == "" {
		t.Fatal("expected first request session key")
	}

	store.Response[key] = newTestSSLRecordFromString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", 200)
	store.parseResponse(respChan)

	firstResp := mustReadResponse(t, respChan)
	if firstResp.SessionKey != firstReq.SessionKey {
		t.Fatalf("response session key = %q, want %q", firstResp.SessionKey, firstReq.SessionKey)
	}
	if hasSession(store, scope) {
		t.Fatal("expected session key to be released after response completion")
	}

	store.Request[key] = newTestSSLRecordFromString("GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n", 300)
	store.parseRequest(reqChan, postgresChan)

	secondReq := mustReadRequest(t, reqChan)
	if secondReq.SessionKey == "" {
		t.Fatal("expected second request session key")
	}
	if secondReq.SessionKey == firstReq.SessionKey {
		t.Fatalf("second request reused session key %q", secondReq.SessionKey)
	}
}

func TestSSLStoreHTTP1SSESessionLifecycle(t *testing.T) {
	t.Parallel()

	store := NewSSLStore()
	key := SSLKey{
		PidTgid:  1001,
		UidGid:   2002,
		SSLPtr:   3003,
		CgroupID: 4004,
	}
	scope := sessionScopeForKey(key, 0)
	reqChan := make(chan *export.RawRequest, 1)
	respChan := make(chan *export.RawResponse, 1)
	postgresChan := make(chan *export.RawPostgres, 1)

	store.Request[key] = newTestSSLRecordFromString("GET /events HTTP/1.1\r\nHost: example.com\r\n\r\n", 100)
	store.parseRequest(reqChan, postgresChan)

	req := mustReadRequest(t, reqChan)
	if req.SessionKey == "" {
		t.Fatal("expected request session key")
	}

	store.Response[key] = newTestSSLRecordFromString(
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\nd\r\ndata: hello\n\n\r\n",
		200,
	)
	store.parseResponse(respChan)

	select {
	case resp := <-respChan:
		t.Fatalf("unexpected response before end-of-stream: %+v", resp)
	default:
	}
	if !hasSession(store, scope) {
		t.Fatal("expected session key to remain until chunked response ends")
	}

	store.Response[key].Append([]byte("0\r\n\r\n"), newTestEventInfo(250, len("0\r\n\r\n")))
	store.parseResponse(respChan)

	resp := mustReadResponse(t, respChan)
	if resp.SessionKey != req.SessionKey {
		t.Fatalf("response session key = %q, want %q", resp.SessionKey, req.SessionKey)
	}
	if string(resp.Body) != "data: hello\n\n" {
		t.Fatalf("response body = %q, want %q", resp.Body, "data: hello\\n\\n")
	}
	if hasSession(store, scope) {
		t.Fatal("expected session key to be released after final chunk")
	}
}

func TestSSLStoreHTTP2SessionKeyPerStream(t *testing.T) {
	t.Parallel()

	store := NewSSLStore()
	key := SSLKey{
		PidTgid:  42,
		UidGid:   84,
		SSLPtr:   126,
		CgroupID: 168,
	}
	reqChan := make(chan *export.RawRequest, 2)
	respChan := make(chan *export.RawResponse, 2)
	postgresChan := make(chan *export.RawPostgres, 1)

	store.Request[key] = newTestSSLRecord(http2RequestBytes(t), 100)
	store.parseRequest(reqChan, postgresChan)
	store.parseRequest(reqChan, postgresChan)

	firstReq := mustReadRequest(t, reqChan)
	secondReq := mustReadRequest(t, reqChan)
	requestSessions := map[string]string{
		firstReq.URL:  firstReq.SessionKey,
		secondReq.URL: secondReq.SessionKey,
	}
	if requestSessions["https://example.com/fast"] == "" || requestSessions["https://example.com/slow"] == "" {
		t.Fatalf("unexpected HTTP/2 request sessions: %#v", requestSessions)
	}
	if requestSessions["https://example.com/fast"] == requestSessions["https://example.com/slow"] {
		t.Fatal("expected distinct session keys for concurrent HTTP/2 streams")
	}

	store.Response[key] = newTestSSLRecord(http2ResponseBytes(t), 200)
	store.parseResponse(respChan)
	store.parseResponse(respChan)

	firstResp := mustReadResponse(t, respChan)
	secondResp := mustReadResponse(t, respChan)
	if firstResp.StatusCode != http.StatusCreated || string(firstResp.Body) != "fast" {
		t.Fatalf("unexpected first response: status=%d body=%q", firstResp.StatusCode, firstResp.Body)
	}
	if secondResp.StatusCode != http.StatusOK || string(secondResp.Body) != "slow" {
		t.Fatalf("unexpected second response: status=%d body=%q", secondResp.StatusCode, secondResp.Body)
	}
	if firstResp.SessionKey != requestSessions["https://example.com/fast"] {
		t.Fatalf("fast response session key = %q, want %q", firstResp.SessionKey, requestSessions["https://example.com/fast"])
	}
	if secondResp.SessionKey != requestSessions["https://example.com/slow"] {
		t.Fatalf("slow response session key = %q, want %q", secondResp.SessionKey, requestSessions["https://example.com/slow"])
	}
	if hasSession(store, sessionScopeForKey(key, 1)) {
		t.Fatal("expected stream 1 session key to be released")
	}
	if hasSession(store, sessionScopeForKey(key, 3)) {
		t.Fatal("expected stream 3 session key to be released")
	}
}

func TestSSLStoreHTTP2SSESessionLifecycle(t *testing.T) {
	t.Parallel()

	store := NewSSLStore()
	key := SSLKey{
		PidTgid:  420,
		UidGid:   840,
		SSLPtr:   1260,
		CgroupID: 1680,
	}
	scope := sessionScopeForKey(key, 1)
	reqChan := make(chan *export.RawRequest, 1)
	respChan := make(chan *export.RawResponse, 1)
	postgresChan := make(chan *export.RawPostgres, 1)

	store.Request[key] = newTestSSLRecord(http2SSERequestBytes(t), 100)
	store.parseRequest(reqChan, postgresChan)

	req := mustReadRequest(t, reqChan)
	if req.SessionKey == "" {
		t.Fatal("expected request session key")
	}

	store.Response[key] = newTestSSLRecord(http2SSEInitialResponseBytes(t), 200)
	store.parseResponse(respChan)

	select {
	case resp := <-respChan:
		t.Fatalf("unexpected HTTP/2 SSE response before END_STREAM: %+v", resp)
	default:
	}
	if !hasSession(store, scope) {
		t.Fatal("expected session key to remain until HTTP/2 stream ends")
	}

	finalData := http2SSEFinalDataBytes(t)
	store.Response[key].Append(finalData, newTestEventInfo(250, len(finalData)))
	store.parseResponse(respChan)

	resp := mustReadResponse(t, respChan)
	if resp.SessionKey != req.SessionKey {
		t.Fatalf("response session key = %q, want %q", resp.SessionKey, req.SessionKey)
	}
	if string(resp.Body) != "data: one\n\ndata: two\n\n" {
		t.Fatalf("response body = %q, want %q", resp.Body, "data: one\\n\\ndata: two\\n\\n")
	}
	if hasSession(store, scope) {
		t.Fatal("expected session key to be released after HTTP/2 END_STREAM")
	}
}

func TestSSLStoreSessionKeyExpiresWithoutResponse(t *testing.T) {
	t.Parallel()

	store := NewSSLStore()
	store.sessionTTL = 20 * time.Millisecond
	key := SSLKey{
		PidTgid:  11,
		UidGid:   22,
		SSLPtr:   33,
		CgroupID: 44,
	}
	scope := sessionScopeForKey(key, 0)

	sessionKey := store.ensureSessionKey(scope)
	if sessionKey == "" {
		t.Fatal("expected session key")
	}

	time.Sleep(50 * time.Millisecond)
	store.sessions.CleanUp()
	if hasSession(store, scope) {
		t.Fatal("expected session key to expire without response")
	}
	store.sessionScopesForConn(key)
	if hasIndexedSessionScope(store, scope) {
		t.Fatal("expected expired session key to be removed from the connection index")
	}
}

func TestSSLStoreCleanupStaleRecords(t *testing.T) {
	t.Parallel()

	store := NewSSLStore()
	store.recordTTL = time.Second
	key := SSLKey{
		PidTgid:  55,
		UidGid:   66,
		SSLPtr:   77,
		CgroupID: 88,
	}
	scope := sessionScopeForKey(key, 1)
	staleAt := time.Now().Add(-2 * time.Second)

	store.Request[key] = &SSLRecord{
		Stream:      []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Info:        []*EventInfo{newTestEventInfo(1, 37)},
		LastTouched: staleAt,
	}
	store.Response[key] = &SSLRecord{
		Stream:      http2ResponseBytes(t),
		Info:        []*EventInfo{newTestEventInfo(2, len(http2ResponseBytes(t)))},
		LastTouched: staleAt,
	}
	store.ensureSessionKey(scope)

	store.cleanupStaleRequestRecords(time.Now())
	if _, ok := store.Request[key]; ok {
		t.Fatal("expected stale request record to be evicted")
	}
	if !hasSession(store, scope) {
		t.Fatal("expected request cleanup to keep session keys intact")
	}

	store.cleanupStaleResponseRecords(time.Now())
	if _, ok := store.Response[key]; ok {
		t.Fatal("expected stale response record to be evicted")
	}
	if hasSession(store, scope) {
		t.Fatal("expected stale response cleanup to remove session keys")
	}
	if hasIndexedSessionScope(store, scope) {
		t.Fatal("expected stale response cleanup to remove indexed session scopes")
	}
}

func TestSSLStoreDeleteConnectionSessionsKeepsOtherConnections(t *testing.T) {
	t.Parallel()

	store := NewSSLStore()
	keyA := SSLKey{PidTgid: 1, UidGid: 2, SSLPtr: 3, CgroupID: 4}
	keyB := SSLKey{PidTgid: 5, UidGid: 6, SSLPtr: 7, CgroupID: 8}
	scopeA := sessionScopeForKey(keyA, 1)
	scopeB := sessionScopeForKey(keyB, 1)

	store.ensureSessionKey(scopeA)
	store.ensureSessionKey(scopeB)
	store.deleteConnectionSessions(keyA)

	if hasSession(store, scopeA) {
		t.Fatal("expected connection A sessions to be removed")
	}
	if hasSession(store, scopeB) == false {
		t.Fatal("expected connection B sessions to remain")
	}
	if hasIndexedSessionScope(store, scopeA) {
		t.Fatal("expected connection A session scope to be removed from the index")
	}
	if !hasIndexedSessionScope(store, scopeB) {
		t.Fatal("expected connection B session scope to remain indexed")
	}
}

func http2RequestBytes(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	buf.Write(HTTP2Preface)
	framer := http2.NewFramer(&buf, nil)

	writeHTTP2Headers(t, framer, 1, false, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/slow"},
	})
	writeHTTP2Headers(t, framer, 3, true, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/fast"},
	})
	writeHTTP2Data(t, framer, 1, true, []byte("slow"))

	return buf.Bytes()
}

func http2ResponseBytes(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	framer := http2.NewFramer(&buf, nil)

	writeHTTP2Headers(t, framer, 1, false, []hpack.HeaderField{
		{Name: ":status", Value: "200"},
	})
	writeHTTP2Headers(t, framer, 3, false, []hpack.HeaderField{
		{Name: ":status", Value: "201"},
	})
	writeHTTP2Data(t, framer, 3, true, []byte("fast"))
	writeHTTP2Data(t, framer, 1, true, []byte("slow"))

	return buf.Bytes()
}

func http2SSERequestBytes(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	buf.Write(HTTP2Preface)
	framer := http2.NewFramer(&buf, nil)

	writeHTTP2Headers(t, framer, 1, true, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/events"},
	})

	return buf.Bytes()
}

func http2SSEInitialResponseBytes(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	framer := http2.NewFramer(&buf, nil)

	writeHTTP2Headers(t, framer, 1, false, []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/event-stream"},
	})
	writeHTTP2Data(t, framer, 1, false, []byte("data: one\n\n"))

	return buf.Bytes()
}

func http2SSEFinalDataBytes(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	framer := http2.NewFramer(&buf, nil)
	writeHTTP2Data(t, framer, 1, true, []byte("data: two\n\n"))
	return buf.Bytes()
}

func writeHTTP2Headers(t *testing.T, framer *http2.Framer, streamID uint32, endStream bool, headers []hpack.HeaderField) {
	t.Helper()

	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, header := range headers {
		if err := encoder.WriteField(header); err != nil {
			t.Fatalf("WriteField() error = %v", err)
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: block.Bytes(),
		EndHeaders:    true,
		EndStream:     endStream,
	}); err != nil {
		t.Fatalf("WriteHeaders() error = %v", err)
	}
}

func writeHTTP2Data(t *testing.T, framer *http2.Framer, streamID uint32, endStream bool, data []byte) {
	t.Helper()

	if err := framer.WriteData(streamID, endStream, data); err != nil {
		t.Fatalf("WriteData() error = %v", err)
	}
}

func newTestSSLRecordFromString(stream string, timestamp uint64) *SSLRecord {
	return newTestSSLRecord([]byte(stream), timestamp)
}

func newTestSSLRecord(stream []byte, timestamp uint64) *SSLRecord {
	return &SSLRecord{
		Stream:      stream,
		LastTouched: time.Now(),
		Info: []*EventInfo{
			newTestEventInfo(timestamp, len(stream)),
		},
	}
}

func hasSession(store *SSLStore, scope SessionScope) bool {
	_, ok := store.sessions.GetIfPresent(scope)
	return ok
}

func hasIndexedSessionScope(store *SSLStore, scope SessionScope) bool {
	store.sessionMu.Lock()
	defer store.sessionMu.Unlock()

	scopes, ok := store.sessionScopes[scope.Conn]
	if !ok {
		return false
	}
	_, ok = scopes[scope]
	return ok
}

func newTestEventInfo(timestamp uint64, dataLen int) *EventInfo {
	var eventComm [16]int8
	for i, b := range []byte("curl") {
		if i >= len(eventComm) {
			break
		}
		eventComm[i] = int8(b)
	}
	return &EventInfo{
		TimestampNs: timestamp,
		DataLen:     uint64(dataLen),
		Comm:        eventComm,
	}
}

func mustReadRequest(t *testing.T, channel <-chan *export.RawRequest) *export.RawRequest {
	t.Helper()

	select {
	case req := <-channel:
		if req == nil {
			t.Fatal("request channel returned nil")
		}
		return req
	default:
		t.Fatal("expected request event")
		return nil
	}
}

func mustReadResponse(t *testing.T, channel <-chan *export.RawResponse) *export.RawResponse {
	t.Helper()

	select {
	case resp := <-channel:
		if resp == nil {
			t.Fatal("response channel returned nil")
		}
		return resp
	default:
		t.Fatal("expected response event")
		return nil
	}
}
