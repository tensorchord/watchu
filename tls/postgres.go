package tls

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"

	"github.com/phuslu/log"
)

const PostgresProtoRequest string = "Postgres"

type PostgresParser struct{}

func parsePostgresStatement(record *SSLRecord) (*bytes.Buffer, uint8, uint32) {
	if len(record.Stream) < 5 {
		// not enough
		record.EndOfStream = false
		return nil, 0, 0
	}
	tag := record.Stream[0]
	length := binary.BigEndian.Uint32(record.Stream[1:5])
	if length < 4 || length > uint32(len(record.Stream)-1) {
		// not enough
		record.EndOfStream = false
		return nil, 0, 0
	}
	var body bytes.Buffer
	body.Write(record.Stream[5 : length+1])
	return &body, tag, length + 1
}

func (pp *PostgresParser) ParseRequest(record *SSLRecord) (*ParsedRequest, int, error) {
	body, tag, length := parsePostgresStatement(record)
	var req *ParsedRequest
	// only collect useful postgres events
	if body != nil && (tag == 'Q' || tag == 'P' || tag == 'B' || tag == 'E') {
		req = &ParsedRequest{
			Request: &http.Request{
				Method:        string(tag),
				Proto:         PostgresProtoRequest,
				ProtoMajor:    3,
				Body:          io.NopCloser(body),
				ContentLength: int64(length - 5),
			},
		}
	}
	record.EndOfStream = true
	return req, int(length), nil
}

func (pp *PostgresParser) ParseResponse(record *SSLRecord) (*ParsedResponse, int, error) {
	_, tag, length := parsePostgresStatement(record)
	log.Trace().Byte("tag", tag).Msg("ignored Postgres response tag")
	record.EndOfStream = true
	return nil, int(length), nil
}
