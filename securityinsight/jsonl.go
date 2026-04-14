package securityinsight

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tensorchord/watchu/export"
)

const (
	endpointExec       = "exec_event"
	endpointRequest    = "http_request"
	endpointResponse   = "http_response"
	endpointStdIO      = "mcp_stdio"
	endpointPostgres   = "pg_event"
	endpointFileOp     = "file_op"
	endpointTCPConnect = "tcp_connect"
	endpointAgentEvent = "agent_event"
)

// jsonlEnvelope mirrors export.JSONLRecord but decodes Event as raw JSON.
type jsonlEnvelope struct {
	Endpoint  string          `json:"endpoint"`
	Timestamp time.Time       `json:"timestamp"`
	Event     json.RawMessage `json:"event"`
}

// EventStore holds all parsed events from one or more JSONL files.
type EventStore struct {
	ExecEvents []export.RecordExec
	Requests   []export.RecordRequest
	Responses  []export.RecordResponse
	StdIO      []export.RecordStdIO
	Postgres   []export.RecordPostgres
	FileOps    []export.RecordFileOp
	TCPConns   []export.RecordTCPConnect
	AgentEvts  []export.RecordAgentEvent
}

// LoadEvents reads one or more JSONL files matching the given glob pattern
// and returns an EventStore. Malformed lines are counted but do not terminate
// the load; they are reported as a warning in the returned error count.
func LoadEvents(pattern string) (*EventStore, int, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid glob pattern %q: %w", pattern, err)
	}
	if len(matches) == 0 {
		return nil, 0, fmt.Errorf("no files matched pattern %q", pattern)
	}

	store := &EventStore{}
	malformed := 0

	for _, path := range matches {
		n, err := loadFile(path, store)
		malformed += n
		if err != nil {
			return nil, malformed, fmt.Errorf("load %s: %w", path, err)
		}
	}
	return store, malformed, nil
}

func loadFile(path string, store *EventStore) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	malformed := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var env jsonlEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			malformed++
			continue
		}

		switch env.Endpoint {
		case endpointExec:
			var rec export.RecordExec
			if json.Unmarshal(env.Event, &rec) == nil {
				store.ExecEvents = append(store.ExecEvents, rec)
			} else {
				malformed++
			}
		case endpointRequest:
			var rec export.RecordRequest
			if json.Unmarshal(env.Event, &rec) == nil {
				store.Requests = append(store.Requests, rec)
			} else {
				malformed++
			}
		case endpointResponse:
			var rec export.RecordResponse
			if json.Unmarshal(env.Event, &rec) == nil {
				store.Responses = append(store.Responses, rec)
			} else {
				malformed++
			}
		case endpointStdIO:
			var rec export.RecordStdIO
			if json.Unmarshal(env.Event, &rec) == nil {
				store.StdIO = append(store.StdIO, rec)
			} else {
				malformed++
			}
		case endpointPostgres:
			var rec export.RecordPostgres
			if json.Unmarshal(env.Event, &rec) == nil {
				store.Postgres = append(store.Postgres, rec)
			} else {
				malformed++
			}
		case endpointFileOp:
			var rec export.RecordFileOp
			if json.Unmarshal(env.Event, &rec) == nil {
				store.FileOps = append(store.FileOps, rec)
			} else {
				malformed++
			}
		case endpointTCPConnect:
			var rec export.RecordTCPConnect
			if json.Unmarshal(env.Event, &rec) == nil {
				store.TCPConns = append(store.TCPConns, rec)
			} else {
				malformed++
			}
		case endpointAgentEvent:
			var rec export.RecordAgentEvent
			if json.Unmarshal(env.Event, &rec) == nil {
				store.AgentEvts = append(store.AgentEvts, rec)
			} else {
				malformed++
			}
		default:
			// unknown endpoint, skip
		}
	}
	return malformed, scanner.Err()
}
