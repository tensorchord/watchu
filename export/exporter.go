package export

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/phuslu/log"
)

const (
	pathExec       = "exec_event"
	pathRequest    = "http_request"
	pathResponse   = "http_response"
	pathStdIO      = "mcp_stdio"
	pathPostgres   = "pg_event"
	pathFileOp     = "file_op"
	pathTCPConnect = "tcp_connect"
	pathAgentEvent = "agent_event"

	flushInterval     = time.Second
	maxBatchSize      = 1024
	ExportChannelSize = 4096
)

type RawRecord interface {
	ToRecord(ctx context.Context, host string) any
}

type Exporter struct {
	Host string
	sink Sink
}

func NewExporter(ctx context.Context, target string) (*Exporter, error) {
	sink, err := NewSink(ctx, target)
	if err != nil {
		return nil, err
	}
	return &Exporter{
		Host: GetHostName(),
		sink: sink,
	}, nil
}

func (e *Exporter) Close() error {
	if e == nil || e.sink == nil {
		return nil
	}
	return e.sink.Close()
}

func (e *Exporter) IngestEvents(ctx context.Context, endpoint string, producer func() ([]any, bool)) {
	ticker := time.NewTicker(flushInterval)

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			events, open := producer()
			if len(events) > 0 {
				if err := e.sink.WriteBatch(ctx, endpoint, events); err != nil {
					log.Error().
						Err(err).
						Str("endpoint", endpoint).
						Int("count", len(events)).
						Msg("failed to export batch, dropping batch")
				}
			}
			if !open {
				ticker.Stop()
				return
			}
		}
	}
}

func (e *Exporter) IngestExecEvent(ctx context.Context, channel <-chan *RawExec) {
	e.IngestEvents(ctx, pathExec, consumeFromChannel(ctx, e.Host, channel))
}

func (e *Exporter) IngestRequestEvent(ctx context.Context, channel <-chan *RawRequest) {
	e.IngestEvents(ctx, pathRequest, consumeFromChannel(ctx, e.Host, channel))
}

func (e *Exporter) IngestResponseEvent(ctx context.Context, channel <-chan *RawResponse) {
	e.IngestEvents(ctx, pathResponse, consumeFromChannel(ctx, e.Host, channel))
}

func (e *Exporter) IngestStdIOEvent(ctx context.Context, channel <-chan *RawStdIO) {
	e.IngestEvents(ctx, pathStdIO, consumeFromChannel(ctx, e.Host, channel))
}

func (e *Exporter) IngestPostgresEvent(ctx context.Context, channel <-chan *RawPostgres) {
	e.IngestEvents(ctx, pathPostgres, consumeFromChannel(ctx, e.Host, channel))
}

func (e *Exporter) IngestFileOpEvent(ctx context.Context, channel <-chan *RawFileOp) {
	e.IngestEvents(ctx, pathFileOp, consumeFromChannel(ctx, e.Host, channel))
}

func (e *Exporter) IngestTCPConnectEvent(ctx context.Context, channel <-chan *RawTCPConnect) {
	e.IngestEvents(ctx, pathTCPConnect, consumeFromChannel(ctx, e.Host, channel))
}

func (e *Exporter) IngestAgentEvent(ctx context.Context, channel <-chan *RecordAgentEvent) {
	e.IngestEvents(ctx, pathAgentEvent, consumeFromChannel(ctx, e.Host, channel))
}

func GetHostName() string {
	// prefer Kubernetes Downward API
	if podUID := os.Getenv("POD_UID"); podUID != "" {
		return podUID
	}
	if podName := os.Getenv("POD_NAME"); podName != "" {
		ns := os.Getenv("POD_NAMESPACE")
		if ns == "" {
			ns = "default"
		}
		return fmt.Sprintf("%s/%s", ns, podName)
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return fmt.Sprintf("host:%s", host)
	}
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return fmt.Sprintf("unknown-host-%d", time.Now().UnixNano())
}

func consumeFromChannel[R RawRecord](ctx context.Context, host string, channel <-chan R) func() ([]any, bool) {
	return func() ([]any, bool) {
		events := make([]any, 0, maxBatchSize)
		for len(events) < maxBatchSize {
			select {
			case raw, ok := <-channel:
				if !ok {
					return events, false
				}
				record := raw.ToRecord(ctx, host)
				if record != nil {
					events = append(events, record)
				}
			default:
				return events, true
			}
		}
		return events, true
	}
}
