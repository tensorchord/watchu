package export

import (
	"context"
	"encoding/json"
	"strconv"
	"syscall"
	"time"

	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/internal/container"
)

var (
	bootTime          = GetBootTime()
	containerResolver = container.NewContainerResolver()
)

// in the Linux kernel, `task_struct` contains `pid` & `tgid`, but the meaning
// is different from what we usually call for PID and TID
// - `pid` <=> TID (thread id)
// - `tgid` (thread group id) <=> PID (process id)
//
// refs:
// - https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
// - https://github.com/cilium/tetragon/blob/99bd58f27223743a7907db203577f4e7733f8021/bpf/process/bpf_execve_event.c#L286-L293
func extractPid(raw uint64) int32 {
	return int32(raw >> 32)
}

func extractTid(raw uint64) int32 {
	return int32(raw)
}

// https://docs.ebpf.io/linux/helper-function/bpf_get_current_uid_gid/
func extractUid(raw uint64) int32 {
	return int32(raw)
}

func extractGid(raw uint64) int32 {
	return int32(raw >> 32)
}

func GetBootTime() *time.Time {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		log.Fatal().Err(err).Msg("failed to get sysinfo")
	}
	uptime := time.Duration(info.Uptime) * time.Second
	bt := time.Now().Add(-uptime)
	return &bt
}

func parseElapsedToTimestamp(elapsed uint64) time.Time {
	return bootTime.Add(time.Duration(elapsed) * time.Nanosecond)
}

type RecordExec struct {
	Timestamp   time.Time `json:"timestamp"`
	Pid         int32     `json:"pid"`
	PPid        int32     `json:"ppid"`
	ExecId      string    `json:"exec_id"`
	PExecId     string    `json:"p_exec_id"`
	Cwd         string    `json:"cwd"`
	Comm        string    `json:"comm"`
	Args        string    `json:"args"`
	Host        string    `json:"host"`
	ContainerID string    `json:"container_id"`
}

type RecordRequest struct {
	Timestamp time.Time `json:"timestamp"`
	// SessionKey is a best-effort correlation key for an observed HTTP exchange.
	// It is normally created on the request side, but may be created on the response
	// side when the request was not successfully captured or emitted.
	SessionKey    string          `json:"session_key"`
	Pid           int32           `json:"pid"`
	Tid           int32           `json:"tid"`
	Uid           int32           `json:"uid"`
	Gid           int32           `json:"gid"`
	Comm          string          `json:"comm"`
	Method        string          `json:"method"`
	URL           string          `json:"url"`
	Protocol      string          `json:"protocol"`
	ContentLength int64           `json:"content_length"`
	Headers       json.RawMessage `json:"headers"`
	Body          []byte          `json:"body"`
	Truncated     bool            `json:"truncated"`
	Host          string          `json:"host"`
	ContainerID   string          `json:"container_id"`
}

type RecordResponse struct {
	Timestamp time.Time `json:"timestamp"`
	// SessionKey is a best-effort correlation key for an observed HTTP exchange.
	// A response may carry a SessionKey even when the matching request event was not emitted.
	SessionKey    string          `json:"session_key"`
	Pid           int32           `json:"pid"`
	Tid           int32           `json:"tid"`
	Uid           int32           `json:"uid"`
	Gid           int32           `json:"gid"`
	Comm          string          `json:"comm"`
	StatusCode    int32           `json:"status_code"`
	Protocol      string          `json:"protocol"`
	ContentLength int64           `json:"content_length"`
	Headers       json.RawMessage `json:"headers"`
	Body          []byte          `json:"body"`
	Truncated     bool            `json:"truncated"`
	Host          string          `json:"host"`
	ContainerID   string          `json:"container_id"`
}

type MCP struct {
	JSONRPC string          `json:"jsonrpc"`
	CorrID  int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
	Params  json.RawMessage `json:"params"`
	Method  string          `json:"method"`
}

type RecordStdIO struct {
	Timestamp   time.Time       `json:"timestamp"`
	Pid         int32           `json:"pid"`
	Tid         int32           `json:"tid"`
	Uid         int32           `json:"uid"`
	Gid         int32           `json:"gid"`
	Host        string          `json:"host"`
	ContainerID string          `json:"container_id"`
	MessageType string          `json:"message_type"`
	JSONRPC     string          `json:"jsonrpc"`
	Method      string          `json:"method"`
	Params      json.RawMessage `json:"params"`
	Result      json.RawMessage `json:"result"`
	Error       json.RawMessage `json:"error"`
	CorrID      string          `json:"corr_id"`
}

type RecordPostgres struct {
	Timestamp   time.Time `json:"timestamp"`
	Pid         int32     `json:"pid"`
	Tid         int32     `json:"tid"`
	Uid         int32     `json:"uid"`
	Gid         int32     `json:"gid"`
	Host        string    `json:"host"`
	ContainerID string    `json:"container_id"`
	Comm        string    `json:"comm"`
	Data        []byte    `json:"data"`
	MsgType     string    `json:"msg_type"`
}

type RecordFileOp struct {
	Timestamp   time.Time `json:"timestamp"`
	Pid         int32     `json:"pid"`
	Tid         int32     `json:"tid"`
	Uid         int32     `json:"uid"`
	Gid         int32     `json:"gid"`
	Host        string    `json:"host"`
	ContainerID string    `json:"container_id"`
	Comm        string    `json:"comm"`
	Op          string    `json:"op"`
	Access      string    `json:"access,omitempty"`
	Path        string    `json:"path"`
	NewPath     string    `json:"new_path,omitempty"`
	Bytes       uint64    `json:"bytes,omitempty"`
	Flags       uint64    `json:"flags,omitempty"`
	Create      bool      `json:"create,omitempty"`
	Truncate    bool      `json:"truncate,omitempty"`
	Append      bool      `json:"append,omitempty"`
}

type RecordTCPConnect struct {
	Timestamp   time.Time `json:"timestamp"`
	Pid         int32     `json:"pid"`
	Tid         int32     `json:"tid"`
	Uid         int32     `json:"uid"`
	Gid         int32     `json:"gid"`
	Host        string    `json:"host"`
	ContainerID string    `json:"container_id"`
	Comm        string    `json:"comm"`
	Family      uint16    `json:"family"`
	TargetAddr  string    `json:"target_addr"`
	TargetPort  uint16    `json:"target_port"`
}

type RawExec struct {
	Timestamp time.Time
	Pid       uint32
	PPid      uint32
	ExecId    string
	PExecId   string
	Cwd       string
	Comm      string
	Args      string
	Docker    string
}

type RawTCPConnect struct {
	ElapsedNs  uint64
	PidTGid    uint64
	UidGid     uint64
	CgroupID   uint64
	Comm       string
	Family     uint16
	TargetAddr string
	TargetPort uint16
}

func (raw *RawTCPConnect) ToRecord(ctx context.Context, host string) any {
	return RecordTCPConnect{
		Timestamp:   parseElapsedToTimestamp(raw.ElapsedNs),
		Pid:         extractPid(raw.PidTGid),
		Tid:         extractTid(raw.PidTGid),
		Uid:         extractUid(raw.UidGid),
		Gid:         extractGid(raw.UidGid),
		Host:        host,
		ContainerID: containerResolver.Resolve(ctx, raw.CgroupID),
		Comm:        raw.Comm,
		Family:      raw.Family,
		TargetAddr:  raw.TargetAddr,
		TargetPort:  raw.TargetPort,
	}
}

func (raw *RawExec) ToRecord(_ context.Context, host string) any {
	return RecordExec{
		Timestamp:   raw.Timestamp,
		Pid:         int32(raw.Pid),
		PPid:        int32(raw.PPid),
		ExecId:      raw.ExecId,
		PExecId:     raw.PExecId,
		Cwd:         raw.Cwd,
		Comm:        raw.Comm,
		Args:        raw.Args,
		Host:        host,
		ContainerID: raw.Docker,
	}
}

type RawRequest struct {
	ElapsedNs     uint64
	SessionKey    string
	PidTGid       uint64
	UidGid        uint64
	CgroupID      uint64
	Comm          string
	Method        string
	URL           string
	Protocol      string
	ContentLength int64
	Headers       map[string]string
	Body          []byte
	Truncated     bool
}

func (raw *RawRequest) ToRecord(ctx context.Context, host string) any {
	headers, err := json.Marshal(raw.Headers)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal req headers")
		return nil
	}

	return RecordRequest{
		Timestamp:     parseElapsedToTimestamp(raw.ElapsedNs),
		SessionKey:    raw.SessionKey,
		Pid:           extractPid(raw.PidTGid),
		Tid:           extractTid(raw.PidTGid),
		Uid:           extractUid(raw.UidGid),
		Gid:           extractGid(raw.UidGid),
		Comm:          raw.Comm,
		Method:        raw.Method,
		URL:           raw.URL,
		Protocol:      raw.Protocol,
		ContentLength: raw.ContentLength,
		Headers:       headers,
		Body:          raw.Body,
		Truncated:     raw.Truncated,
		Host:          host,
		ContainerID:   containerResolver.Resolve(ctx, raw.CgroupID),
	}
}

type RawResponse struct {
	ElapsedNs     uint64
	SessionKey    string
	PidTGid       uint64
	UidGid        uint64
	CgroupID      uint64
	Comm          string
	StatusCode    int
	Protocol      string
	ContentLength int64
	Headers       map[string]string
	Body          []byte
	Truncated     bool
}

func (raw *RawResponse) ToRecord(ctx context.Context, host string) any {
	headers, err := json.Marshal(raw.Headers)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal resp headers")
		return nil
	}
	return RecordResponse{
		Timestamp:     parseElapsedToTimestamp(raw.ElapsedNs),
		SessionKey:    raw.SessionKey,
		Pid:           extractPid(raw.PidTGid),
		Tid:           extractTid(raw.PidTGid),
		Uid:           extractUid(raw.UidGid),
		Gid:           extractGid(raw.UidGid),
		Comm:          raw.Comm,
		StatusCode:    int32(raw.StatusCode),
		Protocol:      raw.Protocol,
		ContentLength: raw.ContentLength,
		Headers:       headers,
		Body:          raw.Body,
		Truncated:     raw.Truncated,
		Host:          host,
		ContainerID:   containerResolver.Resolve(ctx, raw.CgroupID),
	}
}

type RawStdIO struct {
	ElapsedNs   uint64
	PidTGid     uint64
	UidGid      uint64
	CgroupID    uint64
	MessageType string
	Data        []byte
}

func (raw *RawStdIO) ToRecord(ctx context.Context, host string) any {
	var mcp MCP
	err := json.Unmarshal(raw.Data, &mcp)
	if err != nil {
		log.Error().Err(err).Bytes("data", raw.Data).Msg("failed to unmarshal mcp message")
		return nil
	}

	return RecordStdIO{
		Timestamp:   parseElapsedToTimestamp(raw.ElapsedNs),
		Pid:         extractPid(raw.PidTGid),
		Tid:         extractTid(raw.PidTGid),
		Uid:         extractUid(raw.UidGid),
		Gid:         extractGid(raw.UidGid),
		ContainerID: containerResolver.Resolve(ctx, raw.CgroupID),
		Host:        host,
		MessageType: raw.MessageType,
		JSONRPC:     mcp.JSONRPC,
		Method:      mcp.Method,
		Params:      mcp.Params,
		Result:      mcp.Result,
		Error:       mcp.Error,
		CorrID:      strconv.Itoa(mcp.CorrID),
	}
}

type RawPostgres struct {
	ElapsedNs uint64
	PidTGid   uint64
	UidGid    uint64
	CgroupID  uint64
	Comm      string
	MsgType   string
	Data      []byte
}

func (raw *RawPostgres) ToRecord(ctx context.Context, host string) any {
	return RecordPostgres{
		Timestamp:   parseElapsedToTimestamp(raw.ElapsedNs),
		Pid:         extractPid(raw.PidTGid),
		Tid:         extractTid(raw.PidTGid),
		Uid:         extractUid(raw.UidGid),
		Gid:         extractGid(raw.UidGid),
		Comm:        raw.Comm,
		Data:        raw.Data,
		MsgType:     raw.MsgType,
		Host:        host,
		ContainerID: containerResolver.Resolve(ctx, raw.CgroupID),
	}
}

type RawFileOp struct {
	ElapsedNs uint64
	PidTGid   uint64
	UidGid    uint64
	CgroupID  uint64
	Comm      string
	Op        string
	Access    string
	Path      string
	NewPath   string
	Bytes     uint64
	Flags     uint64
	Create    bool
	Truncate  bool
	Append    bool
}

func (raw *RawFileOp) ToRecord(ctx context.Context, host string) any {
	return RecordFileOp{
		Timestamp:   parseElapsedToTimestamp(raw.ElapsedNs),
		Pid:         extractPid(raw.PidTGid),
		Tid:         extractTid(raw.PidTGid),
		Uid:         extractUid(raw.UidGid),
		Gid:         extractGid(raw.UidGid),
		Host:        host,
		ContainerID: containerResolver.Resolve(ctx, raw.CgroupID),
		Comm:        raw.Comm,
		Op:          raw.Op,
		Access:      raw.Access,
		Path:        raw.Path,
		NewPath:     raw.NewPath,
		Bytes:       raw.Bytes,
		Flags:       raw.Flags,
		Create:      raw.Create,
		Truncate:    raw.Truncate,
		Append:      raw.Append,
	}
}

type RecordAgentEvent struct {
	Timestamp      time.Time       `json:"timestamp"`
	Tool           string          `json:"tool"`
	EventName      string          `json:"event_name"`
	EventType      string          `json:"event_type"`
	ConversationID string          `json:"conversation_id,omitempty"`
	SessionID      string          `json:"session_id,omitempty"`
	Model          string          `json:"model,omitempty"`
	Slug           string          `json:"slug,omitempty"`
	AppVersion     string          `json:"app_version,omitempty"`
	Host           string          `json:"host"`
	Attributes     json.RawMessage `json:"attributes"`

	Prompt       string `json:"prompt,omitempty"`
	PromptLength int64  `json:"prompt_length,omitempty"`

	ToolName   string `json:"tool_name,omitempty"`
	CallID     string `json:"call_id,omitempty"`
	Arguments  string `json:"arguments,omitempty"`
	Output     string `json:"output,omitempty"`
	Success    bool   `json:"success,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	Decision   string `json:"decision,omitempty"`

	StatusCode int64   `json:"status_code,omitempty"`
	CostUSD    float64 `json:"cost_usd,omitempty"`
	ErrorMsg   string  `json:"error,omitempty"`

	InputTokenCount     int64 `json:"input_token_count,omitempty"`
	OutputTokenCount    int64 `json:"output_token_count,omitempty"`
	CachedTokenCount    int64 `json:"cached_token_count,omitempty"`
	ReasoningTokenCount int64 `json:"reasoning_token_count,omitempty"`
}

func (r *RecordAgentEvent) ToRecord(_ context.Context, host string) any {
	r.Host = host
	return *r
}
