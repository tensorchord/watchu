package export

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/phuslu/log"
)

type JSONLRecord struct {
	Endpoint  string    `json:"endpoint"`
	Timestamp time.Time `json:"timestamp"`
	Event     any       `json:"event"`
}

type JSONLSink struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

func NewJSONLSink(target string) (*JSONLSink, error) {
	path, err := FilePathFromTarget(target)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open export file %q: %w", path, err)
	}
	log.Info().Str("path", path).Msg("exporting events to local jsonl file")
	return &JSONLSink{
		file: file,
		enc:  json.NewEncoder(file),
	}, nil
}

func (s *JSONLSink) WriteBatch(_ context.Context, endpoint string, events []any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil || s.enc == nil {
		return fmt.Errorf("jsonl sink is closed")
	}

	now := time.Now().UTC()
	for _, event := range events {
		record := JSONLRecord{
			Endpoint:  endpoint,
			Timestamp: now,
			Event:     event,
		}
		if err := s.enc.Encode(record); err != nil {
			return fmt.Errorf("write jsonl record: %w", err)
		}
	}
	return nil
}

func (s *JSONLSink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	s.enc = nil
	return err
}

func FilePathFromTarget(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parse file export target %q: %w", target, err)
	}
	if u.Scheme != "file" {
		return "", fmt.Errorf("invalid file export target %q", target)
	}
	if u.Host != "" && u.Host != "localhost" {
		return "", fmt.Errorf("file export target must not include host %q", u.Host)
	}
	if u.Path == "" {
		return "", fmt.Errorf("file export target %q must include an absolute path", target)
	}
	path := filepath.Clean(u.Path)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("file export path %q must be absolute", path)
	}
	return path, nil
}
