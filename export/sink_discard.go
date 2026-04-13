package export

import (
	"context"

	"github.com/phuslu/log"
)

type DiscardSink struct{}

func NewDiscardSink() *DiscardSink {
	log.Info().Msg("event export is disabled, batches will be discarded")
	return &DiscardSink{}
}

func (s *DiscardSink) WriteBatch(_ context.Context, _ string, _ []any) error {
	return nil
}

func (s *DiscardSink) Close() error {
	return nil
}
