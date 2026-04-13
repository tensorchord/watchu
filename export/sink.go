package export

import (
	"context"
	"fmt"
	"strings"
)

type Sink interface {
	WriteBatch(ctx context.Context, endpoint string, events []any) error
	Close() error
}

func NewSink(ctx context.Context, target string) (Sink, error) {
	switch {
	case target == "":
		return NewDiscardSink(), nil
	case strings.HasPrefix(target, "http://"), strings.HasPrefix(target, "https://"):
		return NewGatewaySink(ctx, target)
	case strings.HasPrefix(target, "file://"):
		return NewJSONLSink(target)
	default:
		return nil, fmt.Errorf("invalid --export %q: must be empty, http[s]://, or file://", target)
	}
}
