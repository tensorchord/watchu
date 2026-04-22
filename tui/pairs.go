package tui

import "sort"

type pairLinkKind uint8

const (
	pairLinkNone pairLinkKind = iota
	pairLinkDot
	pairLinkPipe
)

type pairInterval struct {
	Start int
	End   int
	Level int
}

type pairLineAnnotation struct {
	Columns []pairLinkKind
}

func buildVisiblePairAnnotations(start, end int, pairs []pairInterval, maxLevel int) []pairLineAnnotation {
	annotations := make([]pairLineAnnotation, max(0, end-start))
	if len(pairs) == 0 || maxLevel == 0 || end <= start {
		return annotations
	}
	for idx := range annotations {
		annotations[idx].Columns = make([]pairLinkKind, maxLevel)
	}

	for _, pair := range pairs {
		if pair.Start >= end {
			break
		}
		if pair.End < start {
			continue
		}

		lineStart := max(start, pair.Start)
		lineEnd := min(end-1, pair.End)
		for idx := lineStart; idx <= lineEnd; idx++ {
			line := &annotations[idx-start]
			line.Columns[pair.Level] = pairLinkPipe
			if idx == pair.Start || idx == pair.End {
				line.Columns[pair.Level] = pairLinkDot
			}
		}
	}

	return annotations
}

func buildSessionPairs(records []displayRecord) ([]pairInterval, int) {
	requestsBySession := make(map[string]int)
	pairs := make([]pairInterval, 0)

	for idx, record := range records {
		if record.SessionKey == "" {
			continue
		}
		switch record.Endpoint {
		case "http_request":
			requestsBySession[record.SessionKey] = idx
		case "http_response":
			start, ok := requestsBySession[record.SessionKey]
			if !ok || start >= idx {
				continue
			}
			pairs = append(pairs, pairInterval{Start: start, End: idx})
			delete(requestsBySession, record.SessionKey)
		}
	}
	if len(pairs) == 0 {
		return nil, 0
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Start == pairs[j].Start {
			return pairs[i].End < pairs[j].End
		}
		return pairs[i].Start < pairs[j].Start
	})

	activeEnds := make([]int, 0)
	maxLevel := 0
	for idx := range pairs {
		level := 0
		for ; level < len(activeEnds); level++ {
			if activeEnds[level] < pairs[idx].Start {
				break
			}
		}
		if level == len(activeEnds) {
			activeEnds = append(activeEnds, pairs[idx].End)
		} else {
			activeEnds[level] = pairs[idx].End
		}
		pairs[idx].Level = level
		if level+1 > maxLevel {
			maxLevel = level + 1
		}
	}

	return pairs, maxLevel
}
