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

func buildAllTabAnnotations(records []displayRecord) []pairLineAnnotation {
	annotations := make([]pairLineAnnotation, len(records))
	pairs, maxLevel := buildSessionPairs(records)
	if len(pairs) == 0 || maxLevel == 0 {
		return annotations
	}

	for idx := range records {
		line := pairLineAnnotation{
			Columns: make([]pairLinkKind, maxLevel),
		}
		for _, pair := range pairs {
			if idx < pair.Start || idx > pair.End {
				continue
			}
			if pair.Start < idx && idx < pair.End {
				line.Columns[pair.Level] = pairLinkPipe
				continue
			}
			line.Columns[pair.Level] = pairLinkDot
		}
		annotations[idx] = line
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
