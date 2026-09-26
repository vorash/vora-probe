package gateway

import (
	"encoding/json"
	"strings"
	"time"
)

// Logs as a closed action (vorash/vora-probe#13, P2.1).
//
// A model never writes a log query. It names one filter from a closed set, and
// the adapter builds the query from a fixed stream selector (the entity, in the
// configured namespace) plus that filter's fixed line matcher. Free-form LogQL
// would turn the gateway into an arbitrary search surface over the most
// secret-laden data an incident has.

// ActionLogsQuery counts and returns the log lines matching one filter for an
// entity over a window.
const ActionLogsQuery ActionKind = "logs.query"

// LogFilters is the closed set of filters, each a fixed case-insensitive line
// matcher.
var LogFilters = map[string]string{
	"error":         `(?i)\b(error|exception)\b`,
	"out_of_memory": `(?i)(out of memory|oom|cannot allocate memory)`,
	"panic":         `(?i)\b(panic|fatal)\b`,
	"timeout":       `(?i)\b(timeout|timed out|deadline exceeded)\b`,
}

// LogFilterNames is LogFilters' names, sorted, for prompts and schemas.
func LogFilterNames() []string {
	names := make([]string, 0, len(LogFilters))
	for n := range LogFilters {
		names = append(names, n)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

func LogFilterAllowed(name string) bool { _, ok := LogFilters[name]; return ok }

// logSeverities are the alert severities an investigation may read logs for.
// Logs carry the highest risk of leaking secrets, so a low-severity incident,
// or one whose severity is unknown, is never offered them at all.
var logSeverities = []string{"critical", "high", "warning"}

// ActionsFor is the action set offered for an incident of the given severity:
// every allowed action, less logs.query unless the severity warrants it.
func ActionsFor(severity string) []ActionKind {
	logs := equalsOneOf(strings.ToLower(severity), logSeverities)
	out := make([]ActionKind, 0, len(AllowedActions))
	for _, k := range AllowedActions {
		if k == ActionLogsQuery && !logs {
			continue
		}
		out = append(out, k)
	}
	return out
}

// LogLines is the payload of logs.query. Total counts every match in the
// window; Lines holds at most the adapter's bound of them, and Truncated says
// when it holds fewer than Total.
type LogLines struct {
	Filter    string    `json:"filter"`
	Total     int       `json:"total"`
	Truncated bool      `json:"truncated"`
	Lines     []LogLine `json:"lines"`
}

type LogLine struct {
	At   time.Time `json:"at"`
	Line string    `json:"line"`
}

func (r Response) LogLines() (LogLines, error) {
	var v LogLines
	if err := r.decode(); err != nil {
		return v, err
	}
	return v, json.Unmarshal(r.Payload, &v)
}
