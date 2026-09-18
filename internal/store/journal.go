// Package store persists an investigation.
//
// Two properties matter more than the storage format. The journal is append-only
// and requests are written before execution while results are written before the
// next step, so a missing result reads as an interruption rather than as a
// success. And only one investigation may be active at a time, enforced by a
// lock file rather than by convention.
package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type EventKind string

const (
	EventRunStarted  EventKind = "run_started"
	EventRequest     EventKind = "request"
	EventResult      EventKind = "result"
	EventObservation EventKind = "observation"
	EventDecision    EventKind = "decision"
	EventRunFinished EventKind = "run_finished"
)

// Event is one append-only journal entry. Sequence numbers are assigned by the
// journal so the order on disk is the order of events.
type Event struct {
	Seq        int             `json:"seq"`
	At         time.Time       `json:"at"`
	RunID      string          `json:"run_id"`
	IncidentID string          `json:"incident_id"`
	Step       int             `json:"step"`
	Kind       EventKind       `json:"kind"`
	Target     string          `json:"target,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

// Journal is an append-only event log. Writes are flushed and synced, because
// the whole point of the log is to survive the process that wrote it.
type Journal struct {
	mu   sync.Mutex
	path string
	file *os.File
	seq  int
}

func OpenJournal(dir, runID string) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, runID+".journal.jsonl")
	// A resumed run must continue the sequence rather than restart it, or a
	// recovered journal would contain two entries numbered 1.
	seq, err := lastSequence(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Journal{path: path, file: f, seq: seq}, nil
}

func lastSequence(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	seq := 0
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			// A torn final line is exactly what an interrupted run leaves behind.
			// Stop here rather than refusing to reopen the journal.
			break
		}
		if e.Seq > seq {
			seq = e.Seq
		}
	}
	return seq, nil
}

func (j *Journal) Path() string { return j.path }

func (j *Journal) Append(e Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.seq++
	e.Seq = j.seq
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := j.file.Write(append(raw, '\n')); err != nil {
		return err
	}
	return j.file.Sync()
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	return err
}

// Lock enforces one active investigation at a time. It uses flock so the lock is
// released even if the process dies, which is exactly the failure mode this
// guards against.
type Lock struct {
	file *os.File
	path string
}

func AcquireLock(dir, name string) (*Lock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another investigation holds %s: %w", path, err)
	}
	if _, err := f.WriteString(fmt.Sprintf("%d\n", os.Getpid())); err != nil {
		f.Close()
		return nil, err
	}
	return &Lock{file: f, path: path}, nil
}

func (l *Lock) Release() error {
	if l.file == nil {
		return nil
	}
	err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	if cerr := l.file.Close(); err == nil {
		err = cerr
	}
	l.file = nil
	return err
}

// WriteArtifact writes a report artifact with owner-only permissions. Live
// artifacts are ignored by git and are never a source of truth: the fixtures are.
func WriteArtifact(dir, name string, content []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return "", err
	}
	return path, nil
}
