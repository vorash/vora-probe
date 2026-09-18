package store_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/internal/store"
)

func TestJournalIsAppendOnlyAndOrdered(t *testing.T) {
	dir := t.TempDir()
	journal, err := store.OpenJournal(dir, "RUN-1")
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	at := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	for i := range 3 {
		if err := journal.Append(store.Event{RunID: "RUN-1", IncidentID: "INC-1", Kind: store.EventRequest, At: at, Payload: json.RawMessage(`{"i":1}`)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	path := journal.Path()
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("journal has %d lines, want 3", len(lines))
	}
	for i, line := range lines {
		var e store.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if e.Seq != i+1 {
			t.Fatalf("line %d has sequence %d, want %d", i, e.Seq, i+1)
		}
	}
}

// Reopening an existing journal must continue the sequence rather than restart
// it, otherwise a resumed run would produce two events with the same number.
func TestJournalContinuesSequenceAfterReopen(t *testing.T) {
	dir := t.TempDir()
	first, err := store.OpenJournal(dir, "RUN-1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := first.Append(store.Event{RunID: "RUN-1", Kind: store.EventRequest}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := store.OpenJournal(dir, "RUN-1")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()
	if err := second.Append(store.Event{RunID: "RUN-1", Kind: store.EventResult}); err != nil {
		t.Fatalf("append: %v", err)
	}

	raw, err := os.ReadFile(second.Path())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var last store.Event
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if err := json.Unmarshal([]byte(line), &last); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	if last.Seq != 2 {
		t.Fatalf("sequence after reopen = %d, want 2", last.Seq)
	}
}

func TestLockAllowsOnlyOneInvestigation(t *testing.T) {
	dir := t.TempDir()
	first, err := store.AcquireLock(dir, "probe")
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := store.AcquireLock(dir, "probe"); err == nil {
		t.Fatal("a second concurrent investigation must be refused")
	}
	if err := first.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	second, err := store.AcquireLock(dir, "probe")
	if err != nil {
		t.Fatalf("lock should be available after release: %v", err)
	}
	defer second.Release()
}

func TestArtifactsAreOwnerReadableOnly(t *testing.T) {
	dir := t.TempDir()
	path, err := store.WriteArtifact(dir, "report.json", []byte("{}\n"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("artifact permissions = %o, want 600", perm)
	}
	if filepath.Base(path) != "report.json" {
		t.Fatalf("artifact written to %s", path)
	}
}
