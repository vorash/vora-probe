package intake

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vorash/vora-probe/investigation"
)

// The incident log.
//
// Intake's state is an append-only JSONL file of changes, replayed on start
// through the same apply that live changes use, so a restarted server rebuilds
// exactly the state it had: the same incidents, the same open groups, the same
// dedupe keys. A change is written and synced before it is applied, so nothing
// is acknowledged that is not on disk.

type changeKind string

const (
	changeOpened        changeKind = "opened"
	changeDuplicate     changeKind = "duplicate"
	changeResolved      changeKind = "resolved"
	changeHeartbeat     changeKind = "heartbeat"
	changeUnmapped      changeKind = "unmapped"
	changeInvestigation changeKind = "investigation"
	changePost          changeKind = "post"

	changeForecastOpened  changeKind = "forecast_opened"
	changeForecastRevised changeKind = "forecast_revised"
	changeForecastClosed  changeKind = "forecast_closed"
)

// change is one line of the log.
type change struct {
	Kind          changeKind                   `json:"kind"`
	At            time.Time                    `json:"at"`
	ID            string                       `json:"id,omitempty"`
	Record        *Record                      `json:"record,omitempty"`
	Delivery      *Delivery                    `json:"delivery,omitempty"`
	Investigation *Investigation               `json:"investigation,omitempty"`
	Status        investigation.IncidentStatus `json:"incident_status,omitempty"`
	Post          *Post                        `json:"post,omitempty"`
	Forecast      *investigation.Forecast      `json:"forecast,omitempty"`
	Closed        string                       `json:"closed,omitempty"`
	Reason        string                       `json:"reason,omitempty"`
}

// commit writes a change, when there is a log, and then applies it. The caller
// holds in.mu.
func (in *Intake) commit(c change) error {
	if in.log != nil {
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if _, err := in.log.Write(append(raw, '\n')); err != nil {
			return fmt.Errorf("incident log: %w", err)
		}
		if err := in.log.Sync(); err != nil {
			return fmt.Errorf("incident log: %w", err)
		}
	}
	return in.apply(c)
}

// apply is the only code that changes intake's state.
func (in *Intake) apply(c change) error {
	record := func() (*Record, error) {
		r, ok := in.byID[c.ID]
		if !ok {
			return nil, fmt.Errorf("%s change for unknown incident %q", c.Kind, c.ID)
		}
		return r, nil
	}
	switch c.Kind {
	case changeOpened, changeForecastOpened:
		if c.Record == nil {
			return fmt.Errorf("%s change without a record", c.Kind)
		}
		r := c.Record
		in.records = append(in.records, r)
		in.byID[r.Incident.ID] = r
		in.byFingerprint[r.Fingerprint] = r
		in.openByGroup[r.GroupKey] = r
	case changeDuplicate:
		r, err := record()
		if err != nil {
			return err
		}
		r.UpdatedAt = c.At
		r.Notifications = append(r.Notifications, *c.Delivery)
	case changeResolved:
		r, err := record()
		if err != nil {
			return err
		}
		at := c.At
		r.Alert = AlertResolved
		r.ResolvedAt = &at
		r.UpdatedAt = at
		r.Notifications = append(r.Notifications, *c.Delivery)
		if in.openByGroup[r.GroupKey] == r {
			delete(in.openByGroup, r.GroupKey)
		}
	case changeHeartbeat:
		in.heartbeats++
		in.lastHeartbeat = c.At
	case changeUnmapped:
		in.unmapped = append(in.unmapped, *c.Delivery)
	case changeInvestigation:
		r, err := record()
		if err != nil {
			return err
		}
		r.Investigation = *c.Investigation
		if c.Status != "" {
			r.Incident.Status = c.Status
		}
	case changePost:
		r, err := record()
		if err != nil {
			return err
		}
		post := *c.Post
		r.Post = &post
	case changeForecastRevised:
		r, err := record()
		if err != nil {
			return err
		}
		if r.Forecast == nil || c.Forecast == nil {
			return fmt.Errorf("forecast revision for %s, which is not a forecast", c.ID)
		}
		r.Forecast.Current = *c.Forecast
		r.Forecast.Revisions++
		r.UpdatedAt = c.At
	case changeForecastClosed:
		r, err := record()
		if err != nil {
			return err
		}
		if r.Forecast == nil {
			return fmt.Errorf("forecast closure for %s, which is not a forecast", c.ID)
		}
		at := c.At
		r.Forecast.Closed, r.Forecast.ClosedAt, r.Forecast.Reason = c.Closed, &at, c.Reason
		r.Alert, r.ResolvedAt, r.UpdatedAt = AlertResolved, &at, at
		if in.openByGroup[r.GroupKey] == r {
			delete(in.openByGroup, r.GroupKey)
		}
	default:
		return fmt.Errorf("unknown change kind %q", c.Kind)
	}
	return nil
}

// Open is intake backed by the log at path, which is created if absent and
// replayed if present. The log is locked for as long as intake is open: two
// servers appending to one log would interleave two histories.
func Open(cfg Config, path string) (*Intake, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another server holds the incident log %s: %w", path, err)
	}
	in := New(cfg)
	if err := in.replay(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("incident log %s: %w", path, err)
	}
	in.log = f
	return in, nil
}

// replay applies every complete line and positions the file for appending. A
// final line without its newline is a write the process did not finish; it was
// never acknowledged, so it is cut off. Anything unreadable before that is
// corruption, and the log is refused rather than silently shortened.
func (in *Intake) replay(f *os.File) error {
	raw, err := os.ReadFile(f.Name())
	if err != nil {
		return err
	}
	complete := raw
	if i := bytes.LastIndexByte(raw, '\n'); i < len(raw)-1 {
		complete = raw[:i+1]
		if err := f.Truncate(int64(len(complete))); err != nil {
			return fmt.Errorf("cut off the unfinished final line: %w", err)
		}
	}
	for n, line := range bytes.Split(complete, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var c change
		if err := json.Unmarshal(line, &c); err != nil {
			return fmt.Errorf("line %d is not a change: %w", n+1, err)
		}
		if err := in.apply(c); err != nil {
			return fmt.Errorf("line %d: %w", n+1, err)
		}
	}
	_, err = f.Seek(0, 2)
	return err
}

// Close releases the log.
func (in *Intake) Close() error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.log == nil {
		return nil
	}
	err := in.log.Close()
	in.log = nil
	return err
}
