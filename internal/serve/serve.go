// Package serve runs investigations for incidents that arrive as alerts.
//
// Intake decides what an alert means; this package decides when, and whether,
// it is investigated. One worker takes incidents from a FIFO in arrival order,
// so there is never more than one investigation at a time, the same guarantee
// the CLI gets from its lock. Each investigation has a deadline, and whatever
// happens the incident's record says what became of it: queued, held back by a
// rate limit, running, concluded, not concluded, or failed before it could
// report.
package serve

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/internal/probe"
	"github.com/vorash/vora-probe/investigation"
)

// Investigator runs one investigation. It is probe.Run or probe.Investigate
// with their ports bound; the server does not know which.
type Investigator func(ctx context.Context, incident investigation.Incident) (probe.ReplayResult, error)

// Limits bound how many investigations one alert group, and one entity (pod or
// host), may start inside a rolling window. Dedupe stops a single firing from
// starting twice; these stop a flapping alert, or a host that trips many
// rules, from monopolising the only worker.
type Limits struct {
	Window    time.Duration
	PerGroup  int
	PerEntity int
}

func DefaultLimits() Limits {
	return Limits{Window: time.Hour, PerGroup: 3, PerEntity: 5}
}

type Config struct {
	Intake      *intake.Intake
	Investigate Investigator
	Limits      Limits
	// Timeout bounds one investigation on the wall clock. When it passes, the
	// run is closed with a report that does not conclude, and the worker moves
	// on to the next incident.
	Timeout time.Duration
	Now     func() time.Time
}

// Server holds the queue. Accept is safe to call from HTTP handlers; Run is the
// single worker.
type Server struct {
	cfg Config

	mu    sync.Mutex
	queue []string
	wake  chan struct{}
	hits  map[string][]time.Time
}

func New(cfg Config) (*Server, error) {
	if cfg.Intake == nil || cfg.Investigate == nil {
		return nil, errors.New("serve: intake and an investigator are required")
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("serve: an investigation timeout is required; an unbounded run would hold the only worker")
	}
	if cfg.Limits.Window <= 0 || cfg.Limits.PerGroup <= 0 || cfg.Limits.PerEntity <= 0 {
		return nil, fmt.Errorf("serve: rate limits must all be positive, got %+v", cfg.Limits)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{cfg: cfg, wake: make(chan struct{}, 1), hits: map[string][]time.Time{}}, nil
}

// Accept takes intake's decision about one notification. Only an opened
// incident can start an investigation; it is either queued or recorded as rate
// limited. It never blocks on investigation work.
func (s *Server) Accept(received intake.Received) {
	if received.Outcome != intake.OutcomeOpened {
		return
	}
	record, ok := s.cfg.Intake.Get(received.IncidentID)
	if !ok {
		return
	}
	now := s.cfg.Now().UTC()

	s.mu.Lock()
	reason := s.admit(record, now)
	if reason == "" {
		s.queue = append(s.queue, record.Incident.ID)
	}
	s.mu.Unlock()

	s.cfg.Intake.Update(record.Incident.ID, func(r *intake.Record) {
		if reason != "" {
			r.Investigation = intake.Investigation{State: intake.InvestigationRateLimited, Reason: reason}
			return
		}
		r.Investigation = intake.Investigation{State: intake.InvestigationQueued}
	})
	if reason == "" {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

// admit applies the rolling-window limits and, if the incident is admitted,
// counts it. It returns why it was held back, or "".
func (s *Server) admit(r intake.Record, now time.Time) string {
	entity := r.Entity
	if entity == "" {
		entity = r.Namespace + "/" + r.Incident.Service
	}
	keys := []struct {
		key   string
		limit int
		what  string
	}{
		{"group\x00" + r.GroupKey, s.cfg.Limits.PerGroup, "alert group"},
		{"entity\x00" + entity, s.cfg.Limits.PerEntity, "entity " + entity},
	}
	since := now.Add(-s.cfg.Limits.Window)
	for _, k := range keys {
		kept := s.hits[k.key][:0]
		for _, at := range s.hits[k.key] {
			if at.After(since) {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(s.hits, k.key)
		} else {
			s.hits[k.key] = kept
		}
		if len(kept) >= k.limit {
			return fmt.Sprintf("rate limited: the %s already started %d investigations in the last %s", k.what, len(kept), s.cfg.Limits.Window)
		}
	}
	for _, k := range keys {
		s.hits[k.key] = append(s.hits[k.key], now)
	}
	return ""
}

// Queued returns the incident IDs waiting, oldest first.
func (s *Server) Queued() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queue...)
}

// Run is the single worker. It takes incidents in arrival order until ctx is
// cancelled; cancellation also ends the investigation in progress, which is
// closed with a report like any run the controller cannot continue.
func (s *Server) Run(ctx context.Context) error {
	for {
		id, ok := s.next()
		if !ok {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-s.wake:
				continue
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		s.investigate(ctx, id)
	}
}

func (s *Server) next() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return "", false
	}
	id := s.queue[0]
	s.queue = s.queue[1:]
	return id, true
}

func (s *Server) investigate(ctx context.Context, id string) {
	record, ok := s.cfg.Intake.Get(id)
	if !ok {
		return
	}
	started := s.cfg.Now().UTC()
	s.cfg.Intake.Update(id, func(r *intake.Record) {
		r.Incident.Status = investigation.IncidentInvestigating
		r.Investigation = intake.Investigation{State: intake.InvestigationRunning, StartedAt: &started}
	})
	incident := record.Incident
	incident.Status = investigation.IncidentInvestigating

	runCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	result, err := s.cfg.Investigate(runCtx, incident)
	cancel()

	ended := s.cfg.Now().UTC()
	s.cfg.Intake.Update(id, func(r *intake.Record) {
		inv := &r.Investigation
		inv.EndedAt = &ended
		inv.Report = result.ReportJSONPath
		inv.RunStatus = result.Report.Run.Status
		switch {
		case err == nil:
			inv.State = intake.InvestigationConcluded
			r.Incident.Status = investigation.IncidentComplete
		case errors.Is(err, probe.ErrNotConcluded):
			inv.State = intake.InvestigationNotConcluded
			inv.Reason = err.Error()
			r.Incident.Status = investigation.IncidentFailed
		default:
			inv.State = intake.InvestigationError
			inv.Reason = err.Error()
			r.Incident.Status = investigation.IncidentFailed
		}
	})
}
