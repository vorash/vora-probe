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
	"strings"
	"sync"
	"time"

	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/internal/probe"
	"github.com/vorash/vora-probe/investigation"
)

// Investigator runs one investigation. It is probe.Run or probe.Investigate
// with their ports bound; the server does not know which. attempt numbers the
// runs of one incident, so a retried run gets its own journal.
type Investigator func(ctx context.Context, incident investigation.Incident, attempt int) (probe.ReplayResult, error)

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
	// Logf reports a state change that could not be recorded. The work still
	// happens; only its record is behind, and a restart re-derives it.
	Logf func(format string, args ...any)
	// OnFinished is told when an investigation's outcome has been recorded,
	// and OnResolved when an incident's alert resolves. Both must not block:
	// delivery queues its work, it never does it here.
	OnFinished func(id string)
	OnResolved func(id string)
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
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	s := &Server{cfg: cfg, wake: make(chan struct{}, 1), hits: map[string][]time.Time{}}
	s.recover()
	return s, nil
}

// recover rebuilds the queue and the rate-limit windows from intake's records,
// which a persistent intake has just replayed from its log. Incidents resume in
// the order they arrived: queued ones as they were, an interrupted one as its
// next attempt, and one that was recorded but never admitted is admitted now.
func (s *Server) recover() {
	now := s.cfg.Now().UTC()
	for _, r := range s.cfg.Intake.List() {
		inv := r.Investigation
		switch inv.State {
		case intake.InvestigationRateLimited:
			continue
		case intake.InvestigationPending:
			s.admitAndQueue(r, now)
			continue
		}
		s.count(r, r.ReceivedAt)
		switch inv.State {
		case intake.InvestigationQueued:
			s.queue = append(s.queue, r.Incident.ID)
		case intake.InvestigationRunning:
			next := intake.Investigation{
				State:   intake.InvestigationQueued,
				Attempt: attempt(inv) + 1,
				Reason:  fmt.Sprintf("attempt %d was interrupted when the server stopped; its journal is kept", attempt(inv)),
			}
			s.record(r.Incident.ID, next, investigation.IncidentOpen)
			s.queue = append(s.queue, r.Incident.ID)
		}
	}
}

func attempt(inv intake.Investigation) int {
	if inv.Attempt > 0 {
		return inv.Attempt
	}
	return 1
}

func (s *Server) record(id string, inv intake.Investigation, status investigation.IncidentStatus) {
	if err := s.cfg.Intake.SetInvestigation(id, inv, status); err != nil {
		s.cfg.Logf("vora-probe serve: could not record %s as %s: %v", id, inv.State, err)
	}
}

// Accept takes intake's decision about one notification. Only an opened
// incident can start an investigation; it is either queued or recorded as rate
// limited. It never blocks on investigation work.
func (s *Server) Accept(received intake.Received) {
	if received.Outcome == intake.OutcomeResolved && s.cfg.OnResolved != nil {
		s.cfg.OnResolved(received.IncidentID)
	}
	if received.Outcome != intake.OutcomeOpened {
		return
	}
	record, ok := s.cfg.Intake.Get(received.IncidentID)
	if !ok {
		return
	}
	s.admitAndQueue(record, s.cfg.Now().UTC())
}

// admitAndQueue records the decision before the incident becomes visible to the
// worker. Recording it after would race a worker that is already looping: it
// could start the run, and the late "queued" would overwrite "investigating",
// or even the final state. Lock order is s.mu, then intake's; nothing takes
// them the other way round.
func (s *Server) admitAndQueue(record intake.Record, now time.Time) {
	s.mu.Lock()
	reason := s.admit(record, now)
	if reason != "" {
		s.record(record.Incident.ID, intake.Investigation{State: intake.InvestigationRateLimited, Reason: reason}, "")
		s.mu.Unlock()
		return
	}
	s.record(record.Incident.ID, intake.Investigation{State: intake.InvestigationQueued, Attempt: 1}, "")
	s.queue = append(s.queue, record.Incident.ID)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// admit applies the rolling-window limits and, if the incident is admitted,
// counts it. It returns why it was held back, or "".
func (s *Server) admit(r intake.Record, now time.Time) string {
	group, entity := s.limitKeys(r)
	keys := []struct {
		key   string
		limit int
		what  string
	}{
		{group, s.cfg.Limits.PerGroup, "alert group"},
		{entity, s.cfg.Limits.PerEntity, "entity " + strings.TrimPrefix(entity, "entity\x00")},
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
	s.count(r, now)
	return ""
}

// limitKeys are the rolling windows an incident counts against.
func (s *Server) limitKeys(r intake.Record) (group, entity string) {
	e := r.Entity
	if e == "" {
		e = r.Namespace + "/" + r.Incident.Service
	}
	return "group\x00" + r.GroupKey, "entity\x00" + e
}

// count records that an incident started a run at the given time.
func (s *Server) count(r intake.Record, at time.Time) {
	group, entity := s.limitKeys(r)
	s.hits[group] = append(s.hits[group], at)
	s.hits[entity] = append(s.hits[entity], at)
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
	n := attempt(record.Investigation)
	running := intake.Investigation{State: intake.InvestigationRunning, Attempt: n, StartedAt: &started}
	s.record(id, running, investigation.IncidentInvestigating)
	incident := record.Incident
	incident.Status = investigation.IncidentInvestigating

	runCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	result, err := s.cfg.Investigate(runCtx, incident, n)
	cancel()

	ended := s.cfg.Now().UTC()
	done := running
	done.EndedAt = &ended
	done.Report = result.ReportJSONPath
	done.RunStatus = result.Report.Run.Status
	status := investigation.IncidentFailed
	switch {
	case err == nil:
		done.State = intake.InvestigationConcluded
		status = investigation.IncidentComplete
	case errors.Is(err, probe.ErrNotConcluded):
		done.State = intake.InvestigationNotConcluded
		done.Reason = err.Error()
	default:
		done.State = intake.InvestigationError
		done.Reason = err.Error()
	}
	s.record(id, done, status)
	if s.cfg.OnFinished != nil {
		s.cfg.OnFinished(id)
	}
}
