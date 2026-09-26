package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/investigation"
)

type Config struct {
	Intake   *intake.Intake
	Poster   Poster
	Channels Channels
	// MinInterval spaces posts; Slack allows about one message per second per
	// channel.
	MinInterval time.Duration
	// MaxAttempts bounds retries of one post. A post that still fails is
	// recorded with its error and retried on the next start.
	MaxAttempts int
	// Backoff is the wait before attempt n+1 when Slack gave no Retry-After.
	Backoff func(attempt int) time.Duration
	Now     func() time.Time
	Logf    func(format string, args ...any)
}

type jobKind int

const (
	postReport jobKind = iota
	postResolution
	postRevision
)

type job struct {
	kind jobKind
	id   string
}

// Deliverer posts reports and resolutions from its own queue, so posting never
// blocks the webhook or the investigation worker.
type Deliverer struct {
	cfg Config

	mu   sync.Mutex
	jobs []job
	wake chan struct{}
	last time.Time
}

func New(cfg Config) (*Deliverer, error) {
	if cfg.Intake == nil || cfg.Poster == nil || cfg.Channels.Default == "" {
		return nil, errors.New("deliver: intake, a poster and a default channel are required")
	}
	if cfg.MinInterval <= 0 {
		cfg.MinInterval = time.Second
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.Backoff == nil {
		cfg.Backoff = func(attempt int) time.Duration { return time.Duration(attempt*attempt) * 2 * time.Second }
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	d := &Deliverer{cfg: cfg, wake: make(chan struct{}, 1)}
	d.recover()
	return d, nil
}

// recover queues what a previous process left undelivered: finished incidents
// with no message yet, and resolutions not yet in their thread.
func (d *Deliverer) recover() {
	for _, r := range d.cfg.Intake.List() {
		switch {
		case finished(r) && (r.Post == nil || r.Post.TS == ""):
			d.jobs = append(d.jobs, job{postReport, r.Incident.ID})
		case r.Alert == intake.AlertResolved && r.Post != nil && r.Post.TS != "" && r.Post.ResolutionTS == "":
			d.jobs = append(d.jobs, job{postResolution, r.Incident.ID})
		case r.Forecast != nil && r.Forecast.Closed == "" && r.Post != nil && r.Post.TS != "" &&
			r.Forecast.Revisions > r.Post.RevisionsPosted:
			d.jobs = append(d.jobs, job{postRevision, r.Incident.ID})
		}
	}
}

func finished(r intake.Record) bool {
	switch r.Investigation.State {
	case intake.InvestigationConcluded, intake.InvestigationNotConcluded, intake.InvestigationError:
		return true
	}
	return false
}

// Finished queues an incident's report. Called after the investigation's
// outcome is recorded, so the report is already on disk.
func (d *Deliverer) Finished(id string) { d.enqueue(job{postReport, id}) }

// Resolved queues the thread reply for an incident whose alert resolved, or
// whose forecast was withdrawn or realized.
func (d *Deliverer) Resolved(id string) { d.enqueue(job{postResolution, id}) }

// Revised queues the thread reply for a forecast whose ETA moved.
func (d *Deliverer) Revised(id string) { d.enqueue(job{postRevision, id}) }

// enqueue adds a job unless the same one is already waiting. Two triggers for
// one incident (a restart's recovery and a late Finished, say) would otherwise
// both run, and a failing post would be attempted twice as often as bounded.
func (d *Deliverer) enqueue(j job) {
	d.mu.Lock()
	if slices.Contains(d.jobs, j) {
		d.mu.Unlock()
		return
	}
	d.jobs = append(d.jobs, j)
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Pending reports how many deliveries are waiting.
func (d *Deliverer) Pending() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.jobs)
}

// Run is the delivery worker. It returns when ctx is cancelled; what is left is
// recovered on the next start.
func (d *Deliverer) Run(ctx context.Context) error {
	for {
		d.mu.Lock()
		var next *job
		if len(d.jobs) > 0 {
			j := d.jobs[0]
			d.jobs = d.jobs[1:]
			next = &j
		}
		d.mu.Unlock()
		if next == nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-d.wake:
				continue
			}
		}
		switch next.kind {
		case postReport:
			d.deliverReport(ctx, next.id)
		case postResolution:
			d.deliverResolution(ctx, next.id)
		case postRevision:
			d.deliverRevision(ctx, next.id)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

func (d *Deliverer) deliverReport(ctx context.Context, id string) {
	r, ok := d.cfg.Intake.Get(id)
	if !ok || (r.Post != nil && r.Post.TS != "") {
		// Already posted: a retry, a duplicate trigger or a restart must not
		// post twice.
		return
	}
	report, err := loadReport(r.Investigation.Report)
	if err != nil {
		d.cfg.Logf("vora-probe deliver: %s: the report could not be read (%v); posting without it", id, err)
	}
	route := RouteFor(d.cfg.Channels, r, report)
	msg := ReportMessage(route, r, report)
	post := intake.Post{Channel: route.Channel}
	if r.Post != nil {
		post.Attempts = r.Post.Attempts
	}
	ts, err := d.post(ctx, msg, &post)
	if err != nil {
		post.Error = err.Error()
		d.record(id, post)
		return
	}
	at := d.cfg.Now().UTC()
	post.TS, post.PostedAt, post.Error = ts, &at, ""
	if r.Alert == intake.AlertResolved {
		// The post already says the alert resolved; a thread reply would
		// repeat it.
		post.ResolutionTS = ts
	}
	if r.Forecast != nil {
		// The post carries the latest forecast, so earlier revisions need no
		// reply of their own.
		post.RevisionsPosted = r.Forecast.Revisions
	}
	d.record(id, post)
}

func (d *Deliverer) deliverRevision(ctx context.Context, id string) {
	r, ok := d.cfg.Intake.Get(id)
	if !ok || r.Forecast == nil || r.Forecast.Closed != "" || r.Post == nil || r.Post.TS == "" ||
		r.Forecast.Revisions <= r.Post.RevisionsPosted {
		// Not posted yet (the post will carry the latest forecast), already
		// closed (the closure supersedes it), or already told.
		return
	}
	post := *r.Post
	if _, err := d.post(ctx, RevisionMessage(r), &post); err != nil {
		post.Error = err.Error()
		d.record(id, post)
		return
	}
	post.RevisionsPosted, post.Error = r.Forecast.Revisions, ""
	d.record(id, post)
}

func (d *Deliverer) deliverResolution(ctx context.Context, id string) {
	r, ok := d.cfg.Intake.Get(id)
	if !ok || r.Post == nil || r.Post.TS == "" || r.Post.ResolutionTS != "" {
		// Not posted yet (the report will say it resolved), or already
		// replied.
		return
	}
	post := *r.Post
	ts, err := d.post(ctx, ResolutionMessage(r), &post)
	if err != nil {
		post.Error = err.Error()
		d.record(id, post)
		return
	}
	post.ResolutionTS, post.Error = ts, ""
	d.record(id, post)
}

// post sends one message with bounded retries, spacing posts by MinInterval.
func (d *Deliverer) post(ctx context.Context, m Message, state *intake.Post) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= d.cfg.MaxAttempts; attempt++ {
		if err := d.pace(ctx); err != nil {
			return "", err
		}
		state.Attempts++
		ts, err := d.cfg.Poster.Post(ctx, m)
		if err == nil {
			return ts, nil
		}
		lastErr = err
		if attempt == d.cfg.MaxAttempts {
			break
		}
		wait := d.cfg.Backoff(attempt)
		var limited *RateLimited
		if errors.As(err, &limited) {
			wait = limited.After
		}
		if err := sleep(ctx, wait); err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("after %d attempts: %w", d.cfg.MaxAttempts, lastErr)
}

func (d *Deliverer) pace(ctx context.Context) error {
	if wait := d.cfg.MinInterval - time.Since(d.last); wait > 0 {
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
	d.last = time.Now()
	return nil
}

func (d *Deliverer) record(id string, post intake.Post) {
	if err := d.cfg.Intake.SetPost(id, post); err != nil {
		d.cfg.Logf("vora-probe deliver: could not record the post for %s: %v", id, err)
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

const maxReportBytes = 16 << 20

// loadReport reads a run's report.json. A run that could not write one has no
// path, and is delivered as such.
func loadReport(path string) (*investigation.Report, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxReportBytes {
		return nil, fmt.Errorf("report exceeds %d bytes", maxReportBytes)
	}
	var report investigation.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, err
	}
	return &report, nil
}
