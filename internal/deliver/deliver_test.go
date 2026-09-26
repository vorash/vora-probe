package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vorash/vora-probe/fixtures"
	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/internal/probe"
	"github.com/vorash/vora-probe/investigation"
)

// fakeSlack stands in for chat.postMessage. fail, when set, decides whether the
// nth call (1-based) fails and how.
type fakeSlack struct {
	mu    sync.Mutex
	posts []Message
	auth  []string
	calls int
	fail  func(n int) (status int, body string)
}

func (f *fakeSlack) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	if f.fail != nil {
		if status, body := f.fail(f.calls); status != 0 {
			w.WriteHeader(status)
			io.WriteString(w, body)
			return
		}
	}
	var m Message
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.posts = append(f.posts, m)
	fmt.Fprintf(w, `{"ok":true,"channel":%q,"ts":"1700000000.%06d"}`, m.Channel, len(f.posts))
}

func (f *fakeSlack) sent() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Message(nil), f.posts...)
}

func newFake(t *testing.T) (*fakeSlack, *SlackClient) {
	t.Helper()
	fake := &fakeSlack{}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return fake, &SlackClient{BaseURL: srv.URL, Token: "xoxb-test"}
}

func newDeliverer(t *testing.T, in *intake.Intake, poster Poster) *Deliverer {
	t.Helper()
	d, err := New(Config{
		Intake: in, Poster: poster,
		Channels:    Channels{Default: "C-DEFAULT", Critical: "C-CRITICAL"},
		MinInterval: time.Millisecond,
		Backoff:     func(int) time.Duration { return time.Millisecond },
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return d
}

// drain runs the deliverer until its queue is empty.
func drain(t *testing.T, d *Deliverer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = d.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for d.Pending() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // let the last job finish recording
	cancel()
	<-done
}

func notification(group, service, severity, summary string) (intake.Notification, []byte) {
	raw, _ := json.Marshal(map[string]any{
		"version": "4", "groupKey": group, "status": "firing",
		"alerts": []map[string]any{{
			"status":      "firing",
			"labels":      map[string]string{"alertname": "ContainerOOMKilled", "service": service, "severity": severity, "pod": service + "-1"},
			"annotations": map[string]string{"summary": summary},
			"startsAt":    time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339),
			"endsAt":      "0001-01-01T00:00:00Z",
		}},
	})
	n, err := intake.Parse(raw)
	if err != nil {
		panic(err)
	}
	return n, raw
}

// finishedIncident records an alert whose investigation produced the report at
// reportPath with the given state.
func finishedIncident(t *testing.T, in *intake.Intake, group, service, severity, summary, reportPath string, state intake.InvestigationState) string {
	t.Helper()
	n, raw := notification(group, service, severity, summary)
	got, err := in.Receive(n, raw)
	if err != nil || got.Outcome != intake.OutcomeOpened {
		t.Fatalf("receive: %+v %v", got, err)
	}
	inv := intake.Investigation{State: state, Attempt: 1, Report: reportPath}
	if err := in.SetInvestigation(got.IncidentID, inv, investigation.IncidentComplete); err != nil {
		t.Fatalf("set: %v", err)
	}
	return got.IncidentID
}

func text(m Message) string {
	var b strings.Builder
	b.WriteString(m.Text + "\n")
	for _, block := range m.Blocks {
		if block.Text != nil {
			b.WriteString(block.Text.Text + "\n")
		}
		for _, e := range block.Elements {
			b.WriteString(e.Text + "\n")
		}
	}
	return b.String()
}

// P1.4 acceptance: the four OOM fixtures, investigated for real, yield four
// posts — and each post carries what makes the report worth reading: the
// environment, the leading claim, every refused claim with its narrowed form,
// and every gap in the evidence. The missing-telemetry case must list its gaps.
func TestTheFourFixturesYieldFourPostsThatKeepTheReport(t *testing.T) {
	dirs, err := fixtures.Cases(filepath.Join(fixtures.Root(), "oom"))
	if err != nil {
		t.Fatalf("cases: %v", err)
	}
	fake, client := newFake(t)
	in := intake.New(intake.DefaultConfig())
	d := newDeliverer(t, in, client)
	reports := map[string]investigation.Report{}
	for _, dir := range dirs {
		result, err := probe.Replay(context.Background(), probe.ReplayOptions{BundleDir: dir, OutDir: t.TempDir()})
		if err != nil {
			t.Fatalf("replay %s: %v", dir, err)
		}
		id := finishedIncident(t, in, filepath.Base(dir), result.Report.Incident.Service, "warning",
			result.Report.Incident.Symptom, result.ReportJSONPath, intake.InvestigationConcluded)
		reports[id] = result.Report
		d.Finished(id)
	}
	drain(t, d)

	posts := fake.sent()
	if len(posts) != len(dirs) {
		t.Fatalf("posts = %d, want one per fixture (%d)", len(posts), len(dirs))
	}
	for id, report := range reports {
		r, _ := in.Get(id)
		if r.Post == nil || r.Post.TS == "" {
			t.Fatalf("%s: the post's ts was not recorded", id)
		}
		var post Message
		for _, p := range posts {
			if strings.Contains(text(p), id) {
				post = p
			}
		}
		body := text(post)
		if !strings.Contains(post.Blocks[0].Text.Text, "[lab]") {
			t.Errorf("%s: the environment is not tagged in %q", id, post.Blocks[0].Text.Text)
		}
		if report.Leading != nil && !strings.Contains(body, string(report.Leading.Kind)) {
			t.Errorf("%s: the leading claim %s is missing", id, report.Leading.Kind)
		}
		for _, c := range report.Claims {
			if c.Allowed {
				continue
			}
			if !strings.Contains(body, "`"+string(c.Kind)+"` refused") {
				t.Errorf("%s: the refused claim %s is missing", id, c.Kind)
			}
			if c.Narrowed != "" && !strings.Contains(body, escape(c.Narrowed)) {
				t.Errorf("%s: the narrowed form of %s is missing", id, c.Kind)
			}
		}
		for _, g := range report.CoverageGaps {
			if !strings.Contains(body, escape(g.String())) {
				t.Errorf("%s: the gap %q is missing", id, g.String())
			}
		}
		if report.Incident.ID == "INC-0003" && len(report.CoverageGaps) < 2 {
			t.Errorf("the missing-telemetry report should carry its gaps; got %d", len(report.CoverageGaps))
		}
	}
}

// A retry, a duplicate trigger or a restart must never post an incident twice:
// the stored ts is the proof it was delivered.
func TestAnIncidentIsPostedOnce(t *testing.T) {
	fake, client := newFake(t)
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	in, err := intake.Open(intake.DefaultConfig(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	id := finishedIncident(t, in, "g", "payment-api", "warning", "OOMKilled", "", intake.InvestigationError)
	d := newDeliverer(t, in, client)
	d.Finished(id)
	d.Finished(id)
	drain(t, d)
	in.Close()

	in, err = intake.Open(intake.DefaultConfig(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer in.Close()
	restarted := newDeliverer(t, in, client)
	restarted.Finished(id)
	drain(t, restarted)
	if n := len(fake.sent()); n != 1 {
		t.Fatalf("posts = %d, want 1 across duplicate triggers and a restart", n)
	}
}

// A resolution goes into the report's thread, so the channel reads as one
// conversation per incident. If the alert resolved before the report was
// posted, the post says so and no second message follows.
func TestAResolutionGoesIntoTheReportsThread(t *testing.T) {
	fake, client := newFake(t)
	in := intake.New(intake.DefaultConfig())
	d := newDeliverer(t, in, client)
	id := finishedIncident(t, in, "group-late", "payment-api", "warning", "OOMKilled", "", intake.InvestigationError)
	d.Finished(id)
	drain(t, d)

	resolve := func(group string) {
		raw, _ := json.Marshal(map[string]any{"version": "4", "groupKey": group, "status": "resolved",
			"alerts": []map[string]any{{"status": "resolved", "labels": map[string]string{"alertname": "x"},
				"startsAt": time.Now().Add(-time.Hour).Format(time.RFC3339), "endsAt": time.Now().Format(time.RFC3339)}}})
		n, _ := intake.Parse(raw)
		if got, err := in.Receive(n, raw); err != nil || got.Outcome != intake.OutcomeResolved {
			t.Fatalf("resolve: %+v %v", got, err)
		}
	}
	resolve("group-late")
	d.Resolved(id)
	drain(t, d)
	posts := fake.sent()
	if len(posts) != 2 {
		t.Fatalf("posts = %d, want the report then a reply", len(posts))
	}
	r, _ := in.Get(id)
	if posts[1].ThreadTS != r.Post.TS || r.Post.ResolutionTS == "" {
		t.Fatalf("the resolution must reply in the report's thread %q; got thread %q", r.Post.TS, posts[1].ThreadTS)
	}

	// Resolved before the report went out.
	early := finishedIncident(t, in, "group-early", "checkout-api", "warning", "OOMKilled", "", intake.InvestigationError)
	resolve("group-early")
	d.Resolved(early) // nothing posted yet: nothing to reply to
	d.Finished(early)
	drain(t, d)
	posts = fake.sent()
	if len(posts) != 3 {
		t.Fatalf("posts = %d, want 3: a report that already says it resolved needs no reply", len(posts))
	}
	if !strings.Contains(text(posts[2]), "resolved") {
		t.Fatal("a report posted after the alert resolved must say so")
	}
}

// Delivery failing is recorded and never touches the investigation: the report
// is already on disk. A later start retries what was not delivered.
func TestAFailedPostIsRecordedAndRetriedLater(t *testing.T) {
	fake, client := newFake(t)
	fake.fail = func(int) (int, string) { return http.StatusInternalServerError, "down" }
	in := intake.New(intake.DefaultConfig())
	id := finishedIncident(t, in, "g", "payment-api", "warning", "OOMKilled", "", intake.InvestigationError)
	d := newDeliverer(t, in, client)
	d.Finished(id)
	drain(t, d)

	r, _ := in.Get(id)
	if r.Post == nil || r.Post.TS != "" || r.Post.Error == "" || r.Post.Attempts != 3 {
		t.Fatalf("post state = %+v, want the error and 3 attempts recorded", r.Post)
	}
	if r.Investigation.State != intake.InvestigationError {
		t.Fatalf("delivery changed the investigation to %q", r.Investigation.State)
	}

	fake.mu.Lock()
	fake.fail = nil
	fake.mu.Unlock()
	restarted := newDeliverer(t, in, client) // recovers the undelivered post
	drain(t, restarted)
	if r, _ := in.Get(id); r.Post.TS == "" || r.Post.Error != "" {
		t.Fatalf("after recovery: %+v, want it delivered", r.Post)
	}
}

// Alert text reaches the channel, and it is written by whoever wrote the rule.
// It must not be able to ping the channel or disguise a link.
func TestAlertTextCannotMentionTheChannel(t *testing.T) {
	in := intake.New(intake.DefaultConfig())
	id := finishedIncident(t, in, "g", "payment-api", "warning", "<!channel> <https://evil.example|click> & more", "", intake.InvestigationError)
	r, _ := in.Get(id)
	body := text(ReportMessage(RouteFor(Channels{Default: "C"}, r, nil), r, nil))
	for _, forbidden := range []string{"<!channel>", "<https://evil.example|click>"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("the message carries %q unescaped:\n%s", forbidden, body)
		}
	}
	if !strings.Contains(body, "&lt;!channel&gt;") {
		t.Fatal("the text must still be shown, escaped")
	}
}

// Routing is code's decision, from the outcome and the alert's severity.
func TestRoutingIsDecidedFromTheOutcomeAndSeverity(t *testing.T) {
	ch := Channels{Default: "C-DEFAULT", Critical: "C-CRITICAL"}
	concluded := &investigation.Report{Run: investigation.Run{Status: investigation.RunCompleted},
		Leading: &investigation.ClaimReport{Kind: investigation.ClaimMemoryLimitTermination, Allowed: true}}
	inconclusive := &investigation.Report{Run: investigation.Run{Status: investigation.RunCompleted},
		Leading: &investigation.ClaimReport{Kind: investigation.ClaimUnknownCause, Allowed: true}}
	stopped := &investigation.Report{Run: investigation.Run{Status: investigation.RunBudgetExhausted}}
	cases := []struct {
		severity string
		report   *investigation.Report
		want     Route
	}{
		{"warning", concluded, Route{"C-DEFAULT", "finding: memory_limit_termination"}},
		{"critical", concluded, Route{"C-CRITICAL", "finding: memory_limit_termination"}},
		{"warning", inconclusive, Route{"C-DEFAULT", "inconclusive"}},
		{"warning", stopped, Route{"C-DEFAULT", "not concluded (budget_exhausted)"}},
		{"CRITICAL", nil, Route{"C-CRITICAL", "no report"}},
	}
	for _, c := range cases {
		got := RouteFor(ch, intake.Record{Severity: c.severity}, c.report)
		if got != c.want {
			t.Errorf("severity %s: route = %+v, want %+v", c.severity, got, c.want)
		}
	}
	if got := RouteFor(Channels{Default: "C-DEFAULT"}, intake.Record{Severity: "critical"}, concluded); got.Channel != "C-DEFAULT" {
		t.Errorf("without a critical channel, critical goes to the default; got %s", got.Channel)
	}
}

// Slack rejects oversized blocks outright, so a long report must be cut, and
// say it was, rather than fail to post at all.
func TestMessagesStayWithinSlacksLimits(t *testing.T) {
	long := strings.Repeat("é", 5000)
	report := &investigation.Report{Run: investigation.Run{Status: investigation.RunCompleted},
		Leading: &investigation.ClaimReport{Kind: investigation.ClaimMemoryLimitTermination, Allowed: true, Statement: long}}
	for i := range 80 {
		report.Claims = append(report.Claims, investigation.ClaimReport{Kind: investigation.ClaimKind(fmt.Sprintf("k%d", i)), Reasons: []string{long}})
	}
	r := intake.Record{Incident: investigation.Incident{Service: strings.Repeat("s", 400), Symptom: long, Environment: "lab"}}
	m := ReportMessage(RouteFor(Channels{Default: "C"}, r, report), r, report)
	if len(m.Blocks) > maxBlocks {
		t.Fatalf("blocks = %d, over %d", len(m.Blocks), maxBlocks)
	}
	for _, b := range m.Blocks {
		limit := maxSection
		if b.Type == "header" {
			limit = maxHeader
		}
		if b.Text != nil && utf8.RuneCountInString(b.Text.Text) > limit {
			t.Fatalf("%s block of %d characters, over %d", b.Type, utf8.RuneCountInString(b.Text.Text), limit)
		}
	}
	if !strings.Contains(text(m), "truncated; see the report") {
		t.Fatal("truncation must be visible")
	}
}

func TestTheSlackClientChecksTheAnswer(t *testing.T) {
	var gotAuth, gotType string
	answers := []func(w http.ResponseWriter){
		func(w http.ResponseWriter) { io.WriteString(w, `{"ok":true,"ts":"1.2"}`) },
		func(w http.ResponseWriter) { io.WriteString(w, `{"ok":false,"error":"channel_not_found"}`) },
		func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"ok":false,"error":"ratelimited"}`)
		},
	}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotType = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		answers[n](w)
		n++
	}))
	defer srv.Close()
	c := &SlackClient{BaseURL: srv.URL, Token: "xoxb-1"}

	ts, err := c.Post(context.Background(), Message{Channel: "C", Text: "hi"})
	if err != nil || ts != "1.2" {
		t.Fatalf("ok answer: ts %q err %v", ts, err)
	}
	if gotAuth != "Bearer xoxb-1" || !strings.HasPrefix(gotType, "application/json") {
		t.Fatalf("auth %q type %q", gotAuth, gotType)
	}
	if _, err := c.Post(context.Background(), Message{Channel: "C"}); err == nil || !strings.Contains(err.Error(), "channel_not_found") {
		t.Fatalf("ok=false must be an error naming Slack's reason, got %v", err)
	}
	_, err = c.Post(context.Background(), Message{Channel: "C"})
	var limited *RateLimited
	if !errors.As(err, &limited) || limited.After != 7*time.Second {
		t.Fatalf("a 429 must be RateLimited with Retry-After, got %v", err)
	}
}
