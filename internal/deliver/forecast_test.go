package deliver

import (
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/investigation"
)

func forecastAt(at time.Time, eta time.Duration) investigation.Forecast {
	return investigation.Forecast{Version: investigation.ForecastVersion, Outcome: investigation.ForecastWithinHorizon,
		At: at, Limit: 256 * (1 << 20), ETA: eta, Earliest: eta - 5*time.Minute, Latest: eta + 5*time.Minute}
}

// openForecastIncident opens a forecast and records its investigation as
// finished without a report, so it is ready to post.
func openForecastIncident(t *testing.T, in *intake.Intake) string {
	t.Helper()
	got, err := in.OpenForecast("memory-test", "probe-lab", forecastAt(time.Now().UTC(), 40*time.Minute))
	if err != nil || got.Outcome != intake.OutcomeOpened {
		t.Fatalf("open: %+v %v", got, err)
	}
	if err := in.SetInvestigation(got.IncidentID, intake.Investigation{State: intake.InvestigationError, Reason: "no model"}, ""); err != nil {
		t.Fatalf("set: %v", err)
	}
	return got.IncidentID
}

// A forecast lives in one thread: the report, then a reply for each material
// revision, then one for how it ended. Each is posted once, whatever triggers
// it, and none reads as an alert resolving.
func TestAForecastThreadCarriesItsRevisionsAndItsEnd(t *testing.T) {
	fake, client := newFake(t)
	in := intake.New(intake.DefaultConfig())
	d := newDeliverer(t, in, client)
	id := openForecastIncident(t, in)
	d.Finished(id)
	drain(t, d)
	posts := fake.sent()
	if len(posts) != 1 || !strings.Contains(posts[0].Blocks[0].Text.Text, "forecast ·") {
		t.Fatalf("the report must be labelled as a forecast: %+v", posts)
	}

	if _, err := in.ReviseForecast("memory-test", forecastAt(time.Now().UTC(), 15*time.Minute)); err != nil {
		t.Fatalf("revise: %v", err)
	}
	d.Revised(id)
	d.Revised(id) // a duplicate trigger
	drain(t, d)
	d.Revised(id) // a late duplicate, after the reply went out
	drain(t, d)
	restarted := newDeliverer(t, in, client) // and a restart
	drain(t, restarted)
	posts = fake.sent()
	if len(posts) != 2 {
		t.Fatalf("posts = %d, want the report and one revision reply", len(posts))
	}
	r, _ := in.Get(id)
	if posts[1].ThreadTS != r.Post.TS || !strings.Contains(posts[1].Text, "revised") || !strings.Contains(posts[1].Text, "if the growth persists") {
		t.Fatalf("the revision must reply in the thread, conditionally: %+v", posts[1])
	}

	if _, err := in.CloseForecast("memory-test", intake.ForecastWithdrawn, "the trend stopped: the series is not growing"); err != nil {
		t.Fatalf("close: %v", err)
	}
	d.Resolved(id)
	drain(t, d)
	posts = fake.sent()
	last := posts[len(posts)-1]
	if len(posts) != 3 || last.ThreadTS != r.Post.TS {
		t.Fatalf("posts = %d, want the withdrawal as a third message in the thread", len(posts))
	}
	for _, want := range []string{"withdrawn", "not growing", "The limit was not reached"} {
		if !strings.Contains(last.Text, want) {
			t.Fatalf("the withdrawal %q is missing %q", last.Text, want)
		}
	}
	if strings.Contains(last.Text, "alert") {
		t.Fatalf("a forecast's end must not read as an alert resolving: %q", last.Text)
	}
}

// A forecast that came true says so, with no suggestion that anything else
// was concluded from it.
func TestARealizedForecastSaysTheLimitWasReached(t *testing.T) {
	fake, client := newFake(t)
	in := intake.New(intake.DefaultConfig())
	d := newDeliverer(t, in, client)
	id := openForecastIncident(t, in)
	d.Finished(id)
	drain(t, d)
	in.CloseForecast("memory-test", intake.ForecastRealized, "the working set reached its limit")
	d.Resolved(id)
	drain(t, d)
	posts := fake.sent()
	if len(posts) != 2 || !strings.Contains(posts[1].Text, "realized") || !strings.Contains(posts[1].Text, "reached its limit") {
		t.Fatalf("posts = %+v, want the realization in the thread", posts)
	}
}

// A revision after the forecast ended is moot: the end supersedes it.
func TestARevisionAfterTheEndIsNotPosted(t *testing.T) {
	fake, client := newFake(t)
	in := intake.New(intake.DefaultConfig())
	d := newDeliverer(t, in, client)
	id := openForecastIncident(t, in)
	d.Finished(id)
	drain(t, d)
	in.ReviseForecast("memory-test", forecastAt(time.Now().UTC(), 10*time.Minute))
	in.CloseForecast("memory-test", intake.ForecastRealized, "reached")
	d.Revised(id)
	d.Resolved(id)
	drain(t, d)
	for _, p := range fake.sent() {
		if strings.Contains(p.Text, "revised") {
			t.Fatalf("a revision was posted after the forecast ended: %q", p.Text)
		}
	}
}
