package investigation_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/vorash/vora-probe/internal/investigation"
)

func TestSummarizeIsOrderIndependent(t *testing.T) {
	ordered := []investigation.Sample{
		{At: at(12, 0), Value: 1},
		{At: at(12, 5), Value: 3},
		{At: at(12, 10), Value: 2},
	}
	shuffled := []investigation.Sample{ordered[2], ordered[0], ordered[1]}

	a, err := investigation.Summarize(ordered)
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	b, err := investigation.Summarize(shuffled)
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("summaries differ by input order:\n%+v\n%+v", a, b)
	}
	if a.FirstAt != at(12, 0) || a.LastAt != at(12, 10) {
		t.Fatalf("unexpected bounds: %s..%s", a.FirstAt, a.LastAt)
	}
	if a.Count != 3 || a.First != 1 || a.Last != 2 || a.Min != 1 || a.Max != 3 {
		t.Fatalf("unexpected stats: %+v", a)
	}
	if a.MonotonicIncrease {
		t.Fatal("1,3,2 is not monotonically increasing")
	}
}

func TestSummarizeSlope(t *testing.T) {
	st, err := investigation.Summarize([]investigation.Sample{
		{At: at(12, 0), Value: 1},
		{At: at(12, 0).Add(10 * time.Second), Value: 3},
	})
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if got := st.SlopePerSecond; got < 0.199 || got > 0.201 {
		t.Fatalf("slope = %v, want 0.2 per second", got)
	}
}

func TestSummarizeRejectsEmpty(t *testing.T) {
	if _, err := investigation.Summarize(nil); err == nil {
		t.Fatal("an empty series has no summary")
	}
}

func TestScalarHelpers(t *testing.T) {
	st, err := investigation.Summarize([]investigation.Sample{{At: at(12, 0), Value: 2}, {At: at(12, 30), Value: 8}})
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if got := st.Ratio(); got != 4 {
		t.Fatalf("ratio = %v, want 4", got)
	}
	if got := investigation.PercentChange(2, 8); got != 300 {
		t.Fatalf("percent change = %v, want 300", got)
	}
	if got := investigation.PercentChange(0, 8); got != 0 {
		t.Fatalf("percent change from zero = %v, want 0", got)
	}
	if got := investigation.RestartDelta(2, 7); got != 5 {
		t.Fatalf("restart delta = %d, want 5", got)
	}
	if got := investigation.Delta(at(12, 12), at(12, 15)); got != 3*time.Minute {
		t.Fatalf("delta = %s, want 3m0s", got)
	}
	if !investigation.WithinProximity(at(12, 12), at(12, 15), 5*time.Minute) {
		t.Fatal("3 minutes is within a 5 minute bound")
	}
	if investigation.WithinProximity(at(12, 0), at(12, 15), 5*time.Minute) {
		t.Fatal("15 minutes is outside a 5 minute bound")
	}
}

func TestFormattingIsStable(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{investigation.FormatFloat(0.23456, 3), "0.235"},
		{investigation.FormatBytes(553648128), "528.0 MiB"},
		{investigation.FormatBytes(536870912), "512.0 MiB"},
		{investigation.FormatBytes(2147483648), "2.00 GiB"},
		{investigation.FormatBytes(4096), "4.0 KiB"},
		{investigation.FormatBytes(512), "512 B"},
		{investigation.FormatDuration(94 * time.Second), "1m34s"},
		{investigation.FormatDuration(30 * time.Second), "30s"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("formatted %q, want %q", c.got, c.want)
		}
	}
}

func TestSummarizeIsBitIdenticalAcrossRuns(t *testing.T) {
	samples := []investigation.Sample{
		{At: at(12, 0), Value: 188743680},
		{At: at(12, 5), Value: 204472320},
		{At: at(12, 10), Value: 251658240},
		{At: at(12, 15), Value: 429916160},
		{At: at(12, 20), Value: 553648128},
	}
	first, err := investigation.Summarize(samples)
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	for i := range 50 {
		again, err := investigation.Summarize(samples)
		if err != nil {
			t.Fatalf("summarize: %v", err)
		}
		if again != first {
			t.Fatalf("iteration %d produced different statistics", i)
		}
	}
}
