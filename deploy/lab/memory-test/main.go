// Command memory-test is the lab's single workload.
//
// It exists to produce, on demand, the four shapes the OOM slice must tell
// apart: a memory-limit kill, a non-memory restart, a window with a metric
// missing, and the symptom/mechanism metrics a rollout correlation is judged
// against. Parameterised by environment so a scenario is a manifest, not an
// exec into a running pod — fault injection stays declarative and operator-run.
//
// It is a lab fixture and deliberately outside probe's public surface.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type state struct {
	mu     sync.Mutex
	held   [][]byte
	heldMB int

	dropped   map[string]bool
	failAfter time.Duration
	started   time.Time

	latencyMicros atomic.Uint64
	errorPerMille atomic.Uint64
	queries       atomic.Int64
}

func main() {
	s := &state{dropped: map[string]bool{}, started: time.Now()}
	s.latencyMicros.Store(50_000)
	s.errorPerMille.Store(5)

	if v := os.Getenv("HOLD_MB"); v != "" {
		mb, err := strconv.Atoi(v)
		if err != nil || mb < 0 {
			log.Fatalf("HOLD_MB must be a non-negative integer, got %q", v)
		}
		s.hold(mb)
	}
	if v := os.Getenv("FAIL_LIVENESS_AFTER"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("FAIL_LIVENESS_AFTER must be a duration, got %q", v)
		}
		s.failAfter = d
	}
	if v := os.Getenv("DROP_METRIC"); v != "" {
		for _, m := range strings.Split(v, ",") {
			s.dropped[strings.TrimSpace(m)] = true
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/metrics", s.metrics)
	mux.HandleFunc("/work", s.work)
	mux.HandleFunc("/allocate", s.allocate)
	mux.HandleFunc("/free", s.free)
	mux.HandleFunc("/config", s.config)

	log.Printf("memory-test listening on :8080 (held %d MiB, fail-after %s, dropped %v)", s.heldMB, s.failAfter, sortedKeys(s.dropped))
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// health fails once the configured interval has passed, so a liveness probe
// restarts the pod without any memory pressure. That is the non-OOM control.
func (s *state) health(w http.ResponseWriter, _ *http.Request) {
	if s.failAfter > 0 && time.Since(s.started) >= s.failAfter {
		http.Error(w, "liveness deliberately failing", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *state) work(w http.ResponseWriter, _ *http.Request) {
	s.queries.Add(1)
	s.latencyMicros.Store(uint64(40_000 + time.Now().UnixNano()%20_000))
	s.errorPerMille.Store(uint64(3 + time.Now().UnixNano()%9))
	fmt.Fprintln(w, "ok")
}

// allocate grows the working set and holds it. Under a memory limit this is what
// the kernel kills the container for; the bytes are touched, not just reserved,
// so the RSS actually grows.
func (s *state) allocate(w http.ResponseWriter, r *http.Request) {
	mb, err := strconv.Atoi(r.URL.Query().Get("mb"))
	if err != nil || mb <= 0 {
		http.Error(w, "mb must be a positive integer", http.StatusBadRequest)
		return
	}
	s.hold(mb)
	fmt.Fprintf(w, "held %d MiB\n", s.heldMB)
}

func (s *state) hold(mb int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	block := make([]byte, mb<<20)
	for i := 0; i < len(block); i += 4096 {
		block[i] = 1
	}
	s.held = append(s.held, block)
	s.heldMB += mb
}

func (s *state) free(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.held = nil
	s.heldMB = 0
	s.mu.Unlock()
	fmt.Fprintln(w, "released")
}

// config drops a metric on demand, so the missing-evidence case is a request
// rather than a redeploy.
func (s *state) config(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("metric")
	if name == "" {
		http.Error(w, "metric is required", http.StatusBadRequest)
		return
	}
	enabled := r.URL.Query().Get("enabled") != "false"
	s.mu.Lock()
	if enabled {
		delete(s.dropped, name)
	} else {
		s.dropped[name] = true
	}
	s.mu.Unlock()
	fmt.Fprintf(w, "%s enabled=%t\n", name, enabled)
}

// metrics renders the fixed set of app metrics the lab exposes. Names match
// gateway.AllowedMetrics, so the mapping stays a lookup rather than a guess.
func (s *state) metrics(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	held := s.heldMB
	dropped := make(map[string]bool, len(s.dropped))
	for k, v := range s.dropped {
		dropped[k] = v
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	write := func(name, help, kind string, value float64) {
		if dropped[name] {
			return
		}
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s{service=\"memory-test\"} %g\n", name, help, name, kind, name, value)
	}
	write("request_latency_p99_seconds", "p99 request latency", "gauge", float64(s.latencyMicros.Load())/1e6)
	write("request_error_rate", "fraction of requests failing", "gauge", float64(s.errorPerMille.Load())/1000)
	write("db_query_count", "database queries issued", "counter", float64(s.queries.Load()))
	write("memory_test_held_bytes", "bytes the service is holding", "gauge", float64(held)*(1<<20))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
