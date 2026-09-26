// Package live is the gateway that reads a running lab: Prometheus for metrics,
// the Kubernetes API for object state.
//
// It is the second implementation of the gateway port. The discipline is
// deliberately identical to the fixture gateway's: authorize, query through an
// explicit mapping, bound the answer, redact it, and record a digest of exactly
// what came back. What is *not* reimplemented is policy — that is the same
// gateway.Policy the offline path uses, so a permission cannot differ between
// replay and a live run.
//
// There is no discovery anywhere here. Every metric an action may name maps to a
// fixed query, because a free-form PromQL surface would be exactly the generic
// discovery engine the plan rules out.
package live

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vorash/vora-probe/gateway"
)

// KubernetesConfig is the investigator's REST access. It carries explicit
// fields rather than a kubeconfig path so the module stays dependency-free; the
// operator reads the ServiceAccount token and CA out of the cluster once.
type KubernetesConfig struct {
	Server string
	Token  string
	// CAFile is the API server CA bundle. A kubeconfig's certificate-authority-data
	// decodes to exactly this.
	CAFile string
}

type Config struct {
	PrometheusURL string
	Kubernetes    KubernetesConfig
	// Namespace scopes every object request. The lab is one namespace, and the
	// gateway never widens that.
	Namespace string
	Policy    gateway.Policy
	Timeout   time.Duration
	Now       func() time.Time
}

type Gateway struct {
	cfg      Config
	http     *http.Client
	k8s      *http.Client
	executed int
}

func New(cfg Config) (*Gateway, error) {
	if strings.TrimSpace(cfg.PrometheusURL) == "" {
		return nil, errors.New("live: a Prometheus URL is required")
	}
	if strings.TrimSpace(cfg.Kubernetes.Server) == "" {
		return nil, errors.New("live: a Kubernetes API server is required")
	}
	if strings.TrimSpace(cfg.Namespace) == "" {
		return nil, errors.New("live: a namespace is required")
	}
	if cfg.Policy.MaxResponseBytes <= 0 {
		cfg.Policy = gateway.DefaultPolicy()
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	// A redirect is an unapproved destination, in either datasource.
	refuseRedirect := func(*http.Request, []*http.Request) error {
		return errors.New("live: redirects are refused; the destination was not approved by policy")
	}
	g := &Gateway{
		cfg:  cfg,
		http: &http.Client{Timeout: timeout, CheckRedirect: refuseRedirect},
	}
	g.k8s = &http.Client{Timeout: timeout, CheckRedirect: refuseRedirect}
	if cfg.Kubernetes.CAFile != "" {
		pem, err := os.ReadFile(cfg.Kubernetes.CAFile)
		if err != nil {
			return nil, fmt.Errorf("live: read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("live: CA file contains no certificates")
		}
		g.k8s.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}}
	}
	return g, nil
}

func (g *Gateway) Executed() int { return g.executed }

// Execute authorizes, answers and bounds one request. The order matters: policy
// runs before any I/O, and the size bound is applied to the encoded answer
// before the answer is returned.
func (g *Gateway) Execute(a gateway.Action) (gateway.Response, error) {
	if err := g.cfg.Policy.Authorize(a); err != nil {
		return gateway.Response{}, err
	}

	var (
		resp gateway.Response
		err  error
	)
	switch a.Kind {
	case gateway.ActionMetricsQuery:
		resp, err = g.metricSeries(a)
	case gateway.ActionKubernetesContainers:
		resp, err = g.containers(a)
	case gateway.ActionKubernetesEvents:
		resp, err = g.events(a)
	case gateway.ActionKubernetesDeployments:
		resp, err = g.deployments(a)
	case gateway.ActionLogsQuery:
		// Without a log source the answer is a visible coverage gap. Denying
		// would end the run over evidence that is merely not collected here.
		resp, err = g.response(a, gateway.QueryMeta{Datasource: "loki"}, nil, gateway.StatusUnavailable, gateway.Unavailable,
			"no log source is configured for this lab")
	default:
		return gateway.Response{}, &gateway.Denied{Reason: fmt.Sprintf("action %q has no live adapter", a.Kind)}
	}
	if err != nil {
		return gateway.Response{}, err
	}

	resp = gateway.RedactResponse(resp)
	encoded, err := json.Marshal(resp)
	if err != nil {
		return gateway.Response{}, err
	}
	if err := g.cfg.Policy.Accept(a, resp, int64(len(encoded))); err != nil {
		return gateway.Response{}, err
	}
	g.executed++
	return resp, nil
}

// response assembles the envelope. Digest is taken over the payload as returned,
// before redaction, which is what lets RedactResponse mark Completeness and keep
// the digest meaningful.
func (g *Gateway) response(a gateway.Action, query gateway.QueryMeta, payload any, status gateway.ResponseStatus, completeness gateway.Completeness, reason string) (gateway.Response, error) {
	resp := gateway.Response{
		SchemaVersion: gateway.SchemaVersion,
		Kind:          a.Kind,
		Entity:        a.Entity,
		Status:        status,
		Completeness:  completeness,
		RetrievedAt:   g.cfg.Now(),
		Query:         query,
		Reason:        reason,
	}
	if payload == nil {
		resp.Digest = gateway.Digest(nil)
		return resp, nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return gateway.Response{}, err
	}
	resp.Payload = raw
	resp.Digest = gateway.Digest(raw)
	return resp, nil
}
