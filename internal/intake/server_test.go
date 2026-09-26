package intake

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const testToken = "s3cret-token"

func newServer(t *testing.T) (*httptest.Server, *Intake) {
	t.Helper()
	in := newIntake(receivedAt)
	h, err := Handler(in, testToken)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, in
}

func do(t *testing.T, method, url, token string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return raw
}

// The webhook is the only way in, so it is the route that must refuse a caller
// without the token; health stays open so a probe can check liveness without
// holding a credential.
func TestTheWebhookRequiresTheBearerToken(t *testing.T) {
	srv, in := newServer(t)
	body := readFixture(t, "firing.json")
	for name, token := range map[string]string{"missing": "", "wrong": "s3cret-tokeN", "prefix": "s3cret"} {
		if resp := do(t, http.MethodPost, srv.URL+"/webhook/alertmanager", token, body); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s token: status %d, want 401", name, resp.StatusCode)
		}
	}
	if len(in.List()) != 0 {
		t.Fatal("an unauthorized notification was recorded")
	}
	resp := do(t, http.MethodPost, srv.URL+"/webhook/alertmanager", testToken, body)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("authorized notification: status %d, want 202", resp.StatusCode)
	}
	var got Received
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Outcome != OutcomeOpened {
		t.Fatalf("outcome = %q, want opened", got.Outcome)
	}
	if resp := do(t, http.MethodGet, srv.URL+"/healthz", "", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: status %d, want 200 without a token", resp.StatusCode)
	}
	for _, path := range []string{"/incidents", "/incidents/" + got.IncidentID} {
		if resp := do(t, http.MethodGet, srv.URL+path, "", nil); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a token: status %d, want 401", path, resp.StatusCode)
		}
	}
}

// An empty token would make every request authorized, because an empty header
// compares equal to it. The server refuses to start instead.
func TestTheHandlerRefusesAnEmptyToken(t *testing.T) {
	if _, err := Handler(newIntake(receivedAt), ""); err == nil {
		t.Fatal("a handler without a token must not be built")
	}
}

// The incident routes report; they never change anything. A write verb must be
// refused by the router, not by a handler that could grow a branch for it.
func TestTheIncidentRoutesAreReadOnly(t *testing.T) {
	srv, _ := newServer(t)
	resp := do(t, http.MethodPost, srv.URL+"/webhook/alertmanager", testToken, readFixture(t, "firing.json"))
	var opened Received
	if err := json.NewDecoder(resp.Body).Decode(&opened); err != nil {
		t.Fatalf("decode: %v", err)
	}

	list := do(t, http.MethodGet, srv.URL+"/incidents", testToken, nil)
	var records []Record
	if err := json.NewDecoder(list.Body).Decode(&records); err != nil || len(records) != 1 {
		t.Fatalf("GET /incidents: %d records (err %v), want 1", len(records), err)
	}
	one := do(t, http.MethodGet, srv.URL+"/incidents/"+opened.IncidentID, testToken, nil)
	var record Record
	if err := json.NewDecoder(one.Body).Decode(&record); err != nil || record.Incident.ID != opened.IncidentID {
		t.Fatalf("GET /incidents/{id}: got %q (err %v), want %s", record.Incident.ID, err, opened.IncidentID)
	}
	if resp := do(t, http.MethodGet, srv.URL+"/incidents/INC-nope", testToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown incident: status %d, want 404", resp.StatusCode)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		for _, path := range []string{"/incidents", "/incidents/" + opened.IncidentID} {
			if resp := do(t, method, srv.URL+path, testToken, []byte(`{}`)); resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: status %d, want 405", method, path, resp.StatusCode)
			}
		}
	}
}

// A payload Probe cannot act on is refused with a 4xx, which Alertmanager does
// not retry; an oversized one is refused before it is buffered.
func TestTheWebhookRefusesBadPayloads(t *testing.T) {
	srv, in := newServer(t)
	if resp := do(t, http.MethodPost, srv.URL+"/webhook/alertmanager", testToken, []byte(`{"version":"4"`)); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed payload: status %d, want 400", resp.StatusCode)
	}
	huge := append([]byte(`{"version":"4","groupKey":"`), bytes.Repeat([]byte("x"), MaxNotificationBytes)...)
	if resp := do(t, http.MethodPost, srv.URL+"/webhook/alertmanager", testToken, huge); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized payload: status %d, want 413", resp.StatusCode)
	}
	if len(in.List()) != 0 || len(in.Unmapped()) != 0 {
		t.Fatal("a refused payload must not be recorded as a notification")
	}
}
