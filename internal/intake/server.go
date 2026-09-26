package intake

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// MaxNotificationBytes bounds one webhook body. Alertmanager's own default is
// to send every alert in a group, so this is a ceiling on a hostile or broken
// sender, not on a legitimate burst.
const MaxNotificationBytes = 1 << 20

// Handler serves the intake routes. Every route but /healthz requires the
// bearer token; the read routes are GET-only, so the API can report on
// incidents but never change one.
//
// received, when set, is told about every recorded notification after the
// response is decided and before it is written. It must not block: the server
// queues work there, it never does it.
func Handler(in *Intake, token string, received func(Received)) (http.Handler, error) {
	if token == "" {
		// An empty token would make the constant-time compare accept an
		// empty Authorization header. Refuse to start rather than run open.
		return nil, errors.New("intake: a bearer token is required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.Handle("POST /webhook/alertmanager", authorized(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxNotificationBytes))
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("notification exceeds %d bytes", MaxNotificationBytes))
			return
		case err != nil:
			writeError(w, http.StatusBadRequest, err)
			return
		}
		n, err := Parse(raw)
		if err != nil {
			// A 4xx is not retried by Alertmanager, which is right: the same
			// payload would be refused again.
			writeError(w, http.StatusBadRequest, err)
			return
		}
		outcome, err := in.Receive(n, raw)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if received != nil {
			received(outcome)
		}
		// 202 whatever the outcome: the notification is recorded, and
		// whether it is investigated is intake's decision, not something the
		// sender should retry over.
		writeJSON(w, http.StatusAccepted, outcome)
	})))
	mux.Handle("GET /incidents", authorized(token, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, in.List())
	})))
	mux.Handle("GET /incidents/{id}", authorized(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record, ok := in.Get(r.PathValue("id"))
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("no such incident"))
			return
		}
		writeJSON(w, http.StatusOK, record)
	})))
	return mux, nil
}

func authorized(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="vora-probe"`)
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": strings.TrimSpace(err.Error())})
}
