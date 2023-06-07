package guarded_beacon_proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type HTTPAuthenticator func(*http.Request) (AuthenticationStatus, context.Context, error)

func (gbp *GuardedBeaconProxy) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, context, err := gbp.HTTPAuthenticator(r)

		if status == Allowed {
			if context != nil {
				next.ServeHTTP(w, r.WithContext(context))
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		gbp.httpError(w, status.httpStatus(), err)
		return
	})
}

func cloneRequestBody(r *http.Request) (io.ReadCloser, error) {
	// Read the body
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	original := io.NopCloser(bytes.NewBuffer(buf))
	clone := io.NopCloser(bytes.NewBuffer(buf))
	r.Body = original
	return clone, nil
}

func (gbp *GuardedBeaconProxy) httpError(w http.ResponseWriter, code int, err error) {
	w.WriteHeader(code)
	if err != nil {
		escaped, _ := json.Marshal(err.Error())
		fmt.Fprintf(w, "{\"error\":%s}\n", escaped)
	}
}

func (gbp *GuardedBeaconProxy) prepareBeaconProposer(w http.ResponseWriter, r *http.Request) {
	buf, err := cloneRequestBody(r)
	if err != nil {
		gbp.httpError(w, http.StatusInternalServerError, nil)
		return
	}

	var proposers PrepareBeaconProposerRequest
	if err := json.NewDecoder(buf).Decode(&proposers); err != nil {
		gbp.httpError(w, http.StatusBadRequest, nil)
		return
	}

	status, err := gbp.PrepareBeaconProposerGuard(proposers, r.Context())
	if status != Allowed {
		gbp.httpError(w, status.httpStatus(), err)
		return
	}

	gbp.proxy.ServeHTTP(w, r)
}

func (gbp *GuardedBeaconProxy) registerValidator(w http.ResponseWriter, r *http.Request) {
	buf, err := cloneRequestBody(r)
	if err != nil {
		gbp.httpError(w, http.StatusInternalServerError, nil)
		return
	}

	var validators RegisterValidatorRequest
	if err := json.NewDecoder(buf).Decode(&validators); err != nil {
		gbp.httpError(w, http.StatusBadRequest, nil)
		return
	}

	status, err := gbp.RegisterValidatorGuard(validators, r.Context())
	if status != Allowed {
		gbp.httpError(w, status.httpStatus(), err)
		return
	}

	gbp.proxy.ServeHTTP(w, r)
}
