package guardedbeaconproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Rocket-Rescue-Node/guarded-beacon-proxy/ssz"
)

// HTTPAuthenticator is a function type which can authenticate HTTP requests.
// For example, by checking the contents of the BasicAuth header.
//
// Returning an AuthenticationStatus other than Allowed will prevent the request
// from being proxied. You may optionally return a Context, which will be passed
// to the PrepareBeaconProposerGuard/RegisterValidatorGuard functions provided.
// In particular, conext.WithValue allows the authentication method to share state
// with the guard methods.
//
// Any error returned will be sent back to the client, so do not encode sensitive
// information.
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

	// Check the content-type header
	contentType := r.Header.Get("Content-Type")
	contentType = strings.ToLower(contentType)

	var validators RegisterValidatorRequest
	switch contentType {
	case "application/json":
		if err := json.NewDecoder(buf).Decode(&validators); err != nil {
			gbp.httpError(w, http.StatusBadRequest, err)
			return
		}
	case "application/octet-stream":
		// slurp the body into a buffer
		data, err := io.ReadAll(buf)
		if err != nil {
			gbp.httpError(w, http.StatusInternalServerError, err)
			return
		}

		if err := ssz.ToRegisterValidatorRequest(&validators, data); err != nil {
			gbp.httpError(w, http.StatusBadRequest, err)
			return
		}
	default:
		gbp.httpError(w, http.StatusUnsupportedMediaType, fmt.Errorf("unsupported content type: %s", contentType))
		return
	}

	status, err := gbp.RegisterValidatorGuard(validators, r.Context())
	if status != Allowed {
		gbp.httpError(w, status.httpStatus(), err)
		return
	}

	gbp.proxy.ServeHTTP(w, r)
}
