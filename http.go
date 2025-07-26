package guardedbeaconproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"

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

// If true is returned, the upstream will proxy the request.
type httpGuard func(w http.ResponseWriter, r *http.Request) bool

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
	// Use an io.TeeReader to return a reader that re-writes the body to the original request body.
	buf := bytes.NewBuffer(nil)
	tee := io.TeeReader(r.Body, buf)
	out := io.NopCloser(tee)
	r.Body = io.NopCloser(buf)

	return out, nil
}

func (gbp *GuardedBeaconProxy) httpError(w http.ResponseWriter, code int, err error) {
	w.WriteHeader(code)
	if err != nil {
		escaped, _ := json.Marshal(err.Error())
		fmt.Fprintf(w, "{\"error\":%s}\n", escaped)
	}
}

func (gbp *GuardedBeaconProxy) prepareBeaconProposer(w http.ResponseWriter, r *http.Request) bool {
	reader, err := cloneRequestBody(r)
	if err != nil {
		gbp.httpError(w, http.StatusInternalServerError, nil)
		return false
	}

	var proposers PrepareBeaconProposerRequest
	if err := json.NewDecoder(reader).Decode(&proposers); err != nil {
		gbp.httpError(w, http.StatusBadRequest, nil)
		return false
	}

	status, err := gbp.PrepareBeaconProposerGuard(proposers, r.Context())
	if status != Allowed {
		gbp.httpError(w, status.httpStatus(), err)
		return false
	}

	return true
}

func (gbp *GuardedBeaconProxy) registerValidator(w http.ResponseWriter, r *http.Request) bool {
	reader, err := cloneRequestBody(r)
	if err != nil {
		gbp.httpError(w, http.StatusInternalServerError, nil)
		return false
	}

	// Check the content-type header
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		gbp.httpError(w, http.StatusUnsupportedMediaType, err)
		return false
	}

	var validators RegisterValidatorRequest
	switch contentType {
	case "application/json":
		if err := json.NewDecoder(reader).Decode(&validators); err != nil {
			gbp.httpError(w, http.StatusBadRequest, err)
			return false
		}
	case "application/octet-stream":
		if err, status := ssz.ToRegisterValidatorRequest(&validators, reader, gbp.MaxRequestBodySize); err != nil {
			gbp.httpError(w, status, err)
			return false
		}
	default:
		gbp.httpError(w, http.StatusUnsupportedMediaType, fmt.Errorf("unsupported content type: %s", contentType))
		return false
	}

	status, err := gbp.RegisterValidatorGuard(validators, r.Context())
	if status != Allowed {
		gbp.httpError(w, status.httpStatus(), err)
		return false
	}

	return true
}
