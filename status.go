package guardedbeaconproxy

import (
	"net/http"

	"google.golang.org/grpc/codes"
)

// AuthenticationStatus is a generic status response representing auth or guard
// results.
//
// It is returned by the custom authentication or guard functions on the GuardedBeaconProxy,
// and mapped to an appropriate HTTP or gRPC error as needed.
type AuthenticationStatus uint32

// These constants are the only allowable AuthenticationStatus values
const (
	Allowed AuthenticationStatus = iota
	BadRequest
	Unauthorized
	Forbidden
	Conflict
	TooManyRequests
	InternalError
)

func (a AuthenticationStatus) httpStatus() int {
	switch a {
	case Allowed:
		return http.StatusOK
	case BadRequest:
		return http.StatusBadRequest
	case Unauthorized:
		return http.StatusUnauthorized
	case Forbidden:
		return http.StatusForbidden
	case Conflict:
		return http.StatusConflict
	case TooManyRequests:
		return http.StatusTooManyRequests
	case InternalError:
		return http.StatusInternalServerError
	}

	return http.StatusNotImplemented
}

func (a AuthenticationStatus) grpcStatus() codes.Code {
	switch a {
	case Allowed:
		return codes.OK
	case BadRequest:
		return codes.InvalidArgument
	case Unauthorized:
		return codes.Unauthenticated
	case Forbidden:
		return codes.PermissionDenied
	case Conflict:
		return codes.FailedPrecondition
	case TooManyRequests:
		return codes.ResourceExhausted
	case InternalError:
		return codes.Internal
	}

	return codes.Unimplemented

}
