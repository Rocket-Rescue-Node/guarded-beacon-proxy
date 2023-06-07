package guarded_beacon_proxy

import (
	"net/http"

	"google.golang.org/grpc/codes"
)

type AuthenticationStatus uint32

const (
	Allowed AuthenticationStatus = iota
	BadRequest
	Unauthorized
	Forbidden
	Conflict
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
	case InternalError:
		return codes.Internal
	}

	return codes.Unimplemented

}
