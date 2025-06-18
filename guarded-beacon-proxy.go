package guardedbeaconproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/Rocket-Rescue-Node/guarded-beacon-proxy/jsontypes"
	"github.com/gorilla/mux"
	"github.com/mwitkow/grpc-proxy/proxy"
	"google.golang.org/grpc"
)

type RegisterValidatorRequest = jsontypes.RegisterValidatorRequest
type PrepareBeaconProposerRequest = jsontypes.PrepareBeaconProposerRequest

// PrepareBeaconProposerGuard is a function that validates whether or not a PrepareBeaconProposer call
// should be proxied. The provided Context is whatever was returned by the authenticator.
type PrepareBeaconProposerGuard func(PrepareBeaconProposerRequest, context.Context) (AuthenticationStatus, error)

// RegisterValidatorGuard is a function that validates whether or not a RegisterValidator call
// should be proxied. The provided Context is whatever was returned by the authenticator.
type RegisterValidatorGuard func(RegisterValidatorRequest, context.Context) (AuthenticationStatus, error)

// GuardedBeaconProxy is a reverse proxy for guarding beacon nodes with custom logic.
//
// The main goal is to provide easy hooks for custom request authentication and fee recipient
// validation, which is achieved through the Authenticator and Guard callbacks.
//
// Since Prysm uses gRPC, GuardedBeaconProxy can optionally run a gRPC reverse
// proxy in addition to an HTTP reverse proxy.
//
// If GRPCBeaconURL is set, all GRPC fields are required except the TLS block.
// TLS is currently only supported for gRPC.
//
// Fields in GuardedBeaconProxy should be set prior to calling ListenAndServe.
type GuardedBeaconProxy struct {
	// URL of the upstream beacon node
	BeaconURL *url.URL
	// Optional GRPC URL of the upstream beacon node (prysm grpc port)
	GRPCBeaconURL string

	// Optional TLS certificates for gRPC
	TLS struct {
		// Path to certificate file
		CertFile string
		// Path to key file
		KeyFile string
	}

	// Address to listen for requests on
	Addr string
	// Optional GRPC address to listen on
	GRPCAddr string
	// Maximum request body size in bytes
	// If 0, no limit is applied
	MaxRequestBodySize int64
	// Pass-through HTTP server settings
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int

	ErrorLog *log.Logger

	// Optional authentication function for HTTP requests
	HTTPAuthenticator HTTPAuthenticator
	// Optional authentication function for GRPC requests
	GRPCAuthenticator GRPCAuthenticator

	// Optional PrepareBeaconProposerGuard
	PrepareBeaconProposerGuard PrepareBeaconProposerGuard
	// Optional RegisterValidatorGuard
	RegisterValidatorGuard RegisterValidatorGuard

	server    http.Server
	proxy     *httputil.ReverseProxy
	gRPCProxy *grpc.Server
	upstream  *grpc.ClientConn
}

// Stop attempts to gracefully shut down the GuardedBeaconProxy.
//
// Canceling the provided context will trigger an immediate stop.
func (gbp *GuardedBeaconProxy) Stop(ctx context.Context) {
	if gbp.gRPCProxy != nil {
		go func() {
			<-ctx.Done()
			gbp.gRPCProxy.Stop()
		}()

		go gbp.gRPCProxy.GracefulStop()
	}

	defer gbp.server.Close()
	_ = gbp.server.Shutdown(ctx)
}

func (gbp *GuardedBeaconProxy) httpListen() (net.Listener, error) {
	return net.Listen("tcp", gbp.Addr)
}

func (gbp *GuardedBeaconProxy) grpcListen() (net.Listener, error) {
	return net.Listen("tcp", gbp.GRPCAddr)
}

func (gbp *GuardedBeaconProxy) init() {
	gbp.server.Addr = gbp.Addr
	gbp.server.ReadTimeout = gbp.ReadTimeout
	gbp.server.ReadHeaderTimeout = gbp.ReadHeaderTimeout
	gbp.server.WriteTimeout = gbp.WriteTimeout
	gbp.server.IdleTimeout = gbp.IdleTimeout
	gbp.server.MaxHeaderBytes = gbp.MaxHeaderBytes
	gbp.server.ErrorLog = gbp.ErrorLog
}

func (gbp *GuardedBeaconProxy) limitRequestBodyHandlerFunc(next httpGuard) httpGuard {
	return func(w http.ResponseWriter, r *http.Request) bool {
		if gbp.MaxRequestBodySize == 0 {
			return next(w, r)
		}

		// Allow 1 extra byte. If it actually gets read, we will return an error.
		// This lets us detect if the request body is exactly the size of the limit.
		sizeLimit := gbp.MaxRequestBodySize + 1

		if r.ContentLength >= sizeLimit {
			gbp.httpError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("request body too large"))
			return false
		}

		limited := &io.LimitedReader{
			R: r.Body,
			N: sizeLimit,
		}
		// According to the docs, http servers don't need to close the body ReadCloser, only Clients do.
		r.Body = io.NopCloser(limited)
		shouldProxy := next(w, r)
		if !shouldProxy {
			return false
		}
		if limited.N == 0 {
			// The next handler didn't return an error, but we exceeded the limit.
			// Do not proxy the request, and return StatusRequestEntityTooLarge.
			gbp.httpError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("request body too large"))
			return false
		}
		// The next handler didn't return an error, and we didn't exceed the limit.
		// Proxy the request.
		return true
	}
}

// Serve attaches the proxy to the provided listener(s)
//
// Serve blocks until Stop is called or an error is encountered.
func (gbp *GuardedBeaconProxy) Serve(httpListener net.Listener, grpcListener *net.Listener) error {
	gbp.init()

	gbp.proxy = httputil.NewSingleHostReverseProxy(gbp.BeaconURL)

	router := mux.NewRouter()

	if gbp.PrepareBeaconProposerGuard != nil {
		router.Path("/eth/v1/validator/prepare_beacon_proposer").HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if gbp.limitRequestBodyHandlerFunc(gbp.prepareBeaconProposer)(w, r) {
					gbp.proxy.ServeHTTP(w, r)
				}
			},
		)
	}

	if gbp.RegisterValidatorGuard != nil {
		router.Path("/eth/v1/validator/register_validator").HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if gbp.limitRequestBodyHandlerFunc(gbp.registerValidator)(w, r) {
					gbp.proxy.ServeHTTP(w, r)
				}
			},
		)
	}

	router.PathPrefix("/").Handler(gbp.proxy)

	if gbp.HTTPAuthenticator != nil {
		router.Use(gbp.authenticationMiddleware)
	}

	gbp.server.Handler = router

	httpErrChan := make(chan error)
	go func() {
		httpErrChan <- gbp.server.Serve(httpListener)
		close(httpErrChan)
	}()

	if grpcListener == nil {
		e := <-httpErrChan
		if e == http.ErrServerClosed {
			return nil
		}
		return e
	}

	tc, err := gbp.transportCredentials()
	if err != nil {
		return err
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	gbp.upstream, err = grpc.DialContext(dialCtx,
		gbp.GRPCBeaconURL,
		grpc.WithBlock(),
		grpc.WithTransportCredentials(tc))
	defer cancel()
	if err != nil {
		return fmt.Errorf("error dialing beacon node grpc endpoint: %w", err)
	}

	gbp.gRPCProxy = proxy.NewProxy(gbp.upstream,
		grpc.UnknownServiceHandler(proxy.TransparentHandler(gbp.director())),
		grpc.StreamInterceptor(gbp.payloadInterceptor()))

	grpcErrChan := make(chan error)
	go func() {
		grpcErrChan <- gbp.gRPCProxy.Serve(*grpcListener)
		close(grpcErrChan)
	}()

	// Wait for both servers to exit
	httpErr := <-httpErrChan
	if httpErr != nil && httpErr != http.ErrServerClosed {
		return httpErr
	}

	return <-grpcErrChan

}

// ListenAndServe binds the GuardedBeaconProxy to its HTTP port, and
// optionally its gRPC port, and prepares to receive and proxy
// traffic from validators.
//
// ListenAndServe blocks until Stop is called or an error is encountered.
func (gbp *GuardedBeaconProxy) ListenAndServe() error {
	gbp.init()

	httpListener, err := gbp.httpListen()
	if err != nil {
		return err
	}

	var grpcListener *net.Listener
	if gbp.GRPCBeaconURL != "" {
		l, err := gbp.grpcListen()
		if err != nil {
			return err
		}
		grpcListener = &l
	}

	return gbp.Serve(httpListener, grpcListener)
}
