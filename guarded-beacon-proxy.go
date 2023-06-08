package guardedbeaconproxy

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/gorilla/mux"
	"github.com/mwitkow/grpc-proxy/proxy"
	"google.golang.org/grpc"
)

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
	// Optional URL of the upstream beacon node (prysm grpc port)
	GRPCBeaconURL *url.URL

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
// After gracePeriod has elapsed, the GuardedBeaconProxy will be
// immediately stopped instead.
func (gbp *GuardedBeaconProxy) Stop(gracePeriod time.Duration) {
	go func() {
		time.Sleep(gracePeriod)
		gbp.server.Close()
		if gbp.gRPCProxy != nil {
			gbp.gRPCProxy.Stop()
		}
	}()

	if gbp.gRPCProxy != nil {
		go gbp.gRPCProxy.GracefulStop()
	}
	go gbp.server.Shutdown(context.Background())
}

// ListenAndServe binds the GuardedBeaconProxy to its HTTP port, and
// optionally its gRPC port, and prepares to receive and proxy
// traffic from validators.
//
// ListenAndServe blocks until Stop is called or an error is encountered.
func (gbp *GuardedBeaconProxy) ListenAndServe() error {

	gbp.server.Addr = gbp.Addr
	gbp.server.ReadTimeout = gbp.ReadTimeout
	gbp.server.ReadHeaderTimeout = gbp.ReadHeaderTimeout
	gbp.server.WriteTimeout = gbp.WriteTimeout
	gbp.server.IdleTimeout = gbp.IdleTimeout
	gbp.server.MaxHeaderBytes = gbp.MaxHeaderBytes
	gbp.server.ErrorLog = gbp.ErrorLog

	gbp.proxy = httputil.NewSingleHostReverseProxy(gbp.BeaconURL)

	router := mux.NewRouter()

	if gbp.PrepareBeaconProposerGuard != nil {
		router.Path("/eth/v1/validator/prepare_beacon_proposer").HandlerFunc(gbp.prepareBeaconProposer)
	}

	if gbp.RegisterValidatorGuard != nil {
		router.Path("/eth/v1/validator/register_validator").HandlerFunc(gbp.registerValidator)
	}
	router.PathPrefix("/").Handler(gbp.proxy)

	if gbp.HTTPAuthenticator != nil {
		router.Use(gbp.authenticationMiddleware)
	}

	gbp.server.Handler = router

	httpErrChan := make(chan error)
	go func() {
		httpErrChan <- gbp.server.ListenAndServe()
		close(httpErrChan)
	}()
	defer gbp.server.Close()

	if gbp.GRPCBeaconURL == nil {
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

	gbp.upstream, err = grpc.Dial(gbp.GRPCBeaconURL.String(), grpc.WithTransportCredentials(tc))
	if err != nil {
		return err
	}

	gbp.gRPCProxy = proxy.NewProxy(gbp.upstream,
		grpc.UnknownServiceHandler(proxy.TransparentHandler(gbp.director())),
		grpc.StreamInterceptor(gbp.payloadInterceptor()))

	listener, err := net.Listen("tcp", gbp.GRPCAddr)
	if err != nil {
		return err
	}

	grpcErrChan := make(chan error)
	go func() {
		grpcErrChan <- gbp.gRPCProxy.Serve(listener)
		close(grpcErrChan)
	}()
	defer gbp.gRPCProxy.Stop()

	select {
	case httpErr := <-httpErrChan:
		return httpErr
	case grpcErr := <-grpcErrChan:
		return grpcErr
	}

}
