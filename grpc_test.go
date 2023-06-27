package guardedbeaconproxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ethpbv1alpha1 "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"golang.org/x/net/nettest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gotest.tools/assert"

	empty "google.golang.org/protobuf/types/known/emptypb"
)

var goodRecipient []byte = []byte{
	0xab,
	0xcf,
	0x8e,
	0x0d,
	0x4e,
	0x95,
	0x87,
	0x36,
	0x9b,
	0x23,
	0x01,
	0xd0,
	0x79,
	0x03,
	0x47,
	0x32,
	0x03,
	0x02,
	0xcc,
	0x09,
}

type mockServer struct {
	ethpbv1alpha1.UnimplementedBeaconNodeValidatorServer
}

func feeRecipientShouldOK(actual string) bool {
	fr, err := hexutil.Decode(actual)
	if err != nil {
		return false
	}

	return bytes.EqualFold(fr, goodRecipient)
}

func (m *mockServer) PrepareBeaconProposer(ctx context.Context, req *ethpbv1alpha1.PrepareBeaconProposerRequest) (*empty.Empty, error) {

	return &empty.Empty{}, nil
}

func (m *mockServer) SubmitValidatorRegistrations(ctx context.Context, req *ethpbv1alpha1.SignedValidatorRegistrationsV1) (*empty.Empty, error) {

	return &empty.Empty{}, nil
}

func grpcTestServer(t *testing.T) (*grpc.Server, net.Listener, chan error) {
	errChan := make(chan error)
	out := grpc.NewServer()

	srv := &mockServer{}

	ethpbv1alpha1.RegisterBeaconNodeValidatorServer(out, srv)

	listener, err := nettest.NewLocalListener("tcp")
	if err != nil {
		t.Error(err)
	}
	t.Logf("upstream proto listening on %s\n", listener.Addr())

	go func() {
		err := out.Serve(listener)
		if err != nil {
			errChan <- err
		}
		close(errChan)
	}()

	return out, listener, errChan
}

func newGRPCGbp(t *testing.T, upstream net.Listener, httpUpstream *httptest.Server) (out *GuardedBeaconProxy, start func(t *testing.T), stop func()) {
	out = &GuardedBeaconProxy{}

	listener, err := nettest.NewLocalListener("tcp")
	if err != nil {
		t.Error(err)
	}
	t.Logf("proxy http listening on %s\n", listener.Addr())

	grpcListener, err := nettest.NewLocalListener("tcp")
	if err != nil {
		t.Error(err)
	}
	t.Logf("proxy proto listening on %s\n", grpcListener.Addr())

	out.Addr = listener.Addr().String()
	out.GRPCAddr = grpcListener.Addr().String()

	start = func(t *testing.T) {
		err := out.Serve(listener, &grpcListener)
		if err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	}

	stop = func() {
		ctx, _ := context.WithTimeout(context.Background(), time.Second*3)
		out.Stop(ctx)
	}

	// Assign the http upstream
	u, err := url.Parse(httpUpstream.URL)
	t.Logf("proxy connecting to http server on %s\n", httpUpstream.URL)
	if err != nil {
		t.Error(err)
	}

	out.BeaconURL = u

	// Assign the grpcupstream
	out.GRPCBeaconURL = upstream.Addr().String()
	t.Logf("proxy connecting to grpc server on %s\n", out.GRPCBeaconURL)
	return
}

func dial(t *testing.T, addr string) (*grpc.ClientConn, error) {
	return grpc.Dial(addr,
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

func prepareBeaconProposer(client ethpbv1alpha1.BeaconNodeValidatorClient, customFeeRecipient []byte, kvs ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	pbp := ethpbv1alpha1.PrepareBeaconProposerRequest{
		Recipients: make([]*ethpbv1alpha1.PrepareBeaconProposerRequest_FeeRecipientContainer, 1, 1),
	}
	pbp.Recipients[0] = new(ethpbv1alpha1.PrepareBeaconProposerRequest_FeeRecipientContainer)
	if customFeeRecipient == nil {
		pbp.Recipients[0].FeeRecipient = goodRecipient
	} else {
		pbp.Recipients[0].FeeRecipient = customFeeRecipient
	}

	if len(kvs)%2 != 0 {
		return fmt.Errorf("kvs must be even length")
	}
	ctx = metadata.AppendToOutgoingContext(ctx, kvs...)
	_, err := client.PrepareBeaconProposer(ctx, &pbp)
	return err
}

func registerValidator(client ethpbv1alpha1.BeaconNodeValidatorClient, customFeeRecipient []byte, kvs ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	rv := ethpbv1alpha1.SignedValidatorRegistrationsV1{
		Messages: make([]*ethpbv1alpha1.SignedValidatorRegistrationV1, 1, 1),
	}
	rv.Messages[0] = new(ethpbv1alpha1.SignedValidatorRegistrationV1)
	rv.Messages[0].Message = new(ethpbv1alpha1.ValidatorRegistrationV1)
	if customFeeRecipient == nil {
		rv.Messages[0].Message.FeeRecipient = goodRecipient
	} else {
		rv.Messages[0].Message.FeeRecipient = customFeeRecipient
	}

	if len(kvs)%2 != 0 {
		return fmt.Errorf("kvs must be even length")
	}
	ctx = metadata.AppendToOutgoingContext(ctx, kvs...)
	_, err := client.SubmitValidatorRegistrations(ctx, &rv)
	return err
}

func pre(t *testing.T) (*GuardedBeaconProxy, func() ethpbv1alpha1.BeaconNodeValidatorClient, func(t *testing.T) error) {
	var conn *grpc.ClientConn
	httpTS := testServer(handlerOK(), handlerOK(), handlerOK())
	t.Logf("set up upstream http")

	ts, listener, errChan := grpcTestServer(t)
	t.Logf("set up upstream grpc")

	gbp, start, stop := newGRPCGbp(t, listener, httpTS)
	rstart := func() ethpbv1alpha1.BeaconNodeValidatorClient {
		var err error
		go start(t)
		t.Logf("set up proxy")
		// Dial the proxy
		conn, err = dial(t, gbp.GRPCAddr)
		if err != nil {
			t.Error(err)
		}
		t.Logf("connected to proxy")
		return ethpbv1alpha1.NewBeaconNodeValidatorClient(conn)
	}

	rstop := func(t *testing.T) error {
		stop()
		t.Logf("stopped proxy")
		ts.Stop()
		t.Logf("stopped upstream grpc")

		err := <-errChan
		conn.Close()
		httpTS.Close()
		if err != nil && err != grpc.ErrServerStopped {
			return err
		}
		return nil
	}

	return gbp, rstart, rstop
}

func TestUnguardedUnauthedGRPC(t *testing.T) {
	_, start, stop := pre(t)
	client := start()
	err := prepareBeaconProposer(client, nil)
	if err != nil {
		t.Error(err)
	}

	err = registerValidator(client, nil)
	if err != nil {
		t.Error(err)
	}

	err = stop(t)
	if err != nil {
		t.Error(err)
	}
}

func TestUnguardedAuthedGRPC(t *testing.T) {
	mdKey := "testkey"
	mdConflict := "alice"
	mdBadReq := "said"
	mdForbidden := "very"
	mdInternal := "humbly"
	mdAllowed := "dormouse"
	gbp, start, stop := pre(t)

	gbp.GRPCAuthenticator = func(md metadata.MD) (AuthenticationStatus, context.Context, error) {
		t.Log("grpc metadata", fmt.Sprint(md))
		val, exists := md[mdKey]
		if !exists || len(val) < 1 {
			return Unauthorized, nil, fmt.Errorf("missing auth")
		}

		p := val[0]
		if p == mdConflict {
			return Conflict, nil, fmt.Errorf("conflict auth")
		}

		if p == mdBadReq {
			return BadRequest, nil, fmt.Errorf("bad req")
		}

		if p == mdForbidden {
			return Forbidden, nil, fmt.Errorf("forbidden")
		}

		if p == mdInternal {
			return InternalError, nil, fmt.Errorf("internal")
		}

		return Allowed, nil, nil
	}

	client := start()
	err := prepareBeaconProposer(client, nil)
	assert.Equal(t, status.Code(err), Unauthorized.grpcStatus())

	err = registerValidator(client, nil)
	assert.Equal(t, status.Code(err), Unauthorized.grpcStatus())

	err = prepareBeaconProposer(client, nil, mdKey, mdConflict)
	assert.Equal(t, status.Code(err), Conflict.grpcStatus())

	err = registerValidator(client, nil, mdKey, mdConflict)
	assert.Equal(t, status.Code(err), Conflict.grpcStatus())

	err = prepareBeaconProposer(client, nil, mdKey, mdInternal)
	assert.Equal(t, status.Code(err), InternalError.grpcStatus())

	err = registerValidator(client, nil, mdKey, mdInternal)
	assert.Equal(t, status.Code(err), InternalError.grpcStatus())

	err = prepareBeaconProposer(client, nil, mdKey, mdForbidden)
	assert.Equal(t, status.Code(err), Forbidden.grpcStatus())

	err = registerValidator(client, nil, mdKey, mdForbidden)
	assert.Equal(t, status.Code(err), Forbidden.grpcStatus())

	err = prepareBeaconProposer(client, nil, mdKey, mdBadReq)
	assert.Equal(t, status.Code(err), BadRequest.grpcStatus())

	err = registerValidator(client, nil, mdKey, mdBadReq)
	assert.Equal(t, status.Code(err), BadRequest.grpcStatus())

	err = prepareBeaconProposer(client, nil, mdKey, mdAllowed)
	assert.Equal(t, status.Code(err), Allowed.grpcStatus())

	err = registerValidator(client, nil, mdKey, mdAllowed)
	assert.Equal(t, status.Code(err), Allowed.grpcStatus())

	err = stop(t)
	if err != nil {
		t.Error(err)
	}
}

func TestGRPCGuardedUnauthedWithContext(t *testing.T) {
	gbp, start, stop := pre(t)

	gbp.GRPCAuthenticator = func(md metadata.MD) (AuthenticationStatus, context.Context, error) {

		return Allowed, context.WithValue(context.Background(), "testkey", "testvalue"), nil
	}

	gbp.PrepareBeaconProposerGuard = func(r PrepareBeaconProposerRequest, ctx context.Context) (AuthenticationStatus, error) {
		if ctx.Value("testkey") != "testvalue" {
			return InternalError, fmt.Errorf("passthrough failed")
		}

		if len(r) == 0 {
			return Allowed, nil
		}

		for _, m := range r {
			if !feeRecipientShouldOK(m.FeeRecipient) {
				return Conflict, nil
			}
		}

		return Allowed, nil
	}

	gbp.RegisterValidatorGuard = func(r RegisterValidatorRequest, ctx context.Context) (AuthenticationStatus, error) {
		if ctx.Value("testkey") != "testvalue" {
			return InternalError, fmt.Errorf("passthrough failed")
		}

		if len(r) == 0 {
			return Allowed, nil
		}

		for _, m := range r {

			if !feeRecipientShouldOK(m.Message.FeeRecipient) {
				return Conflict, nil
			}
		}

		return Allowed, nil
	}

	client := start()

	t.Log("First batch")
	err := prepareBeaconProposer(client, goodRecipient)
	if err != nil {
		t.Log(err)
	}
	assert.Equal(t, status.Code(err), Allowed.grpcStatus())
	err = registerValidator(client, goodRecipient)
	if err != nil {
		t.Log(err)
	}
	assert.Equal(t, status.Code(err), Allowed.grpcStatus())

	err = prepareBeaconProposer(client, make([]byte, 20, 20))
	if err != nil {
		t.Log(err)
	}
	assert.Equal(t, status.Code(err), InternalError.grpcStatus())
	err = registerValidator(client, make([]byte, 20, 20))
	if err != nil {
		t.Log(err)
	}
	assert.Equal(t, status.Code(err), InternalError.grpcStatus())

	err = stop(t)
	if err != nil {
		t.Error(err)
	}
}
