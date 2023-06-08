package guardedbeaconproxy

import (
	"context"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/mwitkow/grpc-proxy/proxy"
	prysmpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// GRPCAuthenticator is a function type that authenticates gRPC traffic.
// The authentication method must be based on gRPC Metadata, as gRPC does not
// support BasicAuth out of box.
//
// Returning an AuthenticationStatus other than Allowed will prevent the request
// from being proxied. You may optionally return a Context, which will be passed
// to the PrepareBeaconProposerGuard/RegisterValidatorGuard functions provided.
// In particular, conext.WithValue allows the authentication method to share state
// with the guard methods.
//
// Any error returned will be sent back to the client, so do not encode sensitive
// information.
type GRPCAuthenticator func(metadata.MD) (AuthenticationStatus, context.Context, error)

type prepareBeaconProposerStreamGuard struct {
	grpc.ServerStream
	gbp *GuardedBeaconProxy
	ctx context.Context
}

func (g *prepareBeaconProposerStreamGuard) SendMsg(m interface{}) error {
	return g.ServerStream.SendMsg(m)
}

func (g *prepareBeaconProposerStreamGuard) RecvMsg(m interface{}) error {
	pbMsg, ok := m.(proto.Message)
	if !ok {
		return status.Error(codes.Internal, "invalid request")
	}

	pbp := &prysmpb.PrepareBeaconProposerRequest{}

	unknown := []byte(pbMsg.ProtoReflect().GetUnknown())
	err := proto.Unmarshal(unknown, pbp)
	if err != nil {
		return status.Error(codes.Internal, "internal error")
	}

	normalized := make(PrepareBeaconProposerRequest, len(pbp.Recipients))
	for i, recipient := range pbp.Recipients {
		normalized[i].ValidatorIndex = strconv.FormatUint(uint64(recipient.ValidatorIndex), 10)
		normalized[i].FeeRecipient = common.BytesToAddress(recipient.FeeRecipient).String()
	}

	s, err := g.gbp.PrepareBeaconProposerGuard(normalized, g.ctx)
	if s == Allowed {
		return g.ServerStream.RecvMsg(m)
	}

	msg := ""
	if err != nil {
		msg = err.Error()
	}

	return status.Error(s.grpcStatus(), msg)
}

type submitValidatorRegistrationsStreamGuard prepareBeaconProposerStreamGuard

func (g *submitValidatorRegistrationsStreamGuard) SendMsg(m interface{}) error {
	return g.ServerStream.SendMsg(m)
}

func (g *submitValidatorRegistrationsStreamGuard) RecvMsg(m interface{}) error {
	pbMsg, ok := m.(proto.Message)
	if !ok {
		return status.Error(codes.Internal, "invalid request")
	}

	svr := &prysmpb.SignedValidatorRegistrationsV1{}

	unknown := []byte(pbMsg.ProtoReflect().GetUnknown())
	err := proto.Unmarshal(unknown, svr)
	if err != nil {
		return status.Error(codes.Internal, "internal error")
	}

	normalized := make(RegisterValidatorRequest, len(svr.Messages))
	for i, message := range svr.Messages {
		normalized[i].Signature = "0x" + hex.EncodeToString(message.Signature)
		normalized[i].Message.FeeRecipient = common.BytesToAddress(message.Message.FeeRecipient).String()
		normalized[i].Message.GasLimit = strconv.FormatUint(uint64(message.Message.GasLimit), 10)
		normalized[i].Message.Timestamp = strconv.FormatUint(uint64(message.Message.Timestamp), 10)
		normalized[i].Message.Pubkey = "0x" + hex.EncodeToString(message.Message.Pubkey)
	}

	s, err := g.gbp.RegisterValidatorGuard(normalized, g.ctx)
	if s == Allowed {
		return g.ServerStream.RecvMsg(m)
	}

	msg := ""
	if err != nil {
		msg = err.Error()
	}

	return status.Error(s.grpcStatus(), msg)
}

func (gbp *GuardedBeaconProxy) payloadInterceptor() grpc.StreamServerInterceptor {
	services := map[string]any{
		"ethereum.eth.v1alpha1.BeaconChain":         struct{}{},
		"ethereum.eth.v1alpha1.BeaconNodeValidator": struct{}{},
		"ethereum.eth.v1alpha1.Node":                struct{}{},
	}

	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

		method := strings.Split(info.FullMethod, "/")
		_, matched := services[method[1]]
		if !matched {
			return status.Errorf(codes.Unimplemented, "unknown service %s", method[1])
		}

		var authCtx context.Context

		if gbp.GRPCAuthenticator != nil {
			ctx := stream.Context()
			md, exists := metadata.FromIncomingContext(ctx)
			if !exists {
				return status.Error(codes.Unauthenticated, "no metadata on inbound request")
			}

			s, ctx, err := gbp.GRPCAuthenticator(md)
			if s != Allowed {
				msg := ""
				if err != nil {
					msg = err.Error()
				}
				return status.Error(s.grpcStatus(), msg)
			}
			authCtx = ctx
		}

		if method[2] == "PrepareBeaconProposer" && gbp.PrepareBeaconProposerGuard != nil {

			wrapper := &prepareBeaconProposerStreamGuard{
				ServerStream: stream,
				gbp:          gbp,
				ctx:          authCtx,
			}

			return handler(srv, wrapper)
		} else if method[2] == "SubmitValidatorRegistrations" && gbp.RegisterValidatorGuard != nil {
			wrapper := &submitValidatorRegistrationsStreamGuard{
				ServerStream: stream,
				gbp:          gbp,
				ctx:          authCtx,
			}

			return handler(srv, wrapper)
		}
		return handler(srv, stream)
	}
}

func (gbp *GuardedBeaconProxy) director() proxy.StreamDirector {
	return func(ctx context.Context, fullMethodName string) (context.Context, *grpc.ClientConn, error) {

		return ctx, nil, status.Error(codes.Internal, "director should not be invoked")
	}
}

func (gbp *GuardedBeaconProxy) transportCredentials() (credentials.TransportCredentials, error) {
	if gbp.TLS.CertFile == "" {
		return insecure.NewCredentials(), nil
	}

	return credentials.NewServerTLSFromFile(gbp.TLS.CertFile, gbp.TLS.KeyFile)
}
