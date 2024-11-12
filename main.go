package main

import (
	"context"
	"log"
	"net"
	"strconv"
	"time"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	authz_config "authzgcpk8stokeninjector/internal/config"
	authz_logger "authzgcpk8stokeninjector/internal/logger"
	authz_token "authzgcpk8stokeninjector/internal/token"
)

var (
	config authz_config.Config
)

const (
	metadataNamespace = "com.unitvectory.authzgcpk8stokeninjector"
)

type authServer struct {
	pb.UnimplementedAuthorizationServer
}

func main() {
	// Load configuration
	loadedConfig, err := authz_config.LoadConfig()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	config = *loadedConfig

	port := config.Port

	// Validate the port
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		log.Fatalf("invalid port: %v", port)
	}

	// Start the gRPC server
	lis, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthorizationServer(grpcServer, &authServer{})

	// Enable gRPC reflection
	reflection.Register(grpcServer)

	log.Printf("authzjwtbearerinjector service listening on :%s...", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}

func (a *authServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {

	metadataMap := extractMetadataClaims(req, metadataNamespace)

	// Get "audience from metadataMap
	audience, ok := metadataMap["audience"]
	if !ok {
		log.Printf("audience not found in metadata")
		response := createErrorResponse()
		return response, nil
	}

	// Get the identity token
	start := time.Now()
	identityToken, err := authz_token.GetIdentityToken(&config, audience)
	elapsed := time.Since(start)
	authz_logger.DebugLog("GetIdentityToken took %s", elapsed)

	if err != nil {
		log.Printf("Error getting identity token: %v", err)
		response := createErrorResponse()
		return response, nil
	}

	response := &pb.CheckResponse{
		Status: &status.Status{
			Code: int32(0),
		},
		HttpResponse: &pb.CheckResponse_OkResponse{
			OkResponse: &pb.OkHttpResponse{
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "Authorization",
							Value: "Bearer " + identityToken,
						},
					},
				},
			},
		},
	}

	return response, nil
}

func createErrorResponse() *pb.CheckResponse {
	response := &pb.CheckResponse{
		Status: &status.Status{
			Code:    int32(13),
			Message: "Internal server error",
		},
		HttpResponse: &pb.CheckResponse_DeniedResponse{
			DeniedResponse: &pb.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode(500),
				},
				Body: "Failed to request token",
			},
		},
	}
	return response
}

func extractMetadataClaims(req *pb.CheckRequest, namespace string) map[string]string {
	claims := make(map[string]string)
	filterMetadata := req.Attributes.GetRouteMetadataContext().GetFilterMetadata()
	if metadata, ok := filterMetadata[namespace]; ok {
		if fields := metadata.GetFields(); fields != nil {
			for key, value := range fields {
				claims[key] = value.GetStringValue()
			}
		}
	} else {
		authz_logger.DebugLog("%s not found in filter metadata", namespace)
	}

	return claims
}
