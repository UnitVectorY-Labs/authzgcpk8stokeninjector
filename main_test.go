package main

import (
	"testing"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/structpb"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

func TestCreateErrorResponse(t *testing.T) {
	response := createErrorResponse()
	if response == nil {
		t.Fatal("expected non-nil response")
	}
	if response.Status == nil {
		t.Fatal("expected non-nil status")
	}
	if response.Status.Code != 13 {
		t.Errorf("expected status code 13 (Internal), got %d", response.Status.Code)
	}
	if response.Status.Message != "Internal server error" {
		t.Errorf("expected message 'Internal server error', got '%s'", response.Status.Message)
	}

	denied, ok := response.HttpResponse.(*pb.CheckResponse_DeniedResponse)
	if !ok {
		t.Fatal("expected DeniedResponse")
	}
	if denied.DeniedResponse.Status.Code != envoy_type.StatusCode(500) {
		t.Errorf("expected HTTP status 500, got %d", denied.DeniedResponse.Status.Code)
	}
	if denied.DeniedResponse.Body != "Failed to request token" {
		t.Errorf("expected body 'Failed to request token', got '%s'", denied.DeniedResponse.Body)
	}
}

func TestExtractMetadataClaims_WithValidMetadata(t *testing.T) {
	namespace := "com.unitvectory.authzgcpk8stokeninjector"

	fields := map[string]*structpb.Value{
		"audience": structpb.NewStringValue("https://example.com"),
	}

	metadata := &structpb.Struct{Fields: fields}

	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			RouteMetadataContext: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					namespace: metadata,
				},
			},
		},
	}

	claims := extractMetadataClaims(req, namespace)
	if len(claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(claims))
	}
	if claims["audience"] != "https://example.com" {
		t.Errorf("expected audience 'https://example.com', got '%s'", claims["audience"])
	}
}

func TestExtractMetadataClaims_MissingNamespace(t *testing.T) {
	namespace := "com.unitvectory.authzgcpk8stokeninjector"

	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			RouteMetadataContext: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					"other.namespace": {
						Fields: map[string]*structpb.Value{
							"audience": structpb.NewStringValue("https://example.com"),
						},
					},
				},
			},
		},
	}

	claims := extractMetadataClaims(req, namespace)
	if len(claims) != 0 {
		t.Errorf("expected 0 claims for missing namespace, got %d", len(claims))
	}
}

func TestExtractMetadataClaims_EmptyMetadata(t *testing.T) {
	namespace := "com.unitvectory.authzgcpk8stokeninjector"

	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			RouteMetadataContext: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{},
			},
		},
	}

	claims := extractMetadataClaims(req, namespace)
	if len(claims) != 0 {
		t.Errorf("expected 0 claims for empty metadata, got %d", len(claims))
	}
}

func TestExtractMetadataClaims_MultipleFields(t *testing.T) {
	namespace := "com.unitvectory.authzgcpk8stokeninjector"

	fields := map[string]*structpb.Value{
		"audience": structpb.NewStringValue("https://example.com"),
		"extra":    structpb.NewStringValue("extra-value"),
	}

	metadata := &structpb.Struct{Fields: fields}

	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			RouteMetadataContext: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					namespace: metadata,
				},
			},
		},
	}

	claims := extractMetadataClaims(req, namespace)
	if len(claims) != 2 {
		t.Fatalf("expected 2 claims, got %d", len(claims))
	}
	if claims["audience"] != "https://example.com" {
		t.Errorf("expected audience 'https://example.com', got '%s'", claims["audience"])
	}
	if claims["extra"] != "extra-value" {
		t.Errorf("expected extra 'extra-value', got '%s'", claims["extra"])
	}
}

func TestExtractMetadataClaims_NilRouteMetadata(t *testing.T) {
	namespace := "com.unitvectory.authzgcpk8stokeninjector"

	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{},
	}

	claims := extractMetadataClaims(req, namespace)
	if len(claims) != 0 {
		t.Errorf("expected 0 claims for nil route metadata, got %d", len(claims))
	}
}
