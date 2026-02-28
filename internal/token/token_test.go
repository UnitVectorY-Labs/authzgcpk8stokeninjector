package token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	authz_config "github.com/UnitVectorY-Labs/authzgcpk8stokeninjector/internal/config"
)

func TestExchangeToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		var req STSRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}

		if req.GrantType != grantType {
			t.Errorf("expected grant_type '%s', got '%s'", grantType, req.GrantType)
		}
		if req.SubjectToken != "test-k8s-token" {
			t.Errorf("expected subject_token 'test-k8s-token', got '%s'", req.SubjectToken)
		}

		resp := STSResponse{
			AccessToken: "test-access-token",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Override the STS URL for testing
	defer func() { stsUrlOverride = "" }()
	stsUrlOverride = server.URL

	config := &authz_config.Config{
		ProjectNumber:        "123456789",
		WorkloadIdentityPool: "test-pool",
		WorkloadProvider:     "test-provider",
	}

	token, err := exchangeToken(config, "test-k8s-token")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "test-access-token" {
		t.Errorf("expected 'test-access-token', got '%s'", token)
	}
}

func TestExchangeToken_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	defer func() { stsUrlOverride = "" }()
	stsUrlOverride = server.URL

	config := &authz_config.Config{
		ProjectNumber:        "123456789",
		WorkloadIdentityPool: "test-pool",
		WorkloadProvider:     "test-provider",
	}

	_, err := exchangeToken(config, "test-k8s-token")
	if err == nil {
		t.Fatal("expected error for server error response, got nil")
	}
	if !strings.Contains(err.Error(), "STS returned non-OK status") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestExchangeToken_EmptyAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := STSResponse{
			AccessToken: "",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	defer func() { stsUrlOverride = "" }()
	stsUrlOverride = server.URL

	config := &authz_config.Config{
		ProjectNumber:        "123456789",
		WorkloadIdentityPool: "test-pool",
		WorkloadProvider:     "test-provider",
	}

	_, err := exchangeToken(config, "test-k8s-token")
	if err == nil {
		t.Fatal("expected error for empty access token, got nil")
	}
	if !strings.Contains(err.Error(), "empty access token") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGenerateIdentityToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-access-token" {
			t.Errorf("expected 'Bearer test-access-token', got '%s'", auth)
		}

		var req IAMRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		if req.Audience != "https://example.com" {
			t.Errorf("expected audience 'https://example.com', got '%s'", req.Audience)
		}
		if !req.IncludeEmail {
			t.Error("expected includeEmail to be true")
		}

		resp := IAMResponse{Token: "test-identity-token"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Override the service account URL pattern for testing
	defer func() { serviceAccountUrlPatternOverride = "" }()
	serviceAccountUrlPatternOverride = server.URL + "/%s"

	config := &authz_config.Config{
		ServiceAccountEmail: "test@test-project.iam.gserviceaccount.com",
	}

	token, err := generateIdentityToken(config, "test-access-token", "https://example.com")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "test-identity-token" {
		t.Errorf("expected 'test-identity-token', got '%s'", token)
	}
}

func TestGenerateIdentityToken_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	defer func() { serviceAccountUrlPatternOverride = "" }()
	serviceAccountUrlPatternOverride = server.URL + "/%s"

	config := &authz_config.Config{
		ServiceAccountEmail: "test@test-project.iam.gserviceaccount.com",
	}

	_, err := generateIdentityToken(config, "test-access-token", "https://example.com")
	if err == nil {
		t.Fatal("expected error for server error response, got nil")
	}
	if !strings.Contains(err.Error(), "IAM returned non-OK status") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGenerateIdentityToken_EmptyToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IAMResponse{Token: ""}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	defer func() { serviceAccountUrlPatternOverride = "" }()
	serviceAccountUrlPatternOverride = server.URL + "/%s"

	config := &authz_config.Config{
		ServiceAccountEmail: "test@test-project.iam.gserviceaccount.com",
	}

	_, err := generateIdentityToken(config, "test-access-token", "https://example.com")
	if err == nil {
		t.Fatal("expected error for empty identity token, got nil")
	}
	if !strings.Contains(err.Error(), "empty identity token") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGetIdentityToken_FileNotFound(t *testing.T) {
	config := &authz_config.Config{
		K8STokenPath: "/nonexistent/path/token",
	}

	_, err := GetIdentityToken(config, "https://example.com")
	if err == nil {
		t.Fatal("expected error for nonexistent token file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read JWT") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGetIdentityToken_EndToEnd(t *testing.T) {
	// Create a temporary file with a test token
	tmpFile, err := os.CreateTemp("", "k8s-token-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString("test-k8s-jwt-token"); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Mock STS server
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := STSResponse{
			AccessToken: "test-access-token",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer stsServer.Close()

	// Mock IAM server
	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IAMResponse{Token: "test-identity-token"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer iamServer.Close()

	defer func() { stsUrlOverride = "" }()
	stsUrlOverride = stsServer.URL

	defer func() { serviceAccountUrlPatternOverride = "" }()
	serviceAccountUrlPatternOverride = iamServer.URL + "/%s"

	config := &authz_config.Config{
		K8STokenPath:         tmpFile.Name(),
		ProjectNumber:        "123456789",
		WorkloadIdentityPool: "test-pool",
		WorkloadProvider:     "test-provider",
		ServiceAccountEmail:  "test@test-project.iam.gserviceaccount.com",
	}

	token, err := GetIdentityToken(config, "https://example.com")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "test-identity-token" {
		t.Errorf("expected 'test-identity-token', got '%s'", token)
	}
}

func TestExchangeToken_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not-valid-json"))
	}))
	defer server.Close()

	defer func() { stsUrlOverride = "" }()
	stsUrlOverride = server.URL

	config := &authz_config.Config{
		ProjectNumber:        "123456789",
		WorkloadIdentityPool: "test-pool",
		WorkloadProvider:     "test-provider",
	}

	_, err := exchangeToken(config, "test-k8s-token")
	if err == nil {
		t.Fatal("expected error for invalid JSON response, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode STS response") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGenerateIdentityToken_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not-valid-json"))
	}))
	defer server.Close()

	defer func() { serviceAccountUrlPatternOverride = "" }()
	serviceAccountUrlPatternOverride = server.URL + "/%s"

	config := &authz_config.Config{
		ServiceAccountEmail: "test@test-project.iam.gserviceaccount.com",
	}

	_, err := generateIdentityToken(config, "test-access-token", "https://example.com")
	if err == nil {
		t.Fatal("expected error for invalid JSON response, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode IAM response") {
		t.Errorf("unexpected error message: %v", err)
	}
}
