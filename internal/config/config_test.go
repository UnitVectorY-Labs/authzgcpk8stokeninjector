package config

import (
	"os"
	"strings"
	"testing"
)

// setRequiredEnvVars sets all required environment variables with test values
func setRequiredEnvVars(t *testing.T) {
	t.Helper()
	t.Setenv("K8S_TOKEN_PATH", "/var/run/secrets/token")
	t.Setenv("PROJECT_NUMBER", "123456789")
	t.Setenv("WORKLOAD_IDENTITY_POOL", "test-pool")
	t.Setenv("WORKLOAD_PROVIDER", "test-provider")
	t.Setenv("SERVICE_ACCOUNT_EMAIL", "test@test-project.iam.gserviceaccount.com")
}

func TestLoadConfig_AllSet(t *testing.T) {
	setRequiredEnvVars(t)
	t.Setenv("PORT", "8080")

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if config.K8STokenPath != "/var/run/secrets/token" {
		t.Errorf("expected K8STokenPath '/var/run/secrets/token', got '%s'", config.K8STokenPath)
	}
	if config.ProjectNumber != "123456789" {
		t.Errorf("expected ProjectNumber '123456789', got '%s'", config.ProjectNumber)
	}
	if config.WorkloadIdentityPool != "test-pool" {
		t.Errorf("expected WorkloadIdentityPool 'test-pool', got '%s'", config.WorkloadIdentityPool)
	}
	if config.WorkloadProvider != "test-provider" {
		t.Errorf("expected WorkloadProvider 'test-provider', got '%s'", config.WorkloadProvider)
	}
	if config.ServiceAccountEmail != "test@test-project.iam.gserviceaccount.com" {
		t.Errorf("expected ServiceAccountEmail 'test@test-project.iam.gserviceaccount.com', got '%s'", config.ServiceAccountEmail)
	}
	if config.Port != "8080" {
		t.Errorf("expected Port '8080', got '%s'", config.Port)
	}
}

func TestLoadConfig_DefaultPort(t *testing.T) {
	setRequiredEnvVars(t)
	t.Setenv("PORT", "")

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if config.Port != "50051" {
		t.Errorf("expected default port '50051', got '%s'", config.Port)
	}
}

func TestLoadConfig_MissingK8STokenPath(t *testing.T) {
	setRequiredEnvVars(t)
	os.Unsetenv("K8S_TOKEN_PATH")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for missing K8S_TOKEN_PATH, got nil")
	}
	if !strings.Contains(err.Error(), "K8S_TOKEN_PATH") {
		t.Errorf("error should mention K8S_TOKEN_PATH: %v", err)
	}
}

func TestLoadConfig_MissingProjectNumber(t *testing.T) {
	setRequiredEnvVars(t)
	os.Unsetenv("PROJECT_NUMBER")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for missing PROJECT_NUMBER, got nil")
	}
	if !strings.Contains(err.Error(), "PROJECT_NUMBER") {
		t.Errorf("error should mention PROJECT_NUMBER: %v", err)
	}
}

func TestLoadConfig_MissingWorkloadIdentityPool(t *testing.T) {
	setRequiredEnvVars(t)
	os.Unsetenv("WORKLOAD_IDENTITY_POOL")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for missing WORKLOAD_IDENTITY_POOL, got nil")
	}
	if !strings.Contains(err.Error(), "WORKLOAD_IDENTITY_POOL") {
		t.Errorf("error should mention WORKLOAD_IDENTITY_POOL: %v", err)
	}
}

func TestLoadConfig_MissingWorkloadProvider(t *testing.T) {
	setRequiredEnvVars(t)
	os.Unsetenv("WORKLOAD_PROVIDER")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for missing WORKLOAD_PROVIDER, got nil")
	}
	if !strings.Contains(err.Error(), "WORKLOAD_PROVIDER") {
		t.Errorf("error should mention WORKLOAD_PROVIDER: %v", err)
	}
}

func TestLoadConfig_MissingServiceAccountEmail(t *testing.T) {
	setRequiredEnvVars(t)
	os.Unsetenv("SERVICE_ACCOUNT_EMAIL")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for missing SERVICE_ACCOUNT_EMAIL, got nil")
	}
	if !strings.Contains(err.Error(), "SERVICE_ACCOUNT_EMAIL") {
		t.Errorf("error should mention SERVICE_ACCOUNT_EMAIL: %v", err)
	}
}

func TestLoadConfig_AllMissing(t *testing.T) {
	os.Unsetenv("K8S_TOKEN_PATH")
	os.Unsetenv("PROJECT_NUMBER")
	os.Unsetenv("WORKLOAD_IDENTITY_POOL")
	os.Unsetenv("WORKLOAD_PROVIDER")
	os.Unsetenv("SERVICE_ACCOUNT_EMAIL")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error when all required vars missing, got nil")
	}

	for _, envVar := range []string{"K8S_TOKEN_PATH", "PROJECT_NUMBER", "WORKLOAD_IDENTITY_POOL", "WORKLOAD_PROVIDER", "SERVICE_ACCOUNT_EMAIL"} {
		if !strings.Contains(err.Error(), envVar) {
			t.Errorf("error should mention %s: %v", envVar, err)
		}
	}
}

func TestLoadConfig_PortNotOverridden(t *testing.T) {
	setRequiredEnvVars(t)
	// PORT not set at all (unset by the helper since we use t.Setenv)
	os.Unsetenv("PORT")

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if config.Port != "50051" {
		t.Errorf("expected default port '50051', got '%s'", config.Port)
	}
}
