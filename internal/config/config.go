package config

import (
	"fmt"
	"os"
	"strings"
)

// Config holds the configuration loaded from environment variables
type Config struct {
	K8STokenPath         string
	ProjectNumber        string
	WorkloadIdentityPool string
	WorkloadProvider     string
	ServiceAccountEmail  string
	Port                 string
}

// LoadConfig reads environment variables and populates the Config struct
func LoadConfig() (*Config, error) {
	config := &Config{
		K8STokenPath:         os.Getenv("K8S_TOKEN_PATH"),
		ProjectNumber:        os.Getenv("PROJECT_NUMBER"),
		WorkloadIdentityPool: os.Getenv("WORKLOAD_IDENTITY_POOL"),
		WorkloadProvider:     os.Getenv("WORKLOAD_PROVIDER"),
		ServiceAccountEmail:  os.Getenv("SERVICE_ACCOUNT_EMAIL"),
		Port:                 os.Getenv("PORT"),
	}

	// Set default port if not specified
	if config.Port == "" {
		config.Port = "50051"
	}

	// Validate required fields
	missing := []string{}
	if config.K8STokenPath == "" {
		missing = append(missing, "K8S_TOKEN_PATH")
	}
	if config.ProjectNumber == "" {
		missing = append(missing, "PROJECT_NUMBER")
	}
	if config.WorkloadIdentityPool == "" {
		missing = append(missing, "WORKLOAD_IDENTITY_POOL")
	}
	if config.WorkloadProvider == "" {
		missing = append(missing, "WORKLOAD_PROVIDER")
	}
	if config.ServiceAccountEmail == "" {
		missing = append(missing, "SERVICE_ACCOUNT_EMAIL")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return config, nil
}
