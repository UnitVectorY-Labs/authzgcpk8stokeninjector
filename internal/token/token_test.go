package token

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/UnitVectorY-Labs/authzgcpk8stokeninjector/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTokenJSON(t *testing.T) {
	cfg := &config.Config{ProjectNumber: "123", WorkloadIdentityPool: "pool", WorkloadProvider: "provider", ServiceAccountEmail: "account@example.com"}
	tests := []struct {
		name, response, wantBody, wantToken string
		sts, wantError                      bool
	}{
		{"STS valid", `{"access_token":"access","expires_in":3600,"token_type":"Bearer"}`, `{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","audience":"//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider","scope":"https://www.googleapis.com/auth/cloud-platform","requested_token_type":"urn:ietf:params:oauth:token-type:access_token","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","subject_token":"subject"}`, "access", true, false},
		{"IAM valid", `{"token":"identity"}`, `{"audience":"audience","includeEmail":true}`, "identity", false, false},
		{"STS duplicate key", `{"access_token":"first","access_token":"second"}`, "", "", true, true},
		{"IAM duplicate key", `{"token":"first","token":"second"}`, "", "", false, true},
		{"STS invalid UTF-8", "{\"access_token\":\"\xff\"}", "", "", true, true},
		{"IAM invalid UTF-8", "{\"token\":\"\xff\"}", "", "", false, true},
		{"STS case mismatch", `{"ACCESS_TOKEN":"access"}`, "", "", true, true},
		{"IAM case mismatch", `{"Token":"identity"}`, "", "", false, true},
		{"STS trailing value", `{"access_token":"access"} {}`, "", "", true, true},
		{"IAM trailing value", `{"token":"identity"} {}`, "", "", false, true},
	}
	oldTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if tt.wantBody != "" && string(body) != tt.wantBody {
					t.Errorf("request body = %s, want %s", body, tt.wantBody)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tt.response)), Header: make(http.Header)}, nil
			})
			var got string
			var err error
			if tt.sts {
				got, err = exchangeToken(cfg, "subject")
			} else {
				got, err = generateIdentityToken(cfg, "access", "audience")
			}
			if (err != nil) != tt.wantError {
				t.Fatalf("error = %v, want error %v", err, tt.wantError)
			}
			if got != tt.wantToken {
				t.Errorf("token = %q, want %q", got, tt.wantToken)
			}
		})
	}
}
