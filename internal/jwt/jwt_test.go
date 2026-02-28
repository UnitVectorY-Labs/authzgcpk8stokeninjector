package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// createTestJWT creates a simple unsigned JWT with the given claims for testing
func createTestJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	return header + "." + payload + "."
}

func TestParseJWT_ValidToken(t *testing.T) {
	expTime := time.Now().Add(1 * time.Hour).Unix()
	token := createTestJWT(map[string]interface{}{
		"aud": "https://example.com",
		"exp": float64(expTime),
	})

	aud, exp, err := ParseJWT(token)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if aud != "https://example.com" {
		t.Errorf("expected audience 'https://example.com', got '%s'", aud)
	}
	if exp.Unix() != expTime {
		t.Errorf("expected exp %d, got %d", expTime, exp.Unix())
	}
}

func TestParseJWT_MissingAud(t *testing.T) {
	token := createTestJWT(map[string]interface{}{
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	_, _, err := ParseJWT(token)
	if err == nil {
		t.Fatal("expected error for missing aud claim, got nil")
	}
}

func TestParseJWT_MissingExp(t *testing.T) {
	token := createTestJWT(map[string]interface{}{
		"aud": "https://example.com",
	})

	_, _, err := ParseJWT(token)
	if err == nil {
		t.Fatal("expected error for missing exp claim, got nil")
	}
}

func TestParseJWT_InvalidTokenFormat(t *testing.T) {
	_, _, err := ParseJWT("not-a-valid-jwt")
	if err == nil {
		t.Fatal("expected error for invalid token format, got nil")
	}
}

func TestParseJWT_EmptyToken(t *testing.T) {
	_, _, err := ParseJWT("")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestParseJWT_InvalidBase64(t *testing.T) {
	_, _, err := ParseJWT("header.!!!invalid-base64!!!.signature")
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}

func TestParseJWT_InvalidJSON(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`not-json`))
	token := header + "." + payload + "."

	_, _, err := ParseJWT(token)
	if err == nil {
		t.Fatal("expected error for invalid JSON payload, got nil")
	}
}

func TestParseJWT_ExpNotFloat(t *testing.T) {
	token := createTestJWT(map[string]interface{}{
		"aud": "https://example.com",
		"exp": "not-a-number",
	})

	_, _, err := ParseJWT(token)
	if err == nil {
		t.Fatal("expected error for non-numeric exp claim, got nil")
	}
}

func TestParseJWT_AudNotString(t *testing.T) {
	token := createTestJWT(map[string]interface{}{
		"aud": 12345,
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	_, _, err := ParseJWT(token)
	if err == nil {
		t.Fatal("expected error for non-string aud claim, got nil")
	}
}

func TestParseJWT_BothClaimsMissing(t *testing.T) {
	token := createTestJWT(map[string]interface{}{
		"sub": "user123",
	})

	_, _, err := ParseJWT(token)
	if err == nil {
		t.Fatal("expected error when both aud and exp are missing, got nil")
	}
}

func TestParseJWT_ErrorMessageContent(t *testing.T) {
	token := createTestJWT(map[string]interface{}{
		"sub": "user123",
	})

	_, _, err := ParseJWT(token)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "exp or aud claim not found or invalid") {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}
