package cache

import (
	"encoding/base64"
	"encoding/json"
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

func TestNewJwtCache(t *testing.T) {
	cache := NewJwtCache()
	if cache == nil {
		t.Fatal("expected non-nil cache")
	}
	if cache.JwtMap == nil {
		t.Fatal("expected non-nil JwtMap")
	}
	if len(cache.JwtMap) != 0 {
		t.Errorf("expected empty JwtMap, got %d entries", len(cache.JwtMap))
	}
}

func TestAddJwt_ValidToken(t *testing.T) {
	cache := NewJwtCache()
	expTime := time.Now().Add(1 * time.Hour).Unix()
	token := createTestJWT(map[string]interface{}{
		"aud": "https://example.com",
		"exp": float64(expTime),
	})

	cache.AddJwt(token)

	if len(cache.JwtMap) != 1 {
		t.Fatalf("expected 1 entry in cache, got %d", len(cache.JwtMap))
	}

	info, ok := cache.JwtMap["https://example.com"]
	if !ok {
		t.Fatal("expected entry for 'https://example.com'")
	}
	if info.Jwt != token {
		t.Error("stored JWT does not match input token")
	}
	if info.ExpirationTime.Unix() != expTime {
		t.Errorf("expected expiration %d, got %d", expTime, info.ExpirationTime.Unix())
	}
}

func TestAddJwt_InvalidToken(t *testing.T) {
	cache := NewJwtCache()
	cache.AddJwt("invalid-token")

	if len(cache.JwtMap) != 0 {
		t.Errorf("expected empty cache after adding invalid token, got %d entries", len(cache.JwtMap))
	}
}

func TestAddJwt_MultipleAudiences(t *testing.T) {
	cache := NewJwtCache()
	expTime := time.Now().Add(1 * time.Hour).Unix()

	token1 := createTestJWT(map[string]interface{}{
		"aud": "https://api1.example.com",
		"exp": float64(expTime),
	})
	token2 := createTestJWT(map[string]interface{}{
		"aud": "https://api2.example.com",
		"exp": float64(expTime),
	})

	cache.AddJwt(token1)
	cache.AddJwt(token2)

	if len(cache.JwtMap) != 2 {
		t.Fatalf("expected 2 entries in cache, got %d", len(cache.JwtMap))
	}
}

func TestAddJwt_OverwriteExisting(t *testing.T) {
	cache := NewJwtCache()
	audience := "https://example.com"

	token1 := createTestJWT(map[string]interface{}{
		"aud": audience,
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})
	token2 := createTestJWT(map[string]interface{}{
		"aud": audience,
		"exp": float64(time.Now().Add(2 * time.Hour).Unix()),
	})

	cache.AddJwt(token1)
	cache.AddJwt(token2)

	if len(cache.JwtMap) != 1 {
		t.Fatalf("expected 1 entry in cache, got %d", len(cache.JwtMap))
	}
	if cache.JwtMap[audience].Jwt != token2 {
		t.Error("expected cache to contain the second token")
	}
}

func TestGetJwt_ValidNonExpired(t *testing.T) {
	cache := NewJwtCache()
	expTime := time.Now().Add(1 * time.Hour).Unix()
	token := createTestJWT(map[string]interface{}{
		"aud": "https://example.com",
		"exp": float64(expTime),
	})

	cache.AddJwt(token)

	result, found := cache.GetJwt("https://example.com")
	if !found {
		t.Fatal("expected to find token in cache")
	}
	if result != token {
		t.Error("retrieved token does not match stored token")
	}
}

func TestGetJwt_NotFound(t *testing.T) {
	cache := NewJwtCache()

	_, found := cache.GetJwt("https://nonexistent.example.com")
	if found {
		t.Error("expected token not to be found")
	}
}

func TestGetJwt_Expired(t *testing.T) {
	cache := NewJwtCache()

	// Add a token that is already expired
	expTime := time.Now().Add(-1 * time.Minute)
	cache.JwtMap["https://example.com"] = JwtInfo{
		Jwt:            "expired-token",
		ExpirationTime: expTime,
		AddedAt:        time.Now().Add(-1 * time.Hour),
	}

	_, found := cache.GetJwt("https://example.com")
	if found {
		t.Error("expected expired token not to be returned")
	}
}

func TestGetJwt_NearExpiration(t *testing.T) {
	cache := NewJwtCache()

	// Add a token that is more than 75% expired (should be treated as expired)
	// Simulate a token with total TTL of 1 hour, added 50 minutes ago (>75% expired)
	cache.JwtMap["https://example.com"] = JwtInfo{
		Jwt:            "nearly-expired-token",
		ExpirationTime: time.Now().Add(10 * time.Minute),
		AddedAt:        time.Now().Add(-50 * time.Minute),
	}

	_, found := cache.GetJwt("https://example.com")
	if found {
		t.Error("expected nearly-expired token not to be returned (>75% expired)")
	}
}

func TestGetJwt_WellWithinExpiration(t *testing.T) {
	cache := NewJwtCache()

	// Add a token with plenty of time left
	cache.JwtMap["https://example.com"] = JwtInfo{
		Jwt:            "valid-token",
		ExpirationTime: time.Now().Add(2 * time.Hour),
		AddedAt:        time.Now(),
	}

	result, found := cache.GetJwt("https://example.com")
	if !found {
		t.Fatal("expected to find token with plenty of time left")
	}
	if result != "valid-token" {
		t.Error("retrieved token does not match")
	}
}

func TestAddJwt_MissingClaims(t *testing.T) {
	cache := NewJwtCache()

	// Token with no aud claim
	token := createTestJWT(map[string]interface{}{
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	cache.AddJwt(token)

	if len(cache.JwtMap) != 0 {
		t.Errorf("expected empty cache after adding token with missing aud, got %d entries", len(cache.JwtMap))
	}
}
