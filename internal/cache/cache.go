package cache

import (
	"time"

	jwtparser "github.com/UnitVectorY-Labs/authzgcpk8stokeninjector/internal/jwt"
)

type JwtCache struct {
	// Map of JWTs based on the audience
	JwtMap map[string]JwtInfo
}

type JwtInfo struct {
	// The JWT
	Jwt string
	// The expiration time of the JWT
	ExpirationTime time.Time
}

// NewJwtCache creates a new JwtCache
func NewJwtCache() *JwtCache {
	return &JwtCache{
		JwtMap: make(map[string]JwtInfo),
	}
}

// AddJwt adds a JWT to the cache
func (c *JwtCache) AddJwt(jwt string) {
	aud, exp, err := jwtparser.ParseJWT(jwt)
	if err != nil {
		return
	}

	c.JwtMap[aud] = JwtInfo{
		Jwt:            jwt,
		ExpirationTime: exp,
	}
}

// GetJwt gets a JWT from the cache
func (c *JwtCache) GetJwt(audience string) (string, bool) {
	jwtInfo, ok := c.JwtMap[audience]
	if !ok {
		return "", false
	}

	// Check if the token is 75% expired
	expirationDuration := time.Until(jwtInfo.ExpirationTime)
	totalDuration := jwtInfo.ExpirationTime.Sub(time.Now().Add(-expirationDuration))
	if expirationDuration <= totalDuration/4 {
		return "", false
	}

	return jwtInfo.Jwt, true
}
