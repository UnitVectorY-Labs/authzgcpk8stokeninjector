package jwt

import (
	"errors"
	"time"

	jwtp "github.com/golang-jwt/jwt/v4"
)

func ParseJWT(tokenString string) (string, time.Time, error) {
	token, _, err := new(jwtp.Parser).ParseUnverified(tokenString, jwtp.MapClaims{})
	if err != nil {
		return "", time.Time{}, err
	}

	if claims, ok := token.Claims.(jwtp.MapClaims); ok {
		exp, expOk := claims["exp"].(float64)
		aud, audOk := claims["aud"].(string)
		if expOk && audOk {
			return aud, time.Unix(int64(exp), 0), nil
		}
		return "", time.Time{}, errors.New("exp or aud claim not found or invalid")
	}

	return "", time.Time{}, errors.New("invalid token claims")
}
