package config

import "github.com/golang-jwt/jwt/v4"

var JWT_KEY = []byte("$2a$10$D6416YbFlSadof8T4b0Z")

type JWTClaim struct {
	Username string
	jwt.RegisteredClaims
}
