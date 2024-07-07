package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var JwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Function to generate a JWT token
func GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(30 * time.Minute)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// Function to validate the JWT token
func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, err
	}
	return claims, nil
}
