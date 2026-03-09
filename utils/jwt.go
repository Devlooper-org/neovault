package utils

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var GetJWTSecret = func() []byte {
	return []byte(os.Getenv("JWT_SECRET"))
}

func GenerateJWT(userID uint) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // 24 hours expiry
	})

	tokenString, err := token.SignedString(GetJWTSecret())
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func VerifyJWT(tokenString string) (uint, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return GetJWTSecret(), nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// jwt.MapClaims unmarshals numbers as float64
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			return 0, errors.New("invalid token claims")
		}
		return uint(userIDFloat), nil
	}

	return 0, errors.New("invalid token")
}

// GenerateLoginToken issues a 5-minute token for TOTP verification.
func GenerateLoginToken(userID uint) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"step":    "totp_pending",
		"exp":     time.Now().Add(5 * time.Minute).Unix(),
	})
	return token.SignedString(GetJWTSecret())
}

func VerifyLoginToken(tokenString string) (uint, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return GetJWTSecret(), nil
	})
	if err != nil {
		return 0, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		step, _ := claims["step"].(string)
		if step != "totp_pending" {
			return 0, errors.New("not a login token")
		}
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			return 0, errors.New("invalid token claims")
		}
		return uint(userIDFloat), nil
	}
	return 0, errors.New("invalid token")
}

// GenerateVaultToken creates a simple session JWT for the vault.
func GenerateVaultToken(userID uint) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"vault":   true,
		"exp":     time.Now().Add(time.Hour * 8).Unix(),
	})
	return token.SignedString(GetJWTSecret())
}

// VerifyVaultToken checks that the vault session token is valid. Returns userID.
func VerifyVaultToken(tokenString string) (uint, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return GetJWTSecret(), nil
	})
	if err != nil {
		return 0, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			return 0, errors.New("invalid vault token")
		}
		return uint(userIDFloat), nil
	}
	return 0, errors.New("invalid vault token")
}
