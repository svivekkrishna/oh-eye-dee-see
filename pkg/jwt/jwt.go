package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

const githubJWKSEndpoint = "https://token.actions.githubusercontent.com/.well-known/jwks"

type JWK struct {
	N   string
	Kty string
	Kid string
	Alg string
	E   string
	Use string
	X5c []string
	X5t string
}

type JWKS struct {
	Keys []JWK
}

type JWTClaims struct {
	Subject    string `json:"sub"`
	Repository string `json:"repository"`
}

func getKeyFromJwks(jwksBytes []byte) func(*jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		var jwks JWKS
		if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
			return nil, fmt.Errorf("Unable to parse JWKS")
		}

		for _, jwk := range jwks.Keys {
			if jwk.Kid == token.Header["kid"] {
				nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
				if err != nil {
					return nil, fmt.Errorf("Unable to parse key")
				}
				var n big.Int

				eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
				if err != nil {
					return nil, fmt.Errorf("Unable to parse key")
				}
				var e big.Int

				key := rsa.PublicKey{
					N: n.SetBytes(nBytes),
					E: int(e.SetBytes(eBytes).Uint64()),
				}
				return &key, nil
			}
		}

		return nil, fmt.Errorf("Unknown kid: %v", token.Header["kid"])
	}
}

func ValidateOidcToken(oidcTokenString string) (*JWTClaims, error) {

	resp, err := http.Get(githubJWKSEndpoint)
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("Unable to get JWKS configuration")
	}

	jwksBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("Unable to get JWKS configuration")
	}

	// Attempt to validate JWT with JWKS
	oidcToken, err := jwt.Parse(string(oidcTokenString), getKeyFromJwks(jwksBytes))

	if err != nil || !oidcToken.Valid {
		return nil, fmt.Errorf("Unable to validate JWT", err)
	}

	claims, ok := oidcToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("Unable to map JWT claims")
	}

	return &JWTClaims{
		Repository: fmt.Sprint(claims["repository"]),
		Subject:    fmt.Sprint(claims["sub"]),
	}, nil
}

func ValidateAccessToken(accessToken string) (*jwt.Token, error) {

	secretKey := []byte(os.Getenv("JWT_SIGNING_SECRET"))

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Subject     string `json:"subject"`
}

func CreateAccessToken(claims *JWTClaims) (*TokenResponse, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"sub": claims.Subject,
			"exp": time.Now().Add(time.Hour * 24).Unix(),
		})

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SIGNING_SECRET")))
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: tokenString,
		Subject:     claims.Subject,
	}, nil

}
