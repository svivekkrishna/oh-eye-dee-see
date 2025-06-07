package main

import (
	"fmt"
	"log"
	"os"

	"github.com/golang-jwt/jwt"

	jwt_lib "oh-eye-dee-see/pkg/jwt"
)

const allowed_repo = "svivekkrishna/oh-eye-dee-see"

type JWTClaims struct {
	Repository string `json:"repository"`
	jwt.Claims
}

func main() {

	claims, err := jwt_lib.ValidateToken(os.Args[1])

	if err != nil {
		fmt.Errorf("Error occured: ", err)
	}

	if claims.Repository != allowed_repo {
		log.Fatalf("Error: Not allowed")
	}

	log.Printf("Valid token for repository: %s with subject %s", claims.Repository, claims.Subject)
}
