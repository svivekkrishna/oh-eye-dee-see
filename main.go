package main

import (
	"fmt"
	"net/http"
	"oh-eye-dee-see/pkg/jwt"
	"strings"

	lib_jwt "github.com/golang-jwt/jwt"

	"github.com/gin-gonic/gin"
)

var db = make(map[string]string)

func AuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeaders := c.Request.Header["Authorization"]
		if len(authHeaders) == 0 {
			c.String(http.StatusForbidden, "Unauthorized: No tokens sent.")
			return
		}

		bearerTokens := strings.Split(authHeaders[0], "Bearer ")
		if len(bearerTokens) == 0 {
			c.String(http.StatusForbidden, "Unauthorized: No bearer token found.")
			return
		}

		token, err := jwt.ValidateAccessToken(bearerTokens[1])
		if err != nil {
			c.String(http.StatusUnauthorized, "Unauthorized: invalid bearer token.")
			return
		}

		claims, ok := token.Claims.(lib_jwt.MapClaims)

		if !ok {
			c.String(http.StatusUnauthorized, "Unauthorized: Error parsing token claims.")
			return
		}

		organization := strings.Split(fmt.Sprint(claims["sub"]), "/")[0]
		organization = strings.Split(organization, ":")[1]

		c.Set("organization", organization)

		c.Next()
	}
}

func setupRouter() *gin.Engine {
	// Disable Console Color
	// gin.DisableConsoleColor()
	r := gin.Default()

	// Ping test
	r.GET("/org/:org", AuthorizationMiddleware(), func(c *gin.Context) {
		organization, _ := c.Get("organization")
		fmt.Println("Organization in context: ", organization)
		fmt.Println("Organization in param:", c.Param("org"))
		if organization == c.Param("org") {

			val, ok := db[c.Param("org")]
			if ok {
				c.JSON(http.StatusOK, map[string]string{"org": val})
			} else {
				c.String(http.StatusNotFound, "Entity Not found.")
			}
		} else {
			c.String(http.StatusUnauthorized, "Trying to access an unauthorized entity.")
		}

	})

	r.POST("/token", func(c *gin.Context) {
		authHeaders := c.Request.Header["Authorization"]
		if len(authHeaders) == 0 {
			c.String(http.StatusForbidden, "Unauthorized: No tokens sent.")
		}

		oidcTokens := strings.Split(authHeaders[0], "Bearer ")
		if len(oidcTokens) == 0 {
			c.String(http.StatusForbidden, "Unauthorized: No bearer token found.")
			return
		}

		claims, err := jwt.ValidateOidcToken(oidcTokens[1])

		if err != nil {
			c.String(http.StatusUnauthorized, "Unauthorized. Token is invalid.")
			return
		}

		accessTokenResponse, err := jwt.CreateAccessToken(claims)

		if err != nil {
			responseString := fmt.Errorf("Error occurred while generating the access token: %w.", err)
			c.String(http.StatusInternalServerError, responseString.Error())
		}

		c.JSON(http.StatusOK, accessTokenResponse)
	})

	return r
}

func bootstrapData() {
	db["svivekkrishna"] = "oh-eye-dee-see"
	db["anotheruser"] = "oh-eye-cant-see"
}

func main() {
	bootstrapData()
	r := setupRouter()
	// Listen and Server in 0.0.0.0:8080
	r.Run(":8081")
}
