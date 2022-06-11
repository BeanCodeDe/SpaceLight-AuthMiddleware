package authAdapter

import (
	"crypto/rsa"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

const AuthName = "auth"
const ClaimName = "claim"

type Claims struct {
	UserId uuid.UUID `json:"UserId"`
	Roles  []string  `json:"roles"`
	jwt.StandardClaims
}

var (
	verifyKey      *rsa.PublicKey
	pubblicKeyPath string
	authUrl        string
)

func Init() error {
	pubblicKeyPath = os.Getenv("PUBLIC_KEY_PATH")
	authUrl = os.Getenv("AUTH_URL")
	verifyBytes, err := ioutil.ReadFile(pubblicKeyPath)
	if err != nil {
		return fmt.Errorf("error while reading public Key: %v", err)
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return fmt.Errorf("error while parsing public Key: %v", err)
	}

	return nil
}

func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get(AuthName)
		if authHeader == "" {
			return fmt.Errorf("no auth Header found")
		}

		claims, err := ParseToken(authHeader)
		if err != nil {
			return fmt.Errorf("error while parsing token: %v", err)
		}

		var token string

		if time.Now().Add(1 * time.Minute).After(time.Unix(claims.ExpiresAt, 0)) {
			token, err = createJWTToken(authHeader)
			if err != nil {
				return fmt.Errorf("error while creating token: %v", err)
			}
			c.Response().Header().Set(AuthName, token)
		} else {
			token = authHeader
		}

		c.Set(ClaimName, claims)
		c.Response().Header().Set(AuthName, token)
		return next(c)
	}
}

func ParseToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("claim could not be parsed: %v", err)
	}

	if tkn == nil || !tkn.Valid {
		return nil, fmt.Errorf("token is not valid: %v", err)
	}

	return claims, nil
}

func createJWTToken(token string) (string, error) {
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, authUrl, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set(AuthName, token)
	resp, err := client.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status is no ok but %v", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("body with token coulnd be read: %v", err)
	}

	stringToken := string(bodyBytes)

	return stringToken, nil
}
