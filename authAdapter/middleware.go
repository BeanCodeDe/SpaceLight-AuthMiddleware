package authAdapter

import (
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

func CheckToken(next echo.HandlerFunc) echo.HandlerFunc {
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
		c.Set(ClaimName, *claims)
		c.Response().Header().Set(AuthName, token)
		return next(c)
	}
}

func CheckRole(allowedRoles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, ok := c.Get(ClaimName).(Claims)
			if !ok {
				log.Errorf("Got data of wrong type: %v", c.Get(ClaimName))
				return echo.ErrUnauthorized
			}

			for _, role := range claims.Roles {
				for _, allowedRole := range allowedRoles {
					if role == allowedRole {
						return next(c)
					}
				}
			}
			return echo.NewHTTPError(http.StatusUnauthorized, "")
		}
	}
}
