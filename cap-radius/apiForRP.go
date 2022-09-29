package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

func ApiForRP(c echo.Context) error {
	auth := c.Request().Header.Get("Authorization")
	println(auth)
	if auth == "" {
		return fmt.Errorf("access denied")
	}
	authLower := strings.ToLower(auth)
	idx := strings.Index(authLower, "bearer")
	if idx == -1 {
		return fmt.Errorf("access denied")
	}
	accessToken := auth[len("bearer "):]
	accessTokenFromDB, ok := accessTokenStore[accessToken]
	if !ok {
		return fmt.Errorf("access token not found")
	}
	if !ContainsScope(accessTokenFromDB.scopes, RadiusAll) {
		return fmt.Errorf("not permitted")
	}

	capId := accessTokenFromDB.capId
	user := userData[capId]

	ctx := user.radiusCtx
	payload := map[string]interface{}{
		"is_active": ctx.IsActive,
		"timestamp": ctx.TimeStamp,
	}

	return c.JSON(http.StatusOK, &payload)
}
