package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

type DeviceInfoForRP struct {
	EnrolledDateTime string `json:"enrolledDateTime"`
	LastSyncDateTime string `json:"lastSyncDateTime"`
	OperatingSystem  string `json:"operatingSystem"`
	ComplianceState  string `json:"complianceState"`
	JailBroken       string `json:"jailBroken"`
	OsVersion        string `json:"osVersion"`
	LostModeState    string `json:"lostModeState"`
	UsersLoggedOn    []struct {
		// 	OdataType         string `json:"@odata.type"`
		// 	UserID            string `json:"userId"`
		LastLogOnDateTime string `json:"lastLogOnDateTime"`
	} `json:"usersLoggedOn"`
}

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
	if !ContainsScope(accessTokenFromDB.scopes, IntuneAll) {
		return fmt.Errorf("not permitted")
	}

	capId := accessTokenFromDB.capId
	user := userData[capId]

	if time.Since(user.lastUpdated).Seconds() > 300 {
		println("start updating")
		err := GetManagedDeviceAll()
		if err != nil {
			panic(err)
		}
		user = userData[capId]
	}

	ctx := *user.intuneCtx
	ctx.Id = ""
	ctx.Notes = ""

	return c.JSON(http.StatusOK, ctx)
}
