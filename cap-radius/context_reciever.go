package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// デバイスのコンテキストを受け取る
// 本来は相手が正しい相手かをmTLSなどで確認する必要がある
func ContextReceiver() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.POST("/radius/context", func(c echo.Context) error {
		detailRow := c.FormValue("detail")
		authRow := c.FormValue("auth")

		UpdateContext(detailRow, authRow)
		return c.NoContent(http.StatusOK)
	})
	e.Logger.Fatal(e.Start(":9090"))
}

func init() {
	go ContextReceiver()
}
