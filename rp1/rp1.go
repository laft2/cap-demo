package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type AuthForm struct {
	Identifier string `form:"identifier"`
	Passphrase string `form:"passphrase"`
}

type IndexTemplate struct {
	ID string
}

func GenerateRandomString(length int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

var store *sessions.CookieStore

const CLIENT_ID string = "rp1"
const CLIENT_SECRET_CAP1 string = "rp1secret"
const CLIENT_SECRET_CAP2 string = "rp1secret"

const CAP1_AUTH_EP string = "http://localhost:9091/oauth2/authorize"
const CAP1_TOKEN_EP string = "http://localhost:9091/oauth2/token"
const REDIRECT_URI_CAP1 string = "http://localhost:10001/oauth2/cap1/callback"
const API_EP_CAP1 string = "http://localhost:9091/api/context"

const CAP2_AUTH_EP string = "http://localhost:9092/oauth2/authorize"
const CAP2_TOKEN_EP string = "http://localhost:9092/oauth2/token"
const REDIRECT_URI_CAP2 string = "http://localhost:10001/oauth2/cap2/callback"
const API_EP_CAP2 string = "http://localhost:9092/api/context"

type CapConfig struct {
	authEndpoint  string
	tokenEndpoint string
	apiEndpoint   string
	redirectUri   string
}

var CAP_CONFIG_MAP = map[string]*CapConfig{}

func init() {
	secretkey := securecookie.GenerateRandomKey(32)
	store = sessions.NewCookieStore(secretkey)
	CAP_CONFIG_MAP["CAP1"] = &CapConfig{
		authEndpoint:  CAP1_AUTH_EP,
		tokenEndpoint: CAP1_TOKEN_EP,
		apiEndpoint:   API_EP_CAP1,
		redirectUri:   REDIRECT_URI_CAP1,
	}
	CAP_CONFIG_MAP["CAP2"] = &CapConfig{
		authEndpoint:  CAP2_AUTH_EP,
		tokenEndpoint: CAP2_TOKEN_EP,
		apiEndpoint:   API_EP_CAP2,
		redirectUri:   REDIRECT_URI_CAP2,
	}
}
func renderHTML(htmlpath string, w http.ResponseWriter, data interface{}) error {
	t, err := template.ParseFiles(htmlpath)
	if err != nil {
		return err
	}
	if err := t.Execute(w, data); err != nil {
		return err
	}
	return nil
}

func checkDeviceIntune(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := store.Get(c.Request(), "session")
		if err != nil {
			return next(c)
		}
		tokenRaw, ok := sess.Values["accessTokenCap1"]
		if !ok {
			return next(c)
		}
		token, ok := tokenRaw.(string)
		if !ok {
			return next(c)
		}
		// コンテキストを確認してだめならアクセスを拒否する
		deviceCtxOk, _ := CheckContextIntune(token)
		if !deviceCtxOk {
			return renderHTML("front/failed.html", c.Response(), IndexTemplate{
				ID: sess.Values["id"].(string),
			})
		}

		return next(c)
	}
}
func checkDeviceRadius(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := store.Get(c.Request(), "session")
		if err != nil {
			return next(c)
		}
		tokenRaw, ok := sess.Values["accessTokenCap2"]
		if !ok {
			return next(c)
		}
		token, ok := tokenRaw.(string)
		if !ok {
			return next(c)
		}
		// コンテキストを確認してだめならアクセスを拒否する
		deviceCtxOk, _ := CheckContextRadius(token)
		if !deviceCtxOk {
			return renderHTML("front/confidential_failed.html", c.Response(), IndexTemplate{
				ID: sess.Values["id"].(string),
			})
		}

		return next(c)
	}
}

func startOAuthFrontChannel(c echo.Context, capName string) error {
	sess, _ := store.Get(c.Request(), "session")
	state := GenerateRandomString(16)
	sess.Values["state"] = state
	sess.Save(c.Request(), c.Response())

	capConfig, ok := CAP_CONFIG_MAP[capName]
	if !ok {
		return fmt.Errorf("not found capname")
	}

	req, err := http.NewRequest("GET", capConfig.authEndpoint, nil)
	if err != nil {
		return err
	}
	params := req.URL.Query()
	println(req.URL.Query().Encode())
	params.Set("response_type", "code")
	params.Set("client_id", "rp1")
	params.Set("redirect_uri", capConfig.redirectUri)
	params.Set("state", state)
	req.URL.RawQuery = params.Encode()

	return c.Redirect(http.StatusSeeOther, req.URL.String())
}

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Static("/static/css/", "front/css/")
	e.Static("/static/image/", "front/image/")

	e.GET("/confidential", func(c echo.Context) error {
		sess, _ := store.Get(c.Request(), "session")
		a, ok := sess.Values["id"]
		if !ok {
			return c.Redirect(http.StatusSeeOther, "/authenticate")
		}
		return renderHTML("front/confidential.html", c.Response(), IndexTemplate{
			ID: a.(string),
		})
	}, checkDeviceIntune, checkDeviceRadius)
	e.GET("/failed", func(c echo.Context) error {
		sess, _ := store.Get(c.Request(), "session")
		a, ok := sess.Values["id"]
		if !ok {
			return c.Redirect(http.StatusSeeOther, "/authenticate")
		}
		return renderHTML("front/failed.html", c.Response(), IndexTemplate{
			ID: a.(string),
		})
	})
	e.GET("/", func(c echo.Context) error {
		sess, err := store.Get(c.Request(), "session")
		if err != nil {
			err := sess.Save(c.Request(), c.Response())
			if err != nil {
				return err
			}
			return c.Redirect(http.StatusSeeOther, "/authenticate")
		}
		a, ok := sess.Values["id"]
		sess.Save(c.Request(), c.Response())
		if !ok {
			return c.Redirect(http.StatusSeeOther, "/authenticate")
		}
		return renderHTML("front/index.html", c.Response(), IndexTemplate{
			ID: a.(string),
		})
	}, checkDeviceIntune)
	e.GET("/authenticate", func(c echo.Context) error {
		c.File("front/authn.html")
		return nil
	})
	e.POST("/authenticate", func(c echo.Context) error {
		authform := &AuthForm{}
		c.Bind(authform)
		if authform.Identifier == "user" && authform.Passphrase == "a" {
			sess, _ := store.Get(c.Request(), "session")
			sess.Values["id"] = authform.Identifier
			sess.Save(c.Request(), c.Response())

			return startOAuthFrontChannel(c, "CAP1")
		} else {
			c.Redirect(http.StatusSeeOther, "/authenticate")
		}
		return nil
	})
	e.GET("/oauth2/cap1/callback", func(c echo.Context) error {
		code := c.QueryParam("code")
		state := c.QueryParam("state")
		sess, err := store.Get(c.Request(), "session")
		if err != nil {
			return err
		}
		sessState, ok := sess.Values["state"]
		if !ok || state != sessState {
			println(ok)
			println(state)
			println(sessState)
			return fmt.Errorf("err: stateが不一致です")
		}

		formValues := url.Values{}
		formValues.Set("grant_type", "authorization_code")
		formValues.Set("code", code)
		formValues.Set("redirect_uri", REDIRECT_URI_CAP1)
		request, err := http.NewRequest("POST", CAP1_TOKEN_EP, strings.NewReader(formValues.Encode()))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		clientAuth := url.QueryEscape(CLIENT_ID + ":" + CLIENT_SECRET_CAP1)
		request.Header.Set("Authorization", base64.StdEncoding.EncodeToString([]byte("Basic "+clientAuth)))

		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		jsonData := map[string]interface{}{}
		json.Unmarshal(body, &jsonData)
		accessTokenCap1, ok := jsonData["access_token"]
		if !ok {
			return fmt.Errorf("err: invalid json parse")
		}
		fmt.Printf("accessTokenCap1: %v\n", accessTokenCap1)
		sess.Values["accessTokenCap1"] = accessTokenCap1
		sess.Save(c.Request(), c.Response())

		return startOAuthFrontChannel(c, "CAP2")
	})
	e.GET("/oauth2/cap2/callback", func(c echo.Context) error {
		code := c.QueryParam("code")
		state := c.QueryParam("state")
		sess, err := store.Get(c.Request(), "session")
		if err != nil {
			return err
		}
		sessState, ok := sess.Values["state"]
		if !ok || state != sessState {
			println(ok)
			println(state)
			println(sessState)
			return fmt.Errorf("err: stateが不一致です")
		}

		formValues := url.Values{}
		formValues.Set("grant_type", "authorization_code")
		formValues.Set("code", code)
		formValues.Set("redirect_uri", REDIRECT_URI_CAP2)
		request, err := http.NewRequest("POST", CAP2_TOKEN_EP, strings.NewReader(formValues.Encode()))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		clientAuth := url.QueryEscape(CLIENT_ID + ":" + CLIENT_SECRET_CAP2)
		request.Header.Set("Authorization", base64.StdEncoding.EncodeToString([]byte("Basic "+clientAuth)))

		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		jsonData := map[string]interface{}{}
		json.Unmarshal(body, &jsonData)
		accessTokenCap2, ok := jsonData["access_token"]
		if !ok {
			return fmt.Errorf("err: invalid json parse")
		}
		fmt.Printf("accessTokenCap2: %v\n", accessTokenCap2)
		sess.Values["accessTokenCap2"] = accessTokenCap2
		sess.Save(c.Request(), c.Response())

		return c.Redirect(http.StatusSeeOther, "/")
	})
	e.Logger.Fatal(e.Start("localhost:10001"))
}
