package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type ClientConf struct {
	ClientName  string
	ClientID    string
	RedirectUri string
}
type ClientForm struct {
	ResponseType string `query:"resonse_type"`
	ClientID     string `query:"client_id"`
	RedirectUri  string `query:"redirect_uri"`
	State        string `query:"state"`
}

func getClient(clientid string) *ClientConf {
	if clientid == "rp1" {
		res := new(ClientConf)
		res.ClientName = "RP1"
		res.ClientID = "rp1"
		res.RedirectUri = "http://localhost:10001/oauth2/cap1/callback"
		return res
	}
	return nil
}
func getClientSecret(clientid string) string {
	if clientid == "rp1" {
		return "rp1secret"
	}
	return ""
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

type IndexTemplate struct {
	ID                 string
	IsIntuneRegistered bool
	IntuneCtx          ManagedDevice
}

func GenerateRandomString(length int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

type AuthForm struct {
	Identifier string `form:"identifier"`
	Passphrase string `form:"passphrase"`
	ReqId      string `form:"reqid"`
}
type SessionClientInfo = map[string]*ClientConf

var sessionClientInfo SessionClientInfo

type CodeData struct {
	code        string
	redirectUri string
	clientId    string
	capId       CAPID
	scopes      []Scope
}

var codeStore map[string]*CodeData

type CAPID string

type AccessTokenData struct {
	accessToken string
	clientId    string
	capId       CAPID
	scopes      []Scope
}

var accessTokenStore map[string]*AccessTokenData

// var managedDeviceData map[CAPID]*ManagedDevice

type ChromeExtensionSession struct {
	msg   string
	capId CAPID
	ctxc  string
}

var chromeExtensionSessionData map[string]*ChromeExtensionSession

type Scope string

const (
	IntuneAll Scope = "intune_all"
)

func ContainsScope(s []Scope, pat Scope) bool {
	for _, a := range s {
		if a == pat {
			return true
		}
	}
	return false
}

var store *sessions.CookieStore
var intuneAccessToken string

func init() {
	secretkey := securecookie.GenerateRandomKey(32)
	store = sessions.NewCookieStore(secretkey)
	sessionClientInfo = map[string]*ClientConf{}
	codeStore = map[string]*CodeData{}
	accessTokenStore = map[string]*AccessTokenData{}
	chromeExtensionSessionData = map[string]*ChromeExtensionSession{}
}

const INTUNE_SCOPE string = "offline_access DeviceManagementManagedDevices.ReadWrite.All"

func main() {

	CLIENT_ID := os.Getenv("intune_client_id")
	CLIENT_SECRET := os.Getenv("intune_client_secret")

	// const API_URL string = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/"
	AUTH_URL := os.Getenv("intune_auth_uri")
	TOKEN_URL := os.Getenv("intune_token_uri")

	getManagedDeviceAPI := func() (*http.Response, error) {
		var API_URL string = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/26005678-a9a9-4041-941f-dad2d37735f3"
		client := &http.Client{
			Timeout: time.Duration(5 * time.Second),
		}

		request, err := http.NewRequest("GET", API_URL, nil)
		if err != nil {
			return nil, err
		}

		params := request.URL.Query()
		params.Add("$select", "id,hardwareInformation,usersLoggedOn,notes,osVersion,operatingSystem,jailBroken")
		// TODO: 色々足す

		// request.URL.RawQuery = params.Encode()

		request.Header.Add("Authorization", "Bearer "+intuneAccessToken)

		fmt.Println(request.URL.String())

		resp, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	checkUserAuthenticated := func(c echo.Context) bool {
		sess, err := store.Get(c.Request(), "capsession")
		if err != nil {
			// sess.Save(c.Request(), c.Response())
			return false
		}
		id, ok := sess.Values["id"]
		if !ok {
			return false
		}
		_, ok = id.(string)
		return ok
	}
	authenticateUser := func(c echo.Context) bool {
		authform := &AuthForm{}
		c.Bind(authform)
		fmt.Printf("authform: %+v\n", authform)
		if authform.Identifier == "device1" && authform.Passphrase == "a" {
			sess, _ := store.Get(c.Request(), "capsession")
			sess.Values["id"] = authform.Identifier
			sess.Save(c.Request(), c.Response())
			return true
		}
		return false
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Static("/static/css/", "front/css/")
	e.Static("/static/image/", "front/image/")
	e.GET("/", func(c echo.Context) error {
		if !checkUserAuthenticated(c) {
			return c.Redirect(http.StatusSeeOther, "/authenticate")
		}
		sess, _ := store.Get(c.Request(), "capsession")
		id := sess.Values["id"]
		user := userData[CAPID(id.(string))]
		isIntuneRegistered := len(user.intuneCert) > 10
		if isIntuneRegistered {
			return renderHTML("front/index.html", c.Response(), IndexTemplate{
				ID:                 id.(string),
				IsIntuneRegistered: isIntuneRegistered,
				IntuneCtx:          *user.intuneCtx,
			})
		}
		return renderHTML("front/index.html", c.Response(), IndexTemplate{
			ID:                 id.(string),
			IsIntuneRegistered: isIntuneRegistered,
		})
	})
	e.GET("/authenticate", func(c echo.Context) error {
		if checkUserAuthenticated(c) {
			return c.Redirect(http.StatusSeeOther, "/")
		}
		return renderHTML("front/normal_authn.html", c.Response(), map[string]interface{}{})
	})
	e.POST("/authenticate", func(c echo.Context) error {
		if authenticateUser(c) {
			return c.Redirect(http.StatusSeeOther, "/")
		}
		return c.Redirect(http.StatusSeeOther, "/authenticate")
	})
	e.GET("/ctxc/intune", func(c echo.Context) error {
		if !checkUserAuthenticated(c) {
			return c.Redirect(http.StatusSeeOther, "/authenticate")
		}
		msg := GenerateRandomString(32)
		sess, _ := store.Get(c.Request(), "capsession")
		chromeExtensionSessionData[msg] = &ChromeExtensionSession{
			msg:   msg,
			capId: CAPID(sess.Values["id"].(string)),
			ctxc:  "intune",
		}
		return renderHTML("front/intuneid.html", c.Response(), map[string]interface{}{
			"Msg": msg,
		})
	})
	e.POST("/ctxc/intune", func(c echo.Context) error {
		// from chrome extension
		certpem := c.FormValue("cert") // pem
		msg := c.FormValue("msg")
		signB64 := c.FormValue("signatureB64")
		fmt.Printf("signB64: %v\n", signB64)
		signB64 = signB64[:strings.Index(signB64, "=")]
		sign, err := base64.RawStdEncoding.DecodeString(signB64)
		if err != nil {
			return err
		}
		fmt.Printf("certpem: %v\n", certpem)
		fmt.Printf("msg: %v\n", msg)
		fmt.Printf("signB64: %v\n", signB64)

		extsess, ok := chromeExtensionSessionData[msg]
		if !ok {
			return fmt.Errorf("invalid msg")
		}
		_, ok = userData[extsess.capId]
		if !ok {
			return fmt.Errorf("invalid user id")
		}

		certblk, rest := pem.Decode([]byte(certpem))
		if certblk == nil {
			return fmt.Errorf("err: certblk is nil")
		}
		fmt.Printf("rest: %v\n", rest)

		cert, err := x509.ParseCertificate(certblk.Bytes)
		if err != nil {
			return err
		}
		pubkey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("parse failed for rsa.pubkey")
		}
		hash := crypto.Hash.New(crypto.SHA256)
		hash.Write([]byte(msg))
		hashed := hash.Sum(nil)
		err = rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hashed, []byte(sign))
		if err != nil {
			return err
		}

		// TODO: 証明書チェーンの検証

		certFmted := CertToIntuneFmt(cert)
		if certFmted == "" {
			return fmt.Errorf("cannot format")
		}

		ctx, ok := notesToCtx[certFmted]
		if ok {
			userData[extsess.capId] = &User{
				capId:      extsess.capId,
				intuneCert: certFmted,
				intuneId:   ctx.Id,
				intuneCtx:  ctx,
			}
		} else {
			userData[extsess.capId] = &User{
				capId:      extsess.capId,
				intuneCert: certFmted,
			}
			fmt.Printf("certFmted: %v\n", certFmted)
		}

		return c.JSON(http.StatusAccepted, map[string]interface{}{
			"state": "ok",
		})
	})
	e.GET("/setup_intune", func(c echo.Context) error {
		request, err := http.NewRequest("GET", AUTH_URL, nil)
		if err != nil {
			return err
		}
		params := request.URL.Query()
		params.Add("client_id", CLIENT_ID)
		params.Add("response_type", "code")
		params.Add("redirect_uri", "http://localhost:9091/setup_intune/callback")
		params.Add("scope", INTUNE_SCOPE)
		params.Add("state", "12345")
		request.URL.RawQuery = params.Encode()
		c.Redirect(http.StatusTemporaryRedirect, request.URL.String())
		return nil

		// resp, err := http.DefaultClient.Do(request)
		// if err != nil {
		// 	return err
		// }
		// defer resp.Body.Close()

		// b, err := ioutil.ReadAll(resp.Body)
		// if err != nil {
		// 	return err
		// }
		// println(string(b))
	})
	e.GET("/test/api", func(c echo.Context) error {
		resp, err := getManagedDeviceAPI()
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		io.Copy(c.Response().Writer, resp.Body)

		return nil
	})
	e.GET("/setup_intune/callback", func(c echo.Context) error {
		queryParams := c.QueryParams()
		code := queryParams.Get("code")
		state := queryParams.Get("state")
		if state != "12345" {
			return errors.New("invalid scope")
		}

		values := url.Values{}
		values.Add("client_id", CLIENT_ID)
		values.Add("scope", INTUNE_SCOPE)
		values.Add("code", code)
		values.Add("redirect_uri", "http://localhost:9091/setup_intune/callback")
		values.Add("grant_type", "authorization_code")
		values.Add("client_secret", CLIENT_SECRET)
		fmt.Println(values.Encode())
		request, err := http.NewRequest("POST", TOKEN_URL, strings.NewReader(values.Encode()))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var mapData map[string]interface{}
		if err := json.Unmarshal(b, &mapData); err != nil {
			return err
		}
		fmt.Printf("mapData: %+v\n", mapData)
		intuneAccessToken, _ = mapData["access_token"].(string)
		intuneRefreshToken, _ := mapData["refresh_token"].(string)
		fmt.Printf("intuneRefreshToken: %v\n", intuneRefreshToken)
		println(intuneAccessToken)
		c.Redirect(http.StatusTemporaryRedirect, "/test/api")

		return nil
	})
	e.GET("/oauth2/authorize", func(c echo.Context) error {
		clientid := c.QueryParam("client_id")
		client := getClient(clientid)
		if client == nil {
			return errors.New("不正なクライアントです")
		}
		redirectUri := c.QueryParam("redirect_uri")
		if client.RedirectUri != redirectUri {
			return fmt.Errorf("不正なリダイレクトです")
		}
		sess, _ := store.Get(c.Request(), "capsession")
		reqid := GenerateRandomString(8)
		sess.Values["reqid"] = reqid
		sess.Values["state"] = c.QueryParam("state")
		sess.Save(c.Request(), c.Response())
		sessionClientInfo[reqid] = client

		if checkUserAuthenticated(c) {
			return renderHTML("front/authz.html", c.Response(), map[string]interface{}{
				"ID":        sess.Values["id"],
				"ReqEntity": client.ClientName,
				"ReqId":     reqid,
			})
		} else {
			return renderHTML("front/authn.html", c.Response(), map[string]interface{}{
				"ReqId": reqid,
			})
		}

	})
	e.POST("/oauth2/authenticate", func(c echo.Context) error {
		isAuthenticated := authenticateUser(c)
		if !isAuthenticated {
			return fmt.Errorf("bad authenticate")
		}

		authform := &AuthForm{}
		c.Bind(authform)
		reqid := authform.ReqId
		sreqid, ok := sessionClientInfo[reqid]
		fmt.Printf("%+v\n", sreqid)
		println(ok)
		for k := range sessionClientInfo {
			println(k == reqid)
		}
		if sessionClientInfo[reqid] == nil {
			return fmt.Errorf("error: 知らないreqidです")
		}
		clientConf := sessionClientInfo[reqid]
		delete(sessionClientInfo, reqid)
		newReqid := GenerateRandomString(8)
		sessionClientInfo[newReqid] = clientConf
		return renderHTML("front/authz.html", c.Response(), map[string]interface{}{
			"ID":        authform.Identifier,
			"ReqEntity": clientConf.ClientName,
			"ReqId":     newReqid,
		})
	})
	e.POST("/oauth2/authorize", func(c echo.Context) error {
		sess, _ := store.Get(c.Request(), "capsession")
		identifier, ok := sess.Values["id"].(string)
		if !ok {
			return fmt.Errorf("error: 無効なidです")
		}
		if identifier != "device1" {
			return fmt.Errorf("error: 知らない人です")
		}
		reqid := c.FormValue("reqid")
		if sessionClientInfo[reqid] == nil {
			return fmt.Errorf("error: 知らないreqidです")
		}
		clientConf := sessionClientInfo[reqid]
		delete(sessionClientInfo, reqid)
		redirectUri := clientConf.RedirectUri
		req, err := http.NewRequest("GET", redirectUri, nil)
		if err != nil {
			return err
		}
		scopes := []Scope{}
		if c.FormValue("intune_all") == "true" {
			scopes = append(scopes, IntuneAll)
		}
		params := req.URL.Query()
		code := GenerateRandomString(32)
		codeData := &CodeData{}
		codeData.code = code
		codeData.clientId = clientConf.ClientID
		codeData.redirectUri = clientConf.RedirectUri
		codeData.scopes = scopes
		codeData.capId = CAPID(identifier)
		codeStore[code] = codeData
		params.Set("code", code)
		params.Set("state", sess.Values["state"].(string))
		req.URL.RawQuery = params.Encode()

		c.Redirect(http.StatusSeeOther, req.URL.String())

		return nil
	})
	e.POST("/oauth2/cancel", func(c echo.Context) error {
		return nil
	})
	e.POST("/oauth2/token", func(c echo.Context) error {
		auth := c.Request().Header.Get("Authorization")
		authDecoded, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			return err
		}
		authDecodedStr := string(authDecoded)
		authUnescaped, err := url.QueryUnescape(authDecodedStr)
		if err != nil {
			return err
		}
		authUnescaped = authUnescaped[len("basic "):]
		clientAuth := strings.Split(authUnescaped, ":")
		clientId := clientAuth[0]
		clientSecret := clientAuth[1]
		client := getClient(clientId)
		if client == nil {
			return fmt.Errorf("err: invalid client")
		}
		serverClientSecret := getClientSecret(clientId)
		if serverClientSecret == "" || serverClientSecret != clientSecret {
			return fmt.Errorf("err: not correct clientsecret")
		}

		grantType := c.FormValue("grant_type")
		code := c.FormValue("code")
		redirectUri := c.FormValue("redirect_uri")

		println(grantType, code, redirectUri)
		if grantType != "authorization_code" {
			return fmt.Errorf("err: invalid grant type")
		}
		codeData := codeStore[code]
		if codeData == nil {
			return fmt.Errorf("code: codeData is nil")
		}
		if codeData.clientId != clientId {
			return fmt.Errorf("code: clientid is invalid")
		}
		if redirectUri != codeData.redirectUri {
			return fmt.Errorf("code: invalid redirect uri")
		}

		// アクセストークンの発行
		accessToken := GenerateRandomString(32)
		accessTokenData := &AccessTokenData{}
		accessTokenData.accessToken = accessToken
		accessTokenData.clientId = clientId
		accessTokenData.scopes = codeData.scopes
		accessTokenData.capId = codeData.capId
		accessTokenStore[accessToken] = accessTokenData

		return c.JSON(http.StatusOK, map[string]string{
			"access_token": accessToken,
			"token_type":   "Bearer",
		})
	})
	e.GET("/api/context", ApiForRP)

	// get_access_token := func() {
	// 	request, err := http.NewRequest("GET", AUTH_URL, nil)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	params := request.URL.Query()
	// 	params.Add("client_id", CLIENT_ID)
	// 	params.Add("response_type", "code")
	// 	params.Add("redirect_uri", "https://localhost:9091/callback")
	// 	params.Add("scope", SCOPE)
	// 	params.Add("state", "12345")
	// 	request.URL.RawQuery = params.Encode()
	// 	resp, err := http.DefaultClient.Do(request)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	defer resp.Body.Close()

	// 	b, err := ioutil.ReadAll(resp.Body)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	println(string(b))
	// }
	// get_access_token()
	e.Logger.Fatal(e.Start(":9091"))
}
