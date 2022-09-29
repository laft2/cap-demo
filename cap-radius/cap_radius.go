package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"net/url"
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
		res.RedirectUri = "http://localhost:10001/oauth2/cap2/callback"
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
	IsRadiusRegistered bool
	IsActive           bool
	Timestamp          string
	MacAddress         string
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
	RadiusAll Scope = "radius_all"
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
	getManagedDeviceAPI := func() (*http.Response, error) {
		return nil, nil
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
		isRadiusRegistered := len(user.radiusCert.Issuer) > 10
		radiusInfo := user.radiusCtx
		if radiusInfo == nil {
			return renderHTML("front/index.html", c.Response(), IndexTemplate{
				ID:                 id.(string),
				IsRadiusRegistered: isRadiusRegistered,
			})
		}

		timestamp := time.Unix(int64(radiusInfo.TimeStamp), 0).Local().Format(time.RFC3339)
		return renderHTML("front/index.html", c.Response(), IndexTemplate{
			ID:                 id.(string),
			IsRadiusRegistered: isRadiusRegistered,
			IsActive:           radiusInfo.IsActive,
			Timestamp:          timestamp,
			MacAddress:         radiusInfo.MacAddr,
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
	e.GET("/ctxc/radius", func(c echo.Context) error {
		if !checkUserAuthenticated(c) {
			return c.Redirect(http.StatusSeeOther, "/authenticate")
		}
		msg := GenerateRandomString(32)
		sess, _ := store.Get(c.Request(), "capsession")
		chromeExtensionSessionData[msg] = &ChromeExtensionSession{
			msg:   msg,
			capId: CAPID(sess.Values["id"].(string)),
			ctxc:  "radius",
		}
		return renderHTML("front/radiusid.html", c.Response(), map[string]interface{}{
			"Msg": msg,
		})
	})
	e.POST("/ctxc/radius", func(c echo.Context) error {
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

		certRadiusFmt := ClientCert{}
		certRadiusFmt.Issuer = cert.Issuer.CommonName
		certRadiusFmt.Serial = cert.SerialNumber.String()

		fmt.Printf("certRadiusFmt.Issuer: %v\n", certRadiusFmt.Issuer)
		fmt.Printf("certRadiusFmt.Serial: %v\n", certRadiusFmt.Serial)

		if certRadiusFmt.Issuer == "" || certRadiusFmt.Serial == "" {
			return fmt.Errorf("cannot format")
		}

		ok = LinkWithRadius(certRadiusFmt, extsess.capId)
		if !ok {
			return fmt.Errorf("cannot find matching context")
		}

		return c.JSON(http.StatusAccepted, map[string]interface{}{
			"state": "ok",
		})
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
		if c.FormValue("radius_all") == "true" {
			scopes = append(scopes, RadiusAll)
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
	e.GET("/admin", func(c echo.Context) error {
		c.JSON(http.StatusAccepted, map[string]interface{}{
			"Unlinked":  unlinked,
			"Registerd": userData,
		})
		return nil
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
	e.Logger.Fatal(e.Start(":9092"))
}
