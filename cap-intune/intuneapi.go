package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type ManagedDevice struct {
	// OdataType        string `json:"@odata.type"`
	Id               string `json:"id"`
	EnrolledDateTime string `json:"enrolledDateTime"`
	LastSyncDateTime string `json:"lastSyncDateTime"`
	OperatingSystem  string `json:"operatingSystem"`
	ComplianceState  string `json:"complianceState"`
	JailBroken       string `json:"jailBroken"`
	OsVersion        string `json:"osVersion"`
	LostModeState    string `json:"lostModeState"`
	Notes            string `json:"notes"`
}

type User struct {
	capId       CAPID
	intuneCert  string
	intuneId    string
	lastUpdated time.Time
	intuneCtx   *ManagedDevice
}

var userData map[CAPID]*User

type NotesToCtx map[string]*ManagedDevice

var notesToCtx NotesToCtx

func buildIntuneRequestGet(deviceId string) *http.Request {
	intuneApiUri := os.Getenv("intune_api_uri")
	request, err := http.NewRequest("GET", intuneApiUri, nil)
	if err != nil {
		return nil
	}
	request.URL.Path = path.Join(request.URL.Path, deviceId)

	params := request.URL.Query()
	params.Add("$select", "id,notes,operatingSystem,jailBroken,osVersion,enrolledDateTime,lastSyncDateTime,complianceState,lostModeState")
	// TODO: 色々足す

	request.URL.RawQuery = params.Encode()

	request.Header.Add("Authorization", "Bearer "+intuneAccessToken)
	return request
}
func buildIntuneRequestList() *http.Request {
	accessToken := intuneAccessToken
	intuneApiUri := os.Getenv("intune_api_uri")
	request, err := http.NewRequest("GET", intuneApiUri, nil)
	if err != nil {
		return nil
	}

	params := request.URL.Query()
	// notesフィールドは遅延読み込みされるらしくてこれでも読み込めない……
	// (個別に読み込む必要がある)
	// params.Add("$select", "id,notes")
	params.Add("$select", "id")

	request.URL.RawQuery = params.Encode()

	request.Header.Add("Authorization", "Bearer "+accessToken)
	return request
}

func GetManagedDeviceAll() error {
	println("called GetManagedDeviceAll")
	client := &http.Client{
		Timeout: time.Duration(5 * time.Second),
	}

	for _, u := range userData {
		request := buildIntuneRequestGet(u.intuneId)
		if request == nil {
			return fmt.Errorf("failed to build uri")
		}
		resp, err := client.Do(request)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		managedDevice := ManagedDevice{}
		// u.intuneCtx = new(ManagedDevice)
		if err := json.Unmarshal(body, &managedDevice); err != nil {
			return err
		}
		u.intuneCtx = &managedDevice
		u.lastUpdated = time.Now()
		fmt.Printf("resp: %v\n", resp)
		fmt.Printf("u.intuneCtx: %+v\n", u.intuneCtx)
	}
	fmt.Printf("userData: %+v\n", userData)
	return nil
}

func GetNotes() error {
	client := &http.Client{
		Timeout: time.Duration(5 * time.Second),
	}
	request := buildIntuneRequestList()
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var payload = struct {
		Value []struct {
			Id string `json:"id"`
		} `json:"value"`
	}{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return err
	}
	fmt.Printf("payload: %+v\n", payload)

	for _, u := range payload.Value {
		request := buildIntuneRequestGet(u.Id)
		if request == nil {
			continue
		}
		resp, err := client.Do(request)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		managedDevice := ManagedDevice{}
		if err := json.Unmarshal(body, &managedDevice); err != nil {
			continue
		}
		if managedDevice.Notes == "" {
			continue
		}
		notesToCtx[managedDevice.Notes] = &managedDevice
		fmt.Printf("managedDevice.Notes: %v\n", managedDevice.Notes)
	}
	return nil
}

func CertToIntuneFmt(cert *x509.Certificate) string {
	notes := ""
	issuer := cert.Issuer
	if len(issuer.Country) == 0 || len(issuer.Province) == 0 || len(issuer.Organization) == 0 {
		return ""
	}
	notes += fmt.Sprintf("Issuer: C = %s, ST = %s, O = %s, CN = %s\n", issuer.Country[0], issuer.Province[0], issuer.Organization[0], issuer.CommonName)
	notes += fmt.Sprintf("Serial Number: %v\n", cert.SerialNumber)
	return notes
}

func updateAccessToken() error {
	refreshToken := os.Getenv("intune_refresh_token")
	values := url.Values{}
	values.Add("client_id", os.Getenv("intune_client_id"))
	values.Add("scope", INTUNE_SCOPE)
	values.Add("redirect_uri", "http://localhost:9091/setup_intune/callback")
	values.Add("grant_type", "refresh_token")
	values.Add("refresh_token", refreshToken)
	values.Add("client_secret", os.Getenv("intune_client_secret"))

	request, err := http.NewRequest("POST", os.Getenv("intune_token_uri"), strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var res = struct {
		AccessToken string `json:"access_token"`
	}{}
	if err := json.Unmarshal(body, &res); err != nil {
		return err
	}
	if len(res.AccessToken) > 10 {
		intuneAccessToken = res.AccessToken
	}
	return nil
}

func init() {
	userData = map[CAPID]*User{}
	userData[CAPID("device1")] = &User{
		capId: "device1",
		// intuneId:    "26005678-a9a9-4041-941f-dad2d37735f3",
		// lastUpdated: time.Now().Add(-5 * time.Hour),
	}
	notesToCtx = NotesToCtx{}
	updateAccessToken()
	// intuneAccessToken = os.Getenv("intune_access_token")
	// fmt.Printf("intuneAccessToken: %v\n", intuneAccessToken)
	// fmt.Printf("updateAccessToken(): %v\n", updateAccessToken())
	fmt.Printf("GetNotes(): %v\n", GetNotes())
}
