package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type DeviceContext struct {
	EnrolledDateTime string `json:"enrolledDateTime"`
	LastSyncDateTime string `json:"lastSyncDateTime"`
	OperatingSystem  string `json:"operatingSystem"`
	ComplianceState  string `json:"complianceState"`
	JailBroken       string `json:"jailBroken"`
	OsVersion        string `json:"osVersion"`
	LostModeState    string `json:"lostModeState"`
}

func CheckContextIntune(token string) (bool, error) {
	client := &http.Client{
		Timeout: time.Duration(5 * time.Second),
	}

	request, err := http.NewRequest("GET", API_EP_CAP1, nil)
	if err != nil {
		return false, err
	}

	params := request.URL.Query()

	request.URL.RawQuery = params.Encode()
	request.Header.Add("Authorization", "Bearer "+token)

	resp, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	ctx := DeviceContext{}
	if err := json.Unmarshal(body, &ctx); err != nil {
		return false, err
	}
	fmt.Printf("temp: %#v\n", ctx)

	// デバイスの状態を確認する
	if ctx.ComplianceState == "compliant" && ctx.JailBroken == "False" &&
		ctx.LostModeState == "disabled" {
		return true, nil
	}
	return false, nil
}

type RadiusInfo struct {
	TimeStamp uint64 `json:"timestamp"`
	IsActive  bool   `json:"is_active"`
}

func CheckContextRadius(token string) (bool, error) {
	client := &http.Client{
		Timeout: time.Duration(5 * time.Second),
	}

	request, err := http.NewRequest("GET", API_EP_CAP2, nil)
	if err != nil {
		return false, err
	}

	params := request.URL.Query()

	request.URL.RawQuery = params.Encode()
	request.Header.Add("Authorization", "Bearer "+token)

	resp, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	radiusInfo := RadiusInfo{}
	if err := json.Unmarshal(body, &radiusInfo); err != nil {
		return false, err
	}
	fmt.Printf("temp: %#v\n", radiusInfo)

	// デバイスの状態を確認する
	if radiusInfo.IsActive {
		return true, nil
	}
	return false, nil
}
