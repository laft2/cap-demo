package main

import (
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type ClientCert struct {
	Issuer string
	Serial string
}
type RadiusInfo struct {
	radiusId      string // macaddrと同じ
	MacAddr       string
	AcctSessionId string
	DeviceType    string
	ClientCert    ClientCert
	TimeStamp     uint64
	IsActive      bool // start/stopのシグナルから計算
}

type User struct {
	capId       CAPID
	radiusCert  ClientCert
	radiusId    string
	lastUpdated time.Time
	radiusCtx   *RadiusInfo
}

// radius id(macaddr) → radiusinfo
var unlinked = make(map[ClientCert]RadiusInfo)
var macaddrToClientCert = make(map[string]ClientCert)

var userData map[CAPID]*User

func setFromAuthdetail(authRow string) {
	fmt.Printf("authRow: %v\n", authRow)
	auths := strings.Split(authRow, "\n\n")
	for _, authEach := range auths {
		authEach = strings.TrimSpace(authEach)
		detail := strings.Split(authEach, "\n")
		for i := range detail {
			detail[i] = strings.TrimSpace(detail[i])
		}
		authMap := make(map[string]string)
		for _, v := range detail[1:] {
			// all target strings are "xxx = yyy"
			splited := strings.Split(v, " =")
			fmt.Printf("splited: %q\n", splited)
			front := strings.TrimSpace(splited[0])
			back := strings.TrimSpace(splited[1])
			authMap[front] = back
		}
		fmt.Printf("authMap[\"TLS-Client-Cert-Issuer\"]: %v\n", authMap["TLS-Client-Cert-Issuer"])
		var issuerCommonName string
		issuer := strings.Split(authMap["TLS-Client-Cert-Issuer"], "/")
		fmt.Printf("issuer: %q\n", issuer)
		const CommonNamePattern string = "CN="
		for _, v := range issuer {
			fmt.Printf("v: %v\n", v)
			idx := strings.Index(v, CommonNamePattern)
			if idx == -1 {
				continue
			}
			issuerCommonName = v[len(CommonNamePattern):]
		}
		serial := authMap["TLS-Client-Cert-Serial"]
		fmt.Printf("issuerCommonName: %v\n", issuerCommonName)
		fmt.Printf("serial: %v\n", serial)
		clientCert := ClientCert{
			Issuer: issuerCommonName,
			Serial: serial,
		}
		macaddr := authMap["Calling-Station-Id"]
		var contextInfo RadiusInfo
		contextInfo.radiusId = macaddr
		contextInfo.MacAddr = macaddr
		contextInfo.ClientCert = clientCert
		contextInfo.TimeStamp, _ = strconv.ParseUint(authMap["Timestamp"], 10, 64)
		contextInfo.IsActive = false

		isHit := false
		for _, u := range userData {
			if u.radiusCert == clientCert {
				u.radiusCtx = &contextInfo
				isHit = true
			}
		}
		if !isHit {
			unlinked[clientCert] = contextInfo
		}
		macaddrToClientCert[macaddr] = clientCert
	}
}

func getContext(clientCert ClientCert) (RadiusInfo, bool) {
	for _, u := range userData {
		if u.radiusCert == clientCert {
			return *u.radiusCtx, true
		}
	}
	if val, ok := unlinked[clientCert]; ok {
		return val, true
	}
	return RadiusInfo{}, false
}
func setContext(clientCert ClientCert, context RadiusInfo) {
	isHit := false
	for _, u := range userData {
		if u.radiusCert == clientCert {
			u.radiusCtx = &context
			isHit = true
		}
	}
	if !isHit {
		unlinked[clientCert] = context
	}
}
func LinkWithRadius(clientCert ClientCert, capId CAPID) bool {
	user, ok := userData[capId]
	if !ok {
		return false
	}
	ctx, ok := unlinked[clientCert]
	if !ok {
		return false
	}
	user.radiusCert = clientCert
	user.radiusCtx = &ctx
	user.radiusId = "accesspoint_name_" + ctx.MacAddr
	delete(unlinked, clientCert)

	return true
}
func UpdateContext(detailRow string, authRow string) {
	if len(strings.Split(authRow, "\n")) > 2 {
		setFromAuthdetail(authRow)
	}

	details := strings.Split(detailRow, "\n\n")
	for _, detailEach := range details {
		detailEach = strings.TrimSpace(detailEach)
		detail := strings.Split(detailEach, "\n")
		for i := range detail {
			detail[i] = strings.TrimSpace(detail[i])
		}
		fmt.Printf("detail: %q\n", detail)
		detailMap := make(map[string]string)
		for _, v := range detail[1:] {
			// all target strings are "xxx = yyy"
			splited := strings.Split(v, "=")
			front := strings.TrimSpace(splited[0])
			back := strings.TrimSpace(splited[1])
			detailMap[front] = back
		}
		macaddr := detailMap["Calling-Station-Id"]
		clientCert, ok := macaddrToClientCert[macaddr]
		if !ok {
			println("Not Found serial.")
			return
		}
		if detailMap["Acct-Status-Type"] == "Start" {
			context, ok := getContext(clientCert)
			if !ok {
				println("Not Found context")
				return
			}
			context.IsActive = true
			context.TimeStamp, _ = strconv.ParseUint(detailMap["Timestamp"], 10, 64)
			context.AcctSessionId = detailMap["Acct-Session-Id"]
			setContext(clientCert, context)
		} else if detailMap["Acct-Status-Type"] == "Interim-Update" {
			context, ok := getContext(clientCert)
			if !ok {
				println("Not Found context")
				return
			}
			context.TimeStamp, _ = strconv.ParseUint(detailMap["Timestamp"], 10, 64)
			setContext(clientCert, context)
		} else if detailMap["Acct-Status-Type"] == "Stop" {
			context, ok := getContext(clientCert)
			if !ok {
				println("Not Found context")
				return
			}
			context.IsActive = false
			context.TimeStamp, _ = strconv.ParseUint(detailMap["Timestamp"], 10, 64)
			context.AcctSessionId = detailMap["Acct-Session-Id"]
			delete(macaddrToClientCert, macaddr)
			setContext(clientCert, context)
		}
	}
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

func init() {
	userData = map[CAPID]*User{}
	userData[CAPID("device1")] = &User{
		capId:       "device1",
		lastUpdated: time.Now().Add(-500 * time.Hour),
	}
}
