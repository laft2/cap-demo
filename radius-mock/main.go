// 簡易的なradiusサーバーのログのモック
// ログの送信まで行う
// 簡単のため、単一のデバイスのコンテキストしか送信せず、
// いくつかのフィールドは省いている

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Detail struct {
	acctStatusType      string
	nasIpAddress        string
	userName            string
	nasPort             string
	nasPortType         string
	callingStationId    string
	calledStationId     string
	framedIpAddress     string
	acctMultiSessionId  string
	acctSessionId       string
	acctDelayTime       string
	acctAuthentic       string
	acctInputOctets     uint64
	acctOutputOctets    uint64
	acctInputPackets    uint64
	acctOutputPackets   uint64
	acctInputGigawords  uint64
	acctOutputGigawords uint64
	acctSessionTime     int64
	acctTerminateCause  string
	eventTimeStamp      string
	acctUniqueSessionId string
	timestamp           int64
}

type AuthDetail struct {
	packetType              string
	userName                string
	nasIpAddress            string
	nasPort                 string
	nasIdentifier           string
	nasPortType             string
	callingStationId        string
	calledStationId         string
	serviceType             string
	framedMtu               int
	eapMessage              string
	state                   string
	messageAuthenticator    string
	eventTimeStamp          string
	eapType                 string
	tlsClientCertSerial     string
	tlsClientCertExpiration string
	tlsClientCertSubject    string
	tlsClientCertIssuer     string
	tlsClientCertCommonName string
	timestamp               int64
}

func (auth AuthDetail) ToString() (res string) {
	res = ""
	time := time.Unix(auth.timestamp, 0)
	res += time.Format("Mon Jan 10 09:44:11 2022\n")
	res += fmt.Sprintf("\tPacket-Type = %v\n", auth.packetType)
	res += fmt.Sprintf("\tUser-Name = %v\n", auth.userName)
	res += fmt.Sprintf("\tNAS-IP-Address = %v\n", auth.nasIpAddress)
	res += fmt.Sprintf("\tNAS-Port = %v\n", auth.nasPort)
	res += fmt.Sprintf("\tNAS-Identifier = %v\n", auth.nasIdentifier)
	res += fmt.Sprintf("\tNAS-Port-Type = %v\n", auth.nasPortType)
	res += fmt.Sprintf("\tCalling-Station-Id = %v\n", auth.callingStationId)
	res += fmt.Sprintf("\tCalled-Station-Id = %v\n", auth.calledStationId)
	res += fmt.Sprintf("\tService-Type = %v\n", auth.serviceType)
	res += fmt.Sprintf("\tFramed-MTU = %v\n", auth.framedMtu)
	res += fmt.Sprintf("\tEAP-Message = %v\n", auth.eapMessage)
	res += fmt.Sprintf("\tState = %v\n", auth.state)
	res += fmt.Sprintf("\tMessage-Authenticator = %v\n", auth.messageAuthenticator)
	res += fmt.Sprintf("\tEvent-Timestamp = %v\n", auth.eventTimeStamp)
	res += fmt.Sprintf("\tEAP-Type = %v\n", auth.eapType)
	res += fmt.Sprintf("\tTLS-Client-Cert-Serial = %v\n", auth.tlsClientCertSerial)
	res += fmt.Sprintf("\tTLS-Client-Cert-Expiration = %v\n", auth.tlsClientCertExpiration)
	res += fmt.Sprintf("\tTLS-Client-Cert-Subject = %v\n", auth.tlsClientCertSubject)
	res += fmt.Sprintf("\tTLS-Client-Cert-Issuer = %v\n", auth.tlsClientCertIssuer)
	res += fmt.Sprintf("\tTLS-Client-Cert-Common-Name = %v\n", auth.tlsClientCertCommonName)
	return
}
func (detail Detail) ToString() (res string) {
	res = ""
	time := time.Unix(detail.timestamp, 0)
	res += time.Format("Mon Jan 01 15:04:05 2006\n")
	status := detail.acctStatusType
	status = strings.ToLower(status)
	res += fmt.Sprintf("\tAcct-Status-Type = %v\n", detail.acctStatusType)
	res += fmt.Sprintf("\tNAS-IP-Address = %v\n", detail.nasIpAddress)
	res += fmt.Sprintf("\tUser-Name = %v\n", detail.userName)
	res += fmt.Sprintf("\tNAS-Port = %v\n", detail.nasPort)
	res += fmt.Sprintf("\tNAS-Port-Type = %v\n", detail.nasPortType)
	res += fmt.Sprintf("\tCalling-Station-Id = %v\n", detail.callingStationId)
	res += fmt.Sprintf("\tCalled-Station-Id = %v\n", detail.calledStationId)
	res += fmt.Sprintf("\tFramed-IP-Address = %v\n", detail.framedIpAddress)
	res += fmt.Sprintf("\tAcct-Multi-Session-Id = %v\n", detail.acctMultiSessionId)
	res += fmt.Sprintf("\tAcct-Session-Id = %v\n", detail.acctSessionId)
	res += fmt.Sprintf("\tAcct-Delay-Time = %v\n", detail.acctDelayTime)
	if status == "interim-update" || status == "stop" {
		res += fmt.Sprintf("\tAcct-Input-Octets = %v\n", detail.acctInputOctets)
		res += fmt.Sprintf("\tAcct-Output-Octets = %v\n", detail.acctOutputOctets)
		res += fmt.Sprintf("\tAcct-Input-Packets = %v\n", detail.acctInputPackets)
		res += fmt.Sprintf("\tAcct-Output-Packets = %v\n", detail.acctOutputPackets)
		res += fmt.Sprintf("\tAcct-Input-Gigawords = %v\n", detail.acctInputGigawords)
		res += fmt.Sprintf("\tAcct-Output-Gigawords = %v\n", detail.acctOutputGigawords)
		res += fmt.Sprintf("\tAcct-Session-Time = %v\n", detail.acctSessionTime)
		if status == "stop" {
			res += fmt.Sprintf("\tAcct-Terminate-Cause = %v\n", detail.acctTerminateCause)
		}
	}
	res += fmt.Sprintf("\tAcct-Authentic = %v\n", detail.acctAuthentic)
	res += fmt.Sprintf("\tEvent-Timestamp = %v\n", detail.eventTimeStamp)
	res += fmt.Sprintf("\tAcct-Unique-Session-Id = %v\n", detail.acctUniqueSessionId)
	res += fmt.Sprintf("\tTimestamp = %v\n", detail.timestamp)
	return res
}

func sendContext(authDetail AuthDetail, detail Detail) error {
	formValues := url.Values{}
	if authDetail.callingStationId != "" {
		fmt.Printf("authDetail.ToString(): %v\n", authDetail.ToString())
		formValues.Set("auth", authDetail.ToString())
	}
	fmt.Printf("detail.ToString(): %v\n", detail.ToString())
	formValues.Set("detail", detail.ToString())
	request, err := http.NewRequest("POST", os.Getenv("CAP_URI"), strings.NewReader(formValues.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	// defer resp.Body.Close()
	// body, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	return err
	// }
	fmt.Printf("resp.StatusCode: %v\n", resp.StatusCode)
	return nil
}

func sendStartSignal() error {
	// 利用しない値については適当に埋めたり何も入れなかったりする
	authDetail := AuthDetail{
		packetType:           "Access-Request",
		nasIpAddress:         "192.168.0.1",
		nasPort:              "0",
		nasIdentifier:        "192.168.0.1",
		callingStationId:     os.Getenv("MAC_ADDRESS"),
		calledStationId:      "100000000001",
		serviceType:          "Framed-User",
		eapType:              "TLS",
		tlsClientCertSerial:  os.Getenv("TLS_CLIENT_SERIAL"),
		tlsClientCertSubject: os.Getenv("TLS_CLIENT_SUBJECT"),
		tlsClientCertIssuer:  os.Getenv("TLS_CLIENT_ISSUER"),
		timestamp:            time.Now().Unix(),
	}
	detail := Detail{
		acctStatusType:   "Start",
		nasIpAddress:     "192.168.0.1",
		nasPort:          "0",
		callingStationId: os.Getenv("MAC_ADDRESS"),
		calledStationId:  "100000000001",
		acctAuthentic:    "RADIUS",
		timestamp:        time.Now().Unix(),
	}
	return sendContext(authDetail, detail)
}

func sendInterimSignal(startedTime time.Time) error {
	// 利用しない値については適当に埋めたり何も入れなかったりする
	now := time.Now()
	difFromStart := now.Sub(startedTime).Seconds()
	detail := Detail{
		acctStatusType:    "Interim-Update",
		nasIpAddress:      "192.168.0.1",
		nasPort:           "0",
		callingStationId:  os.Getenv("MAC_ADDRESS"),
		calledStationId:   "100000000001",
		acctAuthentic:     "RADIUS",
		acctInputOctets:   uint64(100 * difFromStart),
		acctOutputOctets:  uint64(80 * difFromStart),
		acctInputPackets:  uint64(10 * difFromStart),
		acctOutputPackets: uint64(8 * difFromStart),
		acctSessionTime:   int64(difFromStart),
		timestamp:         now.Unix(),
	}
	return sendContext(AuthDetail{}, detail)
}
func sendStopSignal(startedTime time.Time) error {
	// 利用しない値については適当に埋めたり何も入れなかったりする
	now := time.Now()
	difFromStart := now.Sub(startedTime).Seconds()
	detail := Detail{
		acctStatusType:     "Stop",
		nasIpAddress:       "192.168.0.1",
		nasPort:            "0",
		callingStationId:   os.Getenv("MAC_ADDRESS"),
		calledStationId:    "100000000001",
		acctAuthentic:      "RADIUS",
		acctInputOctets:    uint64(100 * difFromStart),
		acctOutputOctets:   uint64(80 * difFromStart),
		acctInputPackets:   uint64(10 * difFromStart),
		acctOutputPackets:  uint64(8 * difFromStart),
		acctSessionTime:    int64(difFromStart),
		acctTerminateCause: "Idle-Timeout",
		timestamp:          now.Unix(),
	}
	return sendContext(AuthDetail{}, detail)
}

// 必要な環境変数が揃っているか確認する
// 環境変数の例については実装内にコメントする
func checkEnvs() bool {
	res := true
	var ok bool
	// http://localhost:9091/radius/context
	// 他の実装と合わせて確認する場合はパス部分は上記のままにすること
	_, ok = os.LookupEnv("CAP_URI")
	res = res && ok
	// /C=JP/O=EXAMPLE/CN=Client01
	_, ok = os.LookupEnv("TLS_CLIENT_SUBJECT")
	res = res && ok
	// /C=JP/O=EXAMPLE/CN=Intermediate CA
	_, ok = os.LookupEnv("TLS_CLIENT_ISSUER")
	res = res && ok
	// 1
	_, ok = os.LookupEnv("TLS_CLIENT_SERIAL")
	res = res && ok
	// 000000000001
	_, ok = os.LookupEnv("MAC_ADDRESS")
	res = res && ok
	return res
}
func main() {
	if !checkEnvs() {
		println("You should export environment variables: CAP_URI, TLS_CLIENT_SUBJECT, TLS_CLIENT_ISSUER, TLS_CLIENT_SERIAL, MAC_ADDRESS")
		return
	}
	alreadyStarted := false
	var startedTime time.Time
	for range time.Tick(50 * time.Millisecond) {
		println("input 'start' or 'interim' or 'stop'")
		print(">>> ")
		var state string
		fmt.Scan(&state)
		state = strings.ToLower(state)
		if state == "start" {
			if err := sendStartSignal(); err != nil {
				fmt.Printf("err: %v\n", err)
			}
			startedTime = time.Now()
			alreadyStarted = true
		} else if state == "interim" {
			if alreadyStarted {
				sendInterimSignal(startedTime)
				if err := sendInterimSignal(startedTime); err != nil {
					fmt.Printf("err: %v\n", err)
				}
			}
		} else if state == "stop" {
			if alreadyStarted {
				if err := sendStopSignal(startedTime); err != nil {
					fmt.Printf("err: %v\n", err)
				}
				alreadyStarted = false
			}
		} else {
			continue
		}
	}
}
