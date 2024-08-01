// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package auth

import (
	"log"
	"os"
	"sync"

	config "bingoproxy/config"
	utils "bingoproxy/utils"
)

const (
	TokenLen     = 16
	letters      = "qewr4560tyuiopadsfgh123jklzxcvbnmQWERTY789UIOPASDFGHJKLZCXVBNM"
	ExpiringTime = 3 // TODO
)

var authMu sync.RWMutex

func AuthValidation(remote_token []byte) (bool, string) {
	buf, err := ReadAccessToken()
	if err != nil {
		return false, "Failed to read from the ack file due to" + err.Error()
	}
	if len(buf) == 0 {
		return false, "Failed to authenticate due to empty token."
	}
	flag, reason := utils.CompareByteSliceEqualOrNot(buf, remote_token)
	return flag, reason
}

func IsAcessTokenExisited() bool {
	_, err := os.Lstat(config.GlobalProxyConfiguration.Local.PathToAccessToken)
	return !os.IsNotExist(err)
}

func CreateAcessToken() {
	if IsAcessTokenExisited() {
		return
	}

	buf := utils.GenerateEnterableRandomString(TokenLen)
	err := os.WriteFile(config.GlobalProxyConfiguration.Local.PathToAccessToken, []byte(buf), 0o644)
	if err != nil {
		panic(err)
	}
}

func ReadAccessToken() ([]byte, error) {
	authMu.RLock()
	res, err := os.ReadFile(config.GlobalProxyConfiguration.Local.PathToAccessToken)
	authMu.RUnlock()
	if err != nil {
		return []byte{}, err
	}
	return res, nil
}

func RemoveAccessFile() {
	authMu.Lock()
	err := os.Remove(config.GlobalProxyConfiguration.Local.PathToAccessToken)
	authMu.Unlock()
	if err != nil {
		panic(err)
	}
	log.Println(`Access token has been removed.`)
}

func ChangeToken() string {
	if !IsAcessTokenExisited() {
		return ``
	}
	res := utils.GenerateEnterableRandomString(TokenLen)
	authMu.Lock()
	err := os.WriteFile(config.GlobalProxyConfiguration.Local.PathToAccessToken, []byte(res), 0o644)
	authMu.Unlock()
	if err != nil {
		panic(err)
	}
	return res
}

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	CreateAcessToken()
	res, err := ReadAccessToken()
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(`accessToken is "` + string(res) + `"`)
}
