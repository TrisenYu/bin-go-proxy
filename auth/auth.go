// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package auth

import (
	"log"
	"os"
	"sync"

	"selfproxy/utils"
)

const (
	TokenLen = 16
	letters  = "qewr4560tyuiopadsfgh123jklzxcvbnmQWERTY789UIOPASDFGHJKLZCXVBNM"
	// TODO: read from config and create corresponding implementation
	ack_path     = `./auth/.proxy-ack.txt`
	ExpiringTime = 3
)

var amu sync.RWMutex

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
	_, err := os.Lstat(ack_path)
	return !os.IsNotExist(err)
}

func CreateAcessToken() {
	if IsAcessTokenExisited() {
		return
	}

	buf := utils.GenerateEnterableRandomString(TokenLen)
	err := os.WriteFile(ack_path, []byte(buf), 0o644)
	if err != nil {
		panic(err)
	}
}

func ReadAccessToken() ([]byte, error) {
	amu.RLock()
	res, err := os.ReadFile(ack_path)
	amu.RUnlock()
	if err != nil {
		return []byte(``), err
	}
	return res, nil
}

func RemoveAccessFile() {
	amu.Lock()
	err := os.Remove(ack_path)
	amu.Unlock()
	if err != nil {
		panic(err)
	}
	log.Println(`Access token has been removed.`)
}

func ChangeToken() string {
	if !IsAcessTokenExisited() {
		return ""
	}
	res := utils.GenerateEnterableRandomString(TokenLen)
	amu.Lock()
	err := os.WriteFile(ack_path, []byte(res), 0o644)
	amu.Unlock()
	if err != nil {
		panic(err)
	}
	return res
}
