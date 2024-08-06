// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package utils

import (
	crand "crypto/rand"
	"math/rand"
)

const letters string = "qewr4560tyuiopadsfgh123jklzxcvbnmQWERTY789UIOPASDFGHJKLZCXVBNM"

// generate pseudo-random string
func GenerateEnterableRandomString(lena int64) string {
	rand.New(rand.NewSource(lena))
	res := make([]byte, lena)
	for i := range res {
		res[i] = letters[(rand.Int63n(lena))%int64(len(letters))]
	}
	return string(res)
}

func SetRandByte(inp *[]byte) (int, error) {
	return crand.Read(*inp)
}
