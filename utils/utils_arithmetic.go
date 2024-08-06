// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package utils

import (
	"fmt"
	"math/rand"
	"time"
)

/*
compare whether two byte slices are the same.

	return true, `ok` if two bytesSlices are equal, otherwise return false with the reason.
*/
func CmpByte2Slices(a []byte, b []byte) (bool, string) {
	lena, lenb := len(a), len(b)
	if lena != lenb {
		return false, fmt.Sprintf(`unequal: differentLen found:(%d,%d)`, lena, lenb)
	}
	for idx, val := range a {
		if val != b[idx] {
			return false, fmt.Sprintf(`unequal: differentVal found at:%d`, idx)
		}
	}
	return true, `ok`
}

type _Intx interface {
	~uint | ~int | ~int32 | ~uint32 | ~int64 | ~uint64 | ~uint16 | ~int16
}

// get the distance from two (u)int(x) numbers.
func AbsMinusInt[T _Intx](a T, b T) T {
	return max(a, b) - min(a, b)
}

/*
generate pseudo-random number between assigned parameter `min` and assigned parameter `max`.
*/
func generateRandomIntNumber(minn int, maxn int) int {
	rand.New(rand.NewSource(time.Now().Unix()))
	return rand.Intn(maxn-minn+1) + minn
}
