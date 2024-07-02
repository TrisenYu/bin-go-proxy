// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package cryptoprotect

import "github.com/emmansun/gmsm/sm3"

func CalculateFlowSM3Hash(msg []byte) [32]byte {
	return sm3.Sum(msg)
}

type SM3 struct{}

func (sm *SM3) CalculateHash(msg []byte) []byte {
	tmp := sm3.Sum(msg)
	return tmp[:]
}
