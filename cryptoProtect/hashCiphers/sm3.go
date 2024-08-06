// SPDX-LICENSE-IDENTIFIER: GPL-2.0-Only
// (C) 2024 Author: <kisfg@hotmail.com>
package hashciphers

import (
	"hash"

	"github.com/emmansun/gmsm/sm3"
)

type SM3 struct {
	hasher hash.Hash
}

func (sm *SM3) CalculateHashOnce(msg []byte) []byte {
	tmp := sm3.Sum(msg)
	return tmp[:]
}

func (sm *SM3) GetHashLen() uint64 { return 32 }

func (sm *SM3) NewHasher() {
	if sm.hasher != nil {
		sm.hasher.Reset()
		return
	}
	sm.hasher = sm3.New()
}
func (sm *SM3) Accumulate(msg []byte) (cnt int, err error) { return sm.hasher.Write(msg) }
func (sm *SM3) AggregatedHash() []byte {
	if sm.hasher == nil {
		return nil
	}
	return sm.hasher.Sum(nil)
}
