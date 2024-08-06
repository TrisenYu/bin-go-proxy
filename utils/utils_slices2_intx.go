// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package utils

func LittleEndianBytesToUint16(inp [2]byte) (res uint16) {
	var functor func(byte, int) uint16 = func(b byte, i int) uint16 { return uint16(b) << i }
	res = functor(inp[0], 0) | functor(inp[1], 8)
	return
}

func LittleEndianBytesToUint32(inp [4]byte) (res uint32) {
	var functor func(byte, int) uint32 = func(b byte, i int) uint32 { return uint32(b) << i }
	res = functor(inp[0], 0) | functor(inp[1], 8) | functor(inp[2], 16) | functor(inp[3], 24)
	return
}

func LittleEndianBytesToUint64(inp [8]byte) (res uint64) {
	var functor func(byte, int) uint64 = func(b byte, i int) uint64 { return uint64(b) << i }
	res = functor(inp[0], 0) | functor(inp[1], 8) | functor(inp[2], 16) | functor(inp[3], 24)
	res |= functor(inp[4], 32) | functor(inp[5], 40) | functor(inp[6], 48) | functor(inp[7], 56)
	return
}
