// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package utils

func Uint64ToLittleEndianBytes(inp uint64) []byte {
	var res []byte
	for i := 0; i < 8; i++ {
		res = append(res, byte((inp>>(i<<3))&0xFF))
	}
	return res
}

func Uint32ToLittleEndianBytes(inp uint32) []byte {
	return []byte{byte(inp), byte(inp >> 8), byte(inp >> 16), byte(inp >> 24)}
}

func Uint16ToLittleEndianBytes(inp uint16) []byte {
	return []byte{byte(inp), byte(inp >> 8)}
}
