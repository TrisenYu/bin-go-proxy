// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package utils

import (
	"encoding/hex"
	"log"
)

/*
Debug function.

	Used for dumping the hex representation of a byte slice.
*/
func BytesHexForm(inp []byte) {
	if len(inp) == 0 {
		log.Println(0)
		return
	}
	log.Println(hex.EncodeToString(inp))
}

/*
Debug function.

	attach description to slice"s hex representation.
*/
func AddTag2HexHeader(hexer []byte, v ...any) {
	log.Println(v, hex.EncodeToString(hexer))
}
