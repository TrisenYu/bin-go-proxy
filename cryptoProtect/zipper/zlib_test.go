// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package zipper

import (
	"log"
	"testing"

	cryptoprotect "bingoproxy/cryptoProtect"
	utils "bingoproxy/utils"
)

func TestZstdCompressionAlgorithm(t *testing.T) {
	helo := `my name is john. I am now majoring at GolangPrograming and distributed systems.` +
		`For some reasons, I encountered an intricacy which drove me mad so I come here to ask you for help.` +
		`I think the current string is inadequate for me or numerous machines to concatenate into several parts and send to` +
		`others with the aim of calculating hash.`
	bhelo := []byte(helo)
	var zz cryptoprotect.CompOption = &Zlib{}
	zz.InitCompresser()
	man, err := zz.CompressMsg(bhelo)
	if err != nil {
		log.Println(err)
	}
	utils.BytesHexForm(man)
	utils.BytesHexForm(bhelo)
}
