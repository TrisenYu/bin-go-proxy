package zipper

import (
	"log"
	"testing"

	cryptoprotect "selfproxy/cryptoProtect"
	"selfproxy/utils"
)

func TestZstdCompressionAlgorithm(t *testing.T) {
	helo := `my name is john. I am now majoring at GolangPrograming and distributed systems.` +
		`For some reasons, I encountered an intricacy which drove me mad so I come here to ask you for help.` +
		`I think the current string is inadequate for me or numerous machines to concate into several parts and send to` +
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
