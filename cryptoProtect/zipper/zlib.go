// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package zipper

import (
	"bytes"
	"compress/zlib"
)

type Zlib struct{}

func (z *Zlib) InitCompresser() error {
	return nil
}

// todo: lengthy bytes after compression
func (z *Zlib) InitDecompresser() error {
	return nil
}

func (z *Zlib) CompressMsg(msg []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	w.Write(msg)
	w.Close()
	return buf.Bytes(), err
}

func (z *Zlib) DecompressMsg(msg []byte) ([]byte, error) {
	var res []byte
	buf := bytes.NewBuffer(msg)
	r, err := zlib.NewReader(buf)
	if err != nil {
		return res, err
	}
	_, err = r.Read(res)
	r.Close()
	return res, err
}
