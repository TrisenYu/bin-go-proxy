// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package zipper

type IdCompress struct{}

func (id *IdCompress) InitCompresser() error                    { return nil }
func (id *IdCompress) InitDecompresser() error                  { return nil }
func (id *IdCompress) CompressMsg(msg []byte) ([]byte, error)   { return msg, nil }
func (id *IdCompress) DecompressMsg(msg []byte) ([]byte, error) { return msg, nil }
