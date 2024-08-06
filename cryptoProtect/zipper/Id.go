// SPDX-LICENSE-IDENTIFIER: GPL-2.0-ONLY
// (C) 2024 Author: <kisfg@hotmail.com>
package zipper

type IdCompresser struct{}

func (id *IdCompresser) InitCompresser() error                    { return nil }
func (id *IdCompresser) InitDecompresser() error                  { return nil }
func (id *IdCompresser) CompressMsg(msg []byte) ([]byte, error)   { return msg, nil }
func (id *IdCompresser) DecompressMsg(msg []byte) ([]byte, error) { return msg, nil }
