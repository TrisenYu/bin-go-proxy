package zipper

type IdCompress struct{}

func (id *IdCompress) InitCompresser() error                    { return nil }
func (id *IdCompress) InitDecompresser() error                  { return nil }
func (id *IdCompress) CompressMsg(msg []byte) ([]byte, error)   { return msg, nil }
func (id *IdCompress) DecompressMsg(msg []byte) ([]byte, error) { return msg, nil }
