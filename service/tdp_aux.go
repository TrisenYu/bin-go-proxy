package service

import utils "bingoproxy/utils"

func RefTimeEvolution(
	last_timeval,
	curr_timeval,
	time_interval uint64,
) (adjust_val uint64) {
	/* TODO
	   +----> measured error
	   |
	   +----> intergrate, const
	   |
	   +----> derivate, const
	*/
	return
}

func FillHeader(
	id, seq, ack uint32,
	payloadLen uint16, advanck uint64,
	bits __tdp_bits__,
	paddedOrNot bool, pms uint32, seed [3]byte,
) []byte {
	a := utils.Uint32ToLittleEndianBytes(id)
	a = append(a, utils.Uint16ToLittleEndianBytes(payloadLen)...)
	a = append(a, utils.Uint32ToLittleEndianBytes(seq)...)
	a = append(a, utils.Uint32ToLittleEndianBytes(ack)...)
	a = append(a, utils.Uint64ToLittleEndianBytes(advanck)...)
	a = append(a, byte(bits))

	if !paddedOrNot {
		return a
	}
	a = append(a, utils.Uint32ToLittleEndianBytes(pms)...)
	a = append(a, seed[:]...)
	return a
}

func (tdp *TDPControlBlock) generateSeed() {
}

func (tdp *TDPControlBlock) copySeed() {
}
