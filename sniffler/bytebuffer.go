package main

import (
	crc32 "hash/crc32"
)

type BitBuffer struct {
	bytes   []byte
	cur_bit uint32
}

func UnpackBytes(b []byte, o uint32) uint32 {
	return (uint32(b[o+3]) << 24) | (uint32(b[o+2]) << 16) | (uint32(b[o+1]) << 8) | uint32(b[o])
}

// ReadUBitLong reads bits from the buffer and places them into a uint64.  Max
// supported bits is 64 for now, since we place the read bits into a uint64
// and can't shove more than 64 bits into that.
// TODO: figure out how to deal with odd b.cur_bit values (aka 3)
func (b *BitBuffer) ReadUBitLong(num_bits uint32) uint32 {
	start_bit := b.cur_bit & uint32(31)
	end_bit := b.cur_bit + num_bits - 1

	wo1 := b.cur_bit >> 3
	wo2 := end_bit >> 3

	//log.Printf("\t\tBitPos: %d", b.cur_bit)
	b.cur_bit += num_bits

	mask := uint32((2 << (num_bits - 1)) - 1)

	w1 := UnpackBytes(b.bytes, wo1) >> start_bit
	w2 := UnpackBytes(b.bytes, wo2) << (32 - start_bit)

	return (w1 | w2) & mask
}

func (b *BitBuffer) ReadLong() uint32 {
	return uint32(b.ReadUBitLong(32))
}

func (b *BitBuffer) ReadShort() uint16 {
	return uint16(b.ReadUBitLong(16))
}

func (b *BitBuffer) ReadByte() byte {
	return byte(b.ReadUBitLong(8))
}

func (b *BitBuffer) ReadBit() byte {
	var value byte = b.bytes[b.cur_bit>>3] >> (b.cur_bit & 7)
	b.cur_bit += 1
	return value & 1
}

func (b *BitBuffer) DoChecksum(offset uint32) uint16 {
	checksum := crc32.ChecksumIEEE(b.bytes[offset:])
	lower_word := uint16(checksum & 0xffff)
	upper_word := uint16((checksum >> 16) & 0xffff)

	return lower_word ^ upper_word
}
