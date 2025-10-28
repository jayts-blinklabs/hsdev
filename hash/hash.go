package main

import (
"fmt"
	"encoding/binary"
	"unsafe"
)

const SHA3_MAX_PERMUTATION_SIZE = 25
const SHA3_MAX_RATE_IN_QWORDS = 24

type Sha3Ctx struct {
	Hash [SHA3_MAX_PERMUTATION_SIZE]uint64
	Message [SHA3_MAX_RATE_IN_QWORDS]uint64
	Rest uint
	BlockSize uint
}

// Header represents a block header
type Header struct {
	// Preheader.
	Nonce		uint32
	Time		uint64
	PrevBlock	[32]byte
	NameRoot	[32]byte	// same as "uint8_t name_root[32]" ?

	// Subheader.
	ExtraNonce	[24]byte
	ReservedRoot	[32]byte
	WitnessRoot	[32]byte
	MerkleRoot	[32]byte
	Version		uint32
	Bits		uint32

	// Mask.
	Mask		[32]byte

	Cache bool
	Hash [32]byte
	Height uint32
	Work [32]byte

	Next *Header
}

func HeaderPadding(hdr *Header, pad []byte, size int) {
	for i := 0; i < size; i++ {
		pad[i] = hdr.PrevBlock[i%32] ^ hdr.NameRoot[i%32]
	}
}

// TODO: data is a level more indirected than in the C code
// Why? Is it ok?
func WriteBytes(data **[]byte, bytes []byte, size int) int {
	if *data == nil { return size }
	copy(**data, bytes)
	// Advance the pointer by `size` bytes
	temp := (**data)[size:]
	*data = &temp
	return size
}

// TODO: This assumes little endian
// (also in WriteU64(), just below
func WriteU32(data **[]byte, out uint32) int {
	if *data == nil { return 4 }
	binary.LittleEndian.PutUint32(**data, out)
	temp := (**data)[4:]
	*data = &temp
	return 4
}

func WriteU64(data **[]byte, out uint64) int {
	if *data == nil { return 8 }
	binary.LittleEndian.PutUint64(**data, out)
	temp := (**data)[8:]
	*data = &temp
	return 8
}

func HeaderSubWrite(hdr *Header, data **[]byte) int {
	s := 0
	s += WriteBytes(data, hdr.ExtraNonce[:], 24)
	s += WriteBytes(data, hdr.ReservedRoot[:], 32)
	s += WriteBytes(data, hdr.WitnessRoot[:], 32)
	s += WriteBytes(data, hdr.MerkleRoot[:], 32)
	s += WriteU32(data, hdr.Version)
	s += WriteU32(data, hdr.Bits)
	return s
}

func HeaderSubSize(hdr *Header) int {
	return HeaderSubWrite(hdr, nil)
}

func HeaderSubEncode(hdr *Header, data []byte) int {
	dptr := &data
	return HeaderSubWrite(hdr, &dptr)
}

const BLAKE2B_BLOCKBYTES = 128
const BLAKE2B_OUTBYTES = 64
const BLAKE2B_KEYBYTES = 64
const BLAKE2B_SALTBYTES = 16
const BLAKE2B_PERSONALBYTES = 16

type Blake2bCtx struct {
	H [8]uint64
	T [2]uint64
	F [2]uint64
	Buf [BLAKE2B_BLOCKBYTES]byte
	Buflen int
	Outlen int
	LastNode uint8
}

func Blake2bIncrementCounter(ctx *Blake2bCtx, inc uint64) {
	ctx.T[0] += inc
	if ctx.T[0] < inc {
		ctx.T[1] += 1
	}
}

var blake2bSigma [12][16]uint8 = [12][16]uint8{
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12 , 0,  2, 11,  7,  5,  3 },
}

func Load64(src []byte) uint64 {
	return binary.LittleEndian.Uint64(src)
}

func Store32(dst []byte, w uint32) {
	binary.LittleEndian.PutUint32(dst, w)
}

func Rotr64(w uint64, c uint) uint64 {
	return (w >> c) | (w << (64 - c))
}

func G(r int, i int, a, b, c, d *uint64, m [16]uint64) {
	*a = *a + *b + m[blake2bSigma[r][2*i+0]]
	*d = Rotr64(*d ^ *a, 32)
	*c = *c + *d
	*b = Rotr64(*b ^ *c, 24)
	*a = *a + *b + m[blake2bSigma[r][2*i+1]]
	*d = Rotr64(*d ^ *a, 16)
	*c = *c + *d
	*b = Rotr64(*b ^ *c, 63)
}

// TODO: This was "static const uint64_t". const?
var blake2bIV [8]uint64 = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// Checked by eye up to here ++++++++

func Blake2bCompress(ctx *Blake2bCtx, block [BLAKE2B_BLOCKBYTES]byte) {
	var m [16]uint64
	var v [16]uint64

	for i := 0; i < 16; i++ { m[i] = Load64(block[i*8 : i*8+8]) }

	for i := 0; i < 8; i++ { v[i] = ctx.H[i] }

	v[8] = blake2bIV[0]
	v[9] = blake2bIV[1]
	v[10] = blake2bIV[2]
	v[11] = blake2bIV[3]
	v[12] = blake2bIV[4] ^ ctx.T[0]
	v[13] = blake2bIV[5] ^ ctx.T[1]
	v[14] = blake2bIV[6] ^ ctx.F[0]
	v[15] = blake2bIV[7] ^ ctx.F[1]

	for r := 0; r < 12; r++ {
		G(r, 0, &v[0], &v[4], &v[8], &v[12], m)
		G(r, 1, &v[1], &v[5], &v[9], &v[13], m)
		G(r, 2, &v[2], &v[6], &v[10], &v[14], m)
		G(r, 3, &v[3], &v[7], &v[11], &v[15], m)
		G(r, 4, &v[0], &v[5], &v[10], &v[15], m)
		G(r, 5, &v[1], &v[6], &v[11], &v[12], m)
		G(r, 6, &v[2], &v[7], &v[8], &v[13], m)
		G(r, 7, &v[3], &v[4], &v[9], &v[14], m)
	}

	for i := 0; i < 8; i++ { ctx.H[i] ^= v[i] ^ v[i+8] }
}

func Blake2bUpdate(ctx *Blake2bCtx, pin []byte, inlen int) int {
	in := pin

	if inlen > 0 {
		left := ctx.Buflen
		fill := BLAKE2B_BLOCKBYTES - left
		if inlen > fill {
			ctx.Buflen = 0
			copy(ctx.Buf[left:], in[:fill])
			Blake2bIncrementCounter(ctx, uint64(fill))
			Blake2bCompress(ctx, ctx.Buf)
			in = in[fill:]
			inlen -= fill
			for inlen > BLAKE2B_BLOCKBYTES {
				Blake2bIncrementCounter(ctx, uint64(BLAKE2B_BLOCKBYTES))
				var block [BLAKE2B_BLOCKBYTES]byte
				copy(block[:], in[:BLAKE2B_BLOCKBYTES])
				Blake2bCompress(ctx, block)
				in = in[BLAKE2B_BLOCKBYTES:]
				inlen -= BLAKE2B_BLOCKBYTES
			}
		}
		copy(ctx.Buf[ctx.Buflen:], in[:inlen])
		ctx.Buflen += inlen
	}
	return 0
}

func Blake2bFinal(ctx *Blake2bCtx, out []byte, outlen int) int {
	if outlen != ctx.Outlen {
		return -1
	}

	if ctx.Buflen > 0 {
		for i := ctx.Buflen; i < BLAKE2B_BLOCKBYTES; i++ {
			ctx.Buf[i] = 0
		}
		Blake2bIncrementCounter(ctx, uint64(ctx.Buflen))
		ctx.F[0] = ^uint64(0)
		Blake2bCompress(ctx, ctx.Buf)
	}

	for i := 0; i < outlen/8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], ctx.H[i])
	}
	if outlen%8 != 0 {
		// Partial last word
		last := ctx.H[outlen/8]
		for j := 0; j < outlen%8; j++ {
			out[ (outlen/8)*8 + j ] = byte(last >> (uint(j)*8))
		}
	}

	return 0
}

func Blake2bInit(ctx *Blake2bCtx, outlen int) int {
	if outlen == 0 || outlen > 64 {
		return -1
	}

	for i := 0; i < 8; i++ {
		ctx.H[i] = blake2bIV[i]
	}

	ctx.H[0] ^= 0x01010000 ^ uint64(outlen)

	ctx.T[0] = 0
	ctx.T[1] = 0
	ctx.F[0] = 0
	ctx.F[1] = 0
	ctx.Buflen = 0
	ctx.LastNode = 0
	ctx.Outlen = outlen

	return 0
}

const SHA3_ROUNDS = 24

var keccakRoundConstants [SHA3_ROUNDS]uint64 = [SHA3_ROUNDS]uint64{
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008,
}

func Rotl64(qword uint64, n uint) uint64 {
	return (qword << n) ^ (qword >> (64 - n))
}

func KeccakTheta(A [25]uint64) [25]uint64 {
	var C [5]uint64
	var D [5]uint64

	for x := 0; x < 5; x++ {
		C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20]
	}

	D[0] = Rotl64(C[1], 1) ^ C[4]
	D[1] = Rotl64(C[2], 1) ^ C[0]
	D[2] = Rotl64(C[3], 1) ^ C[1]
	D[3] = Rotl64(C[4], 1) ^ C[2]
	D[4] = Rotl64(C[0], 1) ^ C[3]

	for x := 0; x < 5; x++ {
		A[x] ^= D[x]
		A[x+5] ^= D[x]
		A[x+10] ^= D[x]
		A[x+15] ^= D[x]
		A[x+20] ^= D[x]
	}

	return A
}

func KeccakPi(A [25]uint64) [25]uint64 {
	a1 := A[1]
	A[1] = A[6]
	A[6] = A[9]
	A[9] = A[22]
	A[22] = A[14]
	A[14] = A[20]
	A[20] = A[2]
	A[2] = A[12]
	A[12] = A[13]
	A[13] = A[19]
	A[19] = A[23]
	A[23] = A[15]
	A[15] = A[4]
	A[4] = A[24]
	A[24] = A[21]
	A[21] = A[8]
	A[8] = A[16]
	A[16] = A[5]
	A[5] = A[3]
	A[3] = A[18]
	A[18] = A[17]
	A[17] = A[11]
	A[11] = A[7]
	A[7] = A[10]
	A[10] = a1
	return A
}

func KeccakChi(A [25]uint64) [25]uint64 {
	for i := 0; i < 25; i += 5 {
		a0 := A[0+i]
		a1 := A[1+i]
		A[0+i] ^= ^a1 & A[2+i]
		A[1+i] ^= ^A[2+i] & A[3+i]
		A[2+i] ^= ^A[3+i] & A[4+i]
		A[3+i] ^= ^A[4+i] & a0
		A[4+i] ^= ^a0 & a1
	}
	return A
}

func Sha3Permutation(state *[25]uint64) {
	for round := 0; round < SHA3_ROUNDS; round++ {
		*state = KeccakTheta(*state)

		state[1] = Rotl64(state[1], 1)
		state[2] = Rotl64(state[2], 62)
		state[3] = Rotl64(state[3], 28)
		state[4] = Rotl64(state[4], 27)
		state[5] = Rotl64(state[5], 36)
		state[6] = Rotl64(state[6], 44)
		state[7] = Rotl64(state[7], 6)
		state[8] = Rotl64(state[8], 55)
		state[9] = Rotl64(state[9], 20)
		state[10] = Rotl64(state[10], 3)
		state[11] = Rotl64(state[11], 10)
		state[12] = Rotl64(state[12], 43)
		state[13] = Rotl64(state[13], 25)
		state[14] = Rotl64(state[14], 39)
		state[15] = Rotl64(state[15], 41)
		state[16] = Rotl64(state[16], 45)
		state[17] = Rotl64(state[17], 15)
		state[18] = Rotl64(state[18], 21)
		state[19] = Rotl64(state[19], 8)
		state[20] = Rotl64(state[20], 18)
		state[21] = Rotl64(state[21], 2)
		state[22] = Rotl64(state[22], 61)
		state[23] = Rotl64(state[23], 56)
		state[24] = Rotl64(state[24], 14)

		*state = KeccakPi(*state)
		*state = KeccakChi(*state)

		state[0] ^= keccakRoundConstants[round]
	}
}

func Sha3ProcessBlock(hash [25]uint64, block []uint64, block_size int) [25]uint64 {
	num_words := block_size / 8

	hash[0] ^= block[0]
	hash[1] ^= block[1]
	hash[2] ^= block[2]
	hash[3] ^= block[3]
	hash[4] ^= block[4]
	hash[5] ^= block[5]
	hash[6] ^= block[6]
	hash[7] ^= block[7]
	hash[8] ^= block[8]

	if num_words > 9 {
		hash[9] ^= block[9]
		hash[10] ^= block[10]
		hash[11] ^= block[11]
		hash[12] ^= block[12]

		if num_words > 13 {
			hash[13] ^= block[13]
			hash[14] ^= block[14]
			hash[15] ^= block[15]
			hash[16] ^= block[16]

			if num_words > 17 {
				hash[17] ^= block[17]

				if num_words > 18 {
					hash[18] ^= block[18]
					hash[19] ^= block[19]
					hash[20] ^= block[20]
					hash[21] ^= block[21]
					hash[22] ^= block[22]
					hash[23] ^= block[23]
					hash[24] ^= block[24]
				}
			}
		}
	}

	Sha3Permutation(&hash)

	return hash
}

/*
func Sha3Update(ctx *Sha3Ctx, msg []byte, size int) {
	index := int(ctx.Rest)
	block_size := int(ctx.BlockSize)

	if ctx.Rest & 1 != 0 { // FINALIZED
		return
	}

	ctx.Rest = uint((index + size) % block_size)

	if index > 0 {
		left := block_size - index
// Fix the next line
//		copy(ctx.Message[index*8:], msg[:min(size, left)])

		if size < left {
			return
		}

		ctx.Hash = Sha3ProcessBlock(ctx.Hash, ctx.Message[:], block_size)
		msg = msg[left:]
		size -= left
	}

	for size >= block_size {
		var aligned_message_block []uint64

		// In Go, to check alignment, but for simplicity, copy to message
// TODO: Fix the next line
		copy(ctx.Message[:], msg[:block_size])

		aligned_message_block = ctx.Message[:]

		ctx.Hash = Sha3ProcessBlock(ctx.Hash, aligned_message_block, block_size)
		msg = msg[block_size:]
		size -= block_size
	}

	if size > 0 {
// TODO: Fix the next line
		copy(ctx.Message[:size], msg)
	}
}
*/

/*
func Sha3Update(ctx *Sha3Ctx, msg []byte, size int) {
	index := int(ctx.Rest)
	block_size := int(ctx.BlockSize)

	messageBytes := (*[SHA3_MAX_RATE_IN_QWORDS * 8]byte)(unsafe.Pointer(&ctx.Message[0]))[:]

	if ctx.Rest&1 != 0 { // FINALIZED
		return
	}

	ctx.Rest = uint((index + size) % block_size)

	if index > 0 {
		left := block_size - index
		copy(messageBytes[index:index+min(size, left)], msg[:min(size, left)])

		if size < left {
			return
		}

		ctx.Hash = Sha3ProcessBlock(ctx.Hash, ctx.Message[:block_size/8], block_size)
		msg = msg[left:]
		size -= left
	}

	for size >= block_size {
		copy(messageBytes[:block_size], msg[:block_size])
		ctx.Hash = Sha3ProcessBlock(ctx.Hash, ctx.Message[:block_size/8], block_size)
		msg = msg[block_size:]
		size -= block_size
	}

	if size > 0 {
		copy(messageBytes[:size], msg[:size])
	}
}
*/

/*
func Sha3Update(ctx *Sha3Ctx, msg []byte, size int) {
	index := int(ctx.Rest)
	block_size := int(ctx.BlockSize)

	messageBytes := (*[SHA3_MAX_RATE_IN_QWORDS * 8]byte)(unsafe.Pointer(&ctx.Message[0]))[:]

	if ctx.Rest & 1 != 0 { // FINALIZED
		return
	}

	ctx.Rest = uint((index + size) % block_size)

	if index > 0 {
		left := block_size - index
		copy(messageBytes[index:index+min(size, left)], msg[:min(size, left)])

		if size < left {
			return
		}

		ctx.Hash = Sha3ProcessBlock(ctx.Hash, messageBytes, block_size)
		msg = msg[left:]
		size -= left
	}

	for size >= block_size {
		copy(messageBytes[:block_size], msg[:block_size])
		ctx.Hash = Sha3ProcessBlock(ctx.Hash, messageBytes, block_size)
		msg = msg[block_size:]
		size -= block_size
	}

	if size > 0 {
		copy(messageBytes[:size], msg[:size])
	}
}
*/

func Sha3Update(ctx *Sha3Ctx, msg []byte, size int) {
	index := int(ctx.Rest)
	block_size := int(ctx.BlockSize)

	messageBytes := (*[SHA3_MAX_RATE_IN_QWORDS * 8]byte)(unsafe.Pointer(&ctx.Message[0]))[:]

	if ctx.Rest&1 != 0 { // FINALIZED
		return
	}

	ctx.Rest = uint((index + size) % block_size)

	if index > 0 {
		left := block_size - index
		copy(messageBytes[index:index+min(size, left)], msg[:min(size, left)])

		if size < left {
			return
		}

		var blockWords [SHA3_MAX_RATE_IN_QWORDS]uint64
		for i := 0; i < block_size/8; i++ {
			blockWords[i] = binary.LittleEndian.Uint64(messageBytes[i*8:(i+1)*8])
		}
		ctx.Hash = Sha3ProcessBlock(ctx.Hash, blockWords[:block_size/8], block_size)
		msg = msg[left:]
		size -= left
	}

	for size >= block_size {
		copy(messageBytes[:block_size], msg[:block_size])
		var blockWords [SHA3_MAX_RATE_IN_QWORDS]uint64
		for i := 0; i < block_size/8; i++ {
			blockWords[i] = binary.LittleEndian.Uint64(messageBytes[i*8:(i+1)*8])
		}
		ctx.Hash = Sha3ProcessBlock(ctx.Hash, blockWords[:block_size/8], block_size)
		msg = msg[block_size:]
		size -= block_size
	}

	if size > 0 {
		copy(messageBytes[:size], msg[:size])
	}
}

/*
func Sha3Final(ctx *Sha3Ctx, result []byte) {
	digest_length := 100 - ctx.BlockSize/2
	block_size := int(ctx.BlockSize)

	if ctx.Rest & 1 == 0 { // not FINALIZED
		for i := int(ctx.Rest); i < block_size; i++ {
			ctx.Message[i] = 0
		}
		ctx.Message[ctx.Rest] |= 0x06
		ctx.Message[block_size-1] |= 0x80

		ctx.Hash = Sha3ProcessBlock(ctx.Hash, ctx.Message[:], block_size)
		ctx.Rest = 1 // FINALIZED
	}

	var i uint
	for i = 0; i < digest_length/8; i++ {
		binary.LittleEndian.PutUint64(result[i*8:], ctx.Hash[i])
	}
	// if digest_length %8 !=0, partial, but in use, it's 32 or 64, even.
}
*/

func Sha3Final(ctx *Sha3Ctx, result []byte) {
	digest_length := 100 - int(ctx.BlockSize)/2
	block_size := int(ctx.BlockSize)

	messageBytes := (*[SHA3_MAX_RATE_IN_QWORDS * 8]byte)(unsafe.Pointer(&ctx.Message[0]))[:block_size]

	if ctx.Rest & 1 == 0 { // not FINALIZED
		for i := int(ctx.Rest); i < block_size; i++ {
			messageBytes[i] = 0
		}
		messageBytes[ctx.Rest] |= 0x06
		messageBytes[block_size-1] |= 0x80

		num_words := block_size / 8
		ctx.Hash = Sha3ProcessBlock(ctx.Hash, ctx.Message[:num_words], block_size)
		ctx.Rest = 1 // FINALIZED
	}

	for i := 0; i < digest_length/8; i++ {
		binary.LittleEndian.PutUint64(result[i*8:(i+1)*8], ctx.Hash[i])
	}
	// if digest_length %8 !=0, partial, but in use, it's 32 or 64, even.
}

const SHA3_FINALIZED = 1 // odd for finalized

func Sha3_256_Init(ctx *Sha3Ctx) {
	for i := 0; i < SHA3_MAX_PERMUTATION_SIZE; i++ {
		ctx.Hash[i] = 0
	}
	ctx.BlockSize = 136 // for SHA3-256
	ctx.Rest = 0
}

func HashBlake512(data []byte, size int, out [64]byte) {
	var ctx Blake2bCtx
	Blake2bInit(&ctx, 64)
	Blake2bUpdate(&ctx, data, size)
	Blake2bFinal(&ctx, out[:], 64)
}

func Sha3_256(data []byte, size int, out [32]byte) {
	var ctx Sha3Ctx
	Sha3_256_Init(&ctx)
	Sha3Update(&ctx, data, size)
	Sha3Final(&ctx, out[:])
}

func HeaderPreSize(hdr *Header) int {
	return 4 + 8 + 32 + 32 // nonce, time, prev, name_root
}

func HeaderPreEncode(hdr *Header, data []byte) int {
	dptr := &data
	s := 0
	s += WriteU32(&dptr, hdr.Nonce)
	s += WriteU64(&dptr, hdr.Time)
	s += WriteBytes(&dptr, hdr.PrevBlock[:], 32)
	s += WriteBytes(&dptr, hdr.NameRoot[:], 32)
	return s
}

func HeaderCache(hdr *Header) [32]byte {
	if hdr.Cache { return hdr.Hash }

	size := HeaderPreSize(hdr)
	pre := make([]byte, size)
	var pad8 [8]byte
	var pad32 [32]byte
	var left [64]byte
	var right [32]byte

	// Generate pads
	HeaderPadding(hdr, pad8[:], 8)
fmt.Printf("Header at place 001:\n");
dump_hex(unsafe.Pointer(hdr),int(unsafe.Sizeof(hdr)))
	HeaderPadding(hdr, pad32[:], 32)
fmt.Printf("Header at place 002:\n");
dump_hex(unsafe.Pointer(hdr),int(unsafe.Sizeof(hdr)))

	// Generate left
	HeaderPreEncode(hdr, pre)
fmt.Printf("Header at place 003:\n");
dump_hex(unsafe.Pointer(hdr),int(unsafe.Sizeof(hdr)))
	HashBlake512(pre, size, left)

	// Generate right
	var sCtx Sha3Ctx
	Sha3_256_Init(&sCtx)
	Sha3Update(&sCtx, pre, size)
	Sha3Update(&sCtx, pad8[:], 8)
	Sha3Final(&sCtx, right[:])

	// Generate hash
	var bCtx Blake2bCtx
	Blake2bInit(&bCtx, 32)
	Blake2bUpdate(&bCtx, left[:], 64)
	Blake2bUpdate(&bCtx, pad32[:], 32)
	Blake2bUpdate(&bCtx, right[:], 32)
	Blake2bFinal(&bCtx, hdr.Hash[:], 32)

	// XOR PoW hash with arbitrary bytes.
        // This can be used by mining pools to
        // mitigate block witholding attacks.

	for i := 0; i < 32; i++ { hdr.Hash[i] ^= hdr.Mask[i] }
fmt.Printf("Header at place 004:\n");
dump_hex(unsafe.Pointer(hdr),int(unsafe.Sizeof(hdr)))

	hdr.Cache = true

	return hdr.Hash
}

func min(a, b int) int {
	if a < b { return a }
	return b
}

// Helper: convert any value to []byte via unsafe pointer
func structToBytes(v any) []byte {
	return (*(*[1 << 30]byte)(unsafe.Pointer(&v)))[:unsafe.Sizeof(v)]
}

func hexDump(v any) {
	// Convert struct to []byte using unsafe (fast, zero-copy)
	data := structToBytes(v)
//	fmt.Printf("%s\n", hex.Dump(data))
	fmt.Printf("length of header: %d\n",len(data))
	for i := range(data) {
		fmt.Printf("%d ",data[i])
	}
	fmt.Printf("\n")
}

var hexdigs = [16]uint8 {
        '0',
        '1',
        '2',
        '3',
        '4',
        '5',
        '6',
        '7',
        '8',
        '9',
        'a',
        'b',
        'c',
        'd',
        'e',
        'f',
}

func fillTestHeader(hdr *Header) {
	var c uint8

	hdr.Nonce = 1234567
        hdr.Time = 1761496325

        for i := 0; i < 32; i++ {
                c = hexdigs[i%16]
                hdr.PrevBlock[i] = c
                hdr.NameRoot[i] = c
                if i < 24 { hdr.ExtraNonce[i] = c }
                hdr.ReservedRoot[i] = c
                hdr.WitnessRoot[i] = c
                hdr.MerkleRoot[i] = c
                hdr.Hash[i] = c
                hdr.Work[i] = c
        }
        hdr.Bits = 1234567
        hdr.Cache = false
        hdr.Height = 0
}

func makeTestHeader() *Header {
	var h = Header{}
	var hdr *Header
	hdr = &h
	fillTestHeader(hdr)
	return hdr
}

/* Functions for displaying values of various sizes in hex.
   For debugging. */

// Print 8-, 16-, 32-, and 64-bit unsigned integers.
func dump_8(x uint8)   { fmt.Printf("%2x", x); }
func dump_16(x uint16) { fmt.Printf("%3x", x); }
func dump_32(x uint32) { fmt.Printf("%5x", x); }
func dump_64(x uint64) { fmt.Printf("%9lx", x); }

// Display a buffer in hex, given a pointer to it.

// dump_hex() prints the hexadecimal representation of a buffer starting at the given pointer.
// The ptr argument can be any pointer type (e.g., *byte, *uint32, unsafe.Pointer, etc.),
// and it is treated as the address of the first byte of a buffer of length len.
func dump_hex(ptr unsafe.Pointer, len int) {
	bytes := (*[1 << 30]byte)(ptr)[:len] // Safely slice up to len bytes
	for i := 0; i < len; i++ {
		fmt.Printf("%02x", bytes[i])
	}
	fmt.Println()
}

/*
func dump_hex(any, len uint64)
{
	var bytes *uint8
        for i := 0; i < len; ++i { printf("%02x",bytes[i]) }
        fmt.Printf("\n")
}
*/

// Dummy main, since C has it, but hdr not initialized.
func main() {
	var testHeader *Header
	var size int

	// Print the size of the header struct.

	size = int(unsafe.Sizeof(*testHeader))
	fmt.Printf("Size of header: %d bytes\n",size)

	// Create the test data. A fake header.

	testHeader = makeTestHeader()
	testHeader.Cache = false

	// Print the bytes in the header has hex uint8.

//	fmt.Printf("Test Header:\n"); hexDump(testHeader)

	fmt.Printf("Header Contents:")
	p := unsafe.Slice((*uint8)(unsafe.Pointer(testHeader)), size)
	for i := 0; i < size; i++ {
		if i%16 == 0 { fmt.Printf("\n") }
		fmt.Printf("%2x ",p[i])
	}
	fmt.Printf("\n")
	

	// Calculate the header's hash

	testHash := HeaderCache(testHeader)

	// Print it.

	fmt.Printf("Header hash:\n")
	fmt.Printf("%x\n", testHash)
}
