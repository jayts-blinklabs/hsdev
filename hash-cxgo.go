package main

import (
	"github.com/gotranspile/cxgo/runtime/libc"
	"github.com/gotranspile/cxgo/runtime/stdio"
	"unsafe"
)

const hsk_sha3_max_permutation_size = 25
const hsk_sha3_max_rate_in_qwords = 24
const HSK_SHA3_ROUNDS = 24
const HSK_SHA3_FINALIZED = 0x80000000

type hsk_sha3_ctx struct {
	hash       [25]uint64
	message    [24]uint64
	rest       uint
	block_size uint
}
type hsk_header_s struct {
	nonce         uint32
	time          uint64
	prev_block    [32]uint8
	name_root     [32]uint8
	extra_nonce   [24]uint8
	reserved_root [32]uint8
	witness_root  [32]uint8
	merkle_root   [32]uint8
	version       uint32
	bits          uint32
	mask          [32]uint8
	cache         bool
	hash          [32]uint8
	height        uint32
	work          [32]uint8
	next          *hsk_header_s
}
type hsk_header_t hsk_header_s

func hsk_header_padding(hdr *hsk_header_t, pad *uint8, size uint64) {
	if hdr == nil || pad == nil {
		panic("assert failed")
	}
	var i uint64
	for i = 0; i < size; i++ {
		*(*uint8)(unsafe.Add(unsafe.Pointer(pad), i)) = uint8(int8(int(hdr.prev_block[i%32]) ^ int(hdr.name_root[i%32])))
	}
}
func write_bytes(data **uint8, bytes *uint8, size uint64) uint64 {
	if data == nil || *data == nil {
		return size
	}
	libc.MemCpy(unsafe.Pointer(*data), unsafe.Pointer(bytes), int(size))
	*data = (*uint8)(unsafe.Add(unsafe.Pointer(*data), size))
	return size
}
func write_u32(data **uint8, out uint32) uint64 {
	if data == nil || *data == nil {
		return 4
	}
	libc.MemCpy(unsafe.Pointer(*data), unsafe.Pointer(&out), 4)
	*data = (*uint8)(unsafe.Add(unsafe.Pointer(*data), 4))
	return 4
}
func write_u64(data **uint8, out uint64) uint64 {
	if data == nil || *data == nil {
		return 8
	}
	libc.MemCpy(unsafe.Pointer(*data), unsafe.Pointer(&out), 8)
	*data = (*uint8)(unsafe.Add(unsafe.Pointer(*data), 8))
	return 8
}
func hsk_header_sub_write(hdr *hsk_header_t, data **uint8) int {
	var s int = 0
	s += int(write_bytes(data, &hdr.extra_nonce[0], 24))
	s += int(write_bytes(data, &hdr.reserved_root[0], 32))
	s += int(write_bytes(data, &hdr.witness_root[0], 32))
	s += int(write_bytes(data, &hdr.merkle_root[0], 32))
	s += int(write_u32(data, hdr.version))
	s += int(write_u32(data, hdr.bits))
	return s
}
func hsk_header_sub_size(hdr *hsk_header_t) int {
	return hsk_header_sub_write(hdr, nil)
}
func hsk_header_sub_encode(hdr *hsk_header_t, data *uint8) int {
	return hsk_header_sub_write(hdr, &data)
}

type hsk_blake2b_constant int

const (
	HSK_BLAKE2B_BLOCKBYTES    hsk_blake2b_constant = 128
	HSK_BLAKE2B_OUTBYTES      hsk_blake2b_constant = 64
	HSK_BLAKE2B_KEYBYTES      hsk_blake2b_constant = 64
	HSK_BLAKE2B_SALTBYTES     hsk_blake2b_constant = 16
	HSK_BLAKE2B_PERSONALBYTES hsk_blake2b_constant = 16
)

type hsk_blake2b_ctx__ struct {
	h         [8]uint64
	t         [2]uint64
	f         [2]uint64
	buf       [128]uint8
	buflen    uint64
	outlen    uint64
	last_node uint8
}
type hsk_blake2b_ctx hsk_blake2b_ctx__

func hsk_blake2b_increment_counter(ctx *hsk_blake2b_ctx, inc uint64) {
	ctx.t[0] += inc
	ctx.t[1] += uint64(libc.BoolToInt(ctx.t[0] < inc))
}

var hsk_blake2b_sigma [12][16]uint8 = [12][16]uint8{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}, {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}, {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}, {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}, {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}}

func load64(src unsafe.Pointer) uint64 {
	var w uint64
	libc.MemCpy(unsafe.Pointer(&w), src, int(unsafe.Sizeof(uint64(0))))
	return w
}
func store32(dst unsafe.Pointer, w uint32) {
	libc.MemCpy(dst, unsafe.Pointer(&w), int(unsafe.Sizeof(uint32(0))))
}
func rotr64(w uint64, c uint) uint64 {
	return (w >> uint64(c)) | w<<uint64(64-c)
}

var hsk_blake2b_IV [8]uint64 = [8]uint64{0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179}

func hsk_blake2b_compress(ctx *hsk_blake2b_ctx, block [128]uint8) {
	var (
		m [16]uint64
		v [16]uint64
		i uint64
	)
	for i = 0; i < 16; i++ {
		m[i] = load64(unsafe.Pointer(&block[i*uint64(unsafe.Sizeof(uint64(0)))]))
	}
	for i = 0; i < 8; i++ {
		v[i] = ctx.h[i]
	}
	v[8] = hsk_blake2b_IV[0]
	v[9] = hsk_blake2b_IV[1]
	v[10] = hsk_blake2b_IV[2]
	v[11] = hsk_blake2b_IV[3]
	v[12] = hsk_blake2b_IV[4] ^ ctx.t[0]
	v[13] = hsk_blake2b_IV[5] ^ ctx.t[1]
	v[14] = hsk_blake2b_IV[6] ^ ctx.f[0]
	v[15] = hsk_blake2b_IV[7] ^ ctx.f[1]
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[0][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[0][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[0][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[0][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[0][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[0][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[0][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[0][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[0][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[0][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[0][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[0][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[0][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[0][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[0][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[0][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[1][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[1][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[1][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[1][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[1][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[1][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[1][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[1][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[1][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[1][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[1][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[1][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[1][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[1][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[1][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[1][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[2][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[2][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[2][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[2][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[2][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[2][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[2][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[2][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[2][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[2][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[2][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[2][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[2][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[2][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[2][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[2][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[3][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[3][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[3][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[3][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[3][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[3][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[3][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[3][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[3][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[3][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[3][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[3][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[3][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[3][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[3][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[3][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[4][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[4][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[4][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[4][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[4][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[4][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[4][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[4][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[4][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[4][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[4][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[4][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[4][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[4][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[4][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[4][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[5][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[5][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[5][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[5][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[5][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[5][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[5][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[5][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[5][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[5][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[5][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[5][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[5][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[5][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[5][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[5][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[6][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[6][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[6][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[6][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[6][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[6][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[6][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[6][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[6][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[6][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[6][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[6][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[6][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[6][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[6][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[6][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[7][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[7][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[7][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[7][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[7][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[7][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[7][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[7][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[7][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[7][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[7][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[7][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[7][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[7][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[7][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[7][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[8][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[8][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[8][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[8][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[8][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[8][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[8][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[8][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[8][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[8][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[8][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[8][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[8][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[8][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[8][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[8][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[9][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[9][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[9][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[9][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[9][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[9][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[9][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[9][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[9][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[9][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[9][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[9][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[9][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[9][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[9][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[9][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[10][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[10][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[10][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[10][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[10][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[10][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[10][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[10][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[10][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[10][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[10][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[10][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[10][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[10][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[10][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[10][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for {
		for {
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[11][2*0+0]]
			v[12] = rotr64(v[12]^v[0], 32)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 24)
			v[0] = v[0] + v[4] + m[hsk_blake2b_sigma[11][2*0+1]]
			v[12] = rotr64(v[12]^v[0], 16)
			v[8] = v[8] + v[12]
			v[4] = rotr64(v[4]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[11][2*1+0]]
			v[13] = rotr64(v[13]^v[1], 32)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 24)
			v[1] = v[1] + v[5] + m[hsk_blake2b_sigma[11][2*1+1]]
			v[13] = rotr64(v[13]^v[1], 16)
			v[9] = v[9] + v[13]
			v[5] = rotr64(v[5]^v[9], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[11][2*2+0]]
			v[14] = rotr64(v[14]^v[2], 32)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 24)
			v[2] = v[2] + v[6] + m[hsk_blake2b_sigma[11][2*2+1]]
			v[14] = rotr64(v[14]^v[2], 16)
			v[10] = v[10] + v[14]
			v[6] = rotr64(v[6]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[11][2*3+0]]
			v[15] = rotr64(v[15]^v[3], 32)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 24)
			v[3] = v[3] + v[7] + m[hsk_blake2b_sigma[11][2*3+1]]
			v[15] = rotr64(v[15]^v[3], 16)
			v[11] = v[11] + v[15]
			v[7] = rotr64(v[7]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[11][2*4+0]]
			v[15] = rotr64(v[15]^v[0], 32)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 24)
			v[0] = v[0] + v[5] + m[hsk_blake2b_sigma[11][2*4+1]]
			v[15] = rotr64(v[15]^v[0], 16)
			v[10] = v[10] + v[15]
			v[5] = rotr64(v[5]^v[10], 63)
			if true {
				break
			}
		}
		for {
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[11][2*5+0]]
			v[12] = rotr64(v[12]^v[1], 32)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 24)
			v[1] = v[1] + v[6] + m[hsk_blake2b_sigma[11][2*5+1]]
			v[12] = rotr64(v[12]^v[1], 16)
			v[11] = v[11] + v[12]
			v[6] = rotr64(v[6]^v[11], 63)
			if true {
				break
			}
		}
		for {
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[11][2*6+0]]
			v[13] = rotr64(v[13]^v[2], 32)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 24)
			v[2] = v[2] + v[7] + m[hsk_blake2b_sigma[11][2*6+1]]
			v[13] = rotr64(v[13]^v[2], 16)
			v[8] = v[8] + v[13]
			v[7] = rotr64(v[7]^v[8], 63)
			if true {
				break
			}
		}
		for {
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[11][2*7+0]]
			v[14] = rotr64(v[14]^v[3], 32)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 24)
			v[3] = v[3] + v[4] + m[hsk_blake2b_sigma[11][2*7+1]]
			v[14] = rotr64(v[14]^v[3], 16)
			v[9] = v[9] + v[14]
			v[4] = rotr64(v[4]^v[9], 63)
			if true {
				break
			}
		}
		if true {
			break
		}
	}
	for i = 0; i < 8; i++ {
		ctx.h[i] = ctx.h[i] ^ v[i] ^ v[i+8]
	}
}
func hsk_blake2b_update(ctx *hsk_blake2b_ctx, pin unsafe.Pointer, inlen uint64) int {
	var in *uint8 = (*uint8)(pin)
var in0 *uint8
var in1 [128]uint8
in0 = in
	if inlen > 0 {
		var (
			left uint64 = ctx.buflen
			fill uint64 = uint64(HSK_BLAKE2B_BLOCKBYTES - hsk_blake2b_constant(left))
		)
		if inlen > fill {
			ctx.buflen = 0
			libc.MemCpy(unsafe.Pointer(&ctx.buf[left]), unsafe.Pointer(in), int(fill))
			hsk_blake2b_increment_counter(ctx, uint64(HSK_BLAKE2B_BLOCKBYTES))
			hsk_blake2b_compress(ctx, ctx.buf)
			in = (*uint8)(unsafe.Add(unsafe.Pointer(in), fill))
			inlen -= fill
			for inlen > uint64(HSK_BLAKE2B_BLOCKBYTES) {
				hsk_blake2b_increment_counter(ctx, uint64(HSK_BLAKE2B_BLOCKBYTES))

// Next line does not compile due to mismatch between *uint8 and [128]uint8
//				hsk_blake2b_compress(ctx, [128]uint8(in))
// replacement:
for i := 1; i < 128; i++ {
	in1[i] = *in0
	in0 = (*uint8)(unsafe.Add(unsafe.Pointer(in0),1))
}
hsk_blake2b_compress(ctx, in1)
				in = (*uint8)(unsafe.Add(unsafe.Pointer(in), HSK_BLAKE2B_BLOCKBYTES))
				inlen -= uint64(HSK_BLAKE2B_BLOCKBYTES)
			}
		}
		libc.MemCpy(unsafe.Pointer(&ctx.buf[ctx.buflen]), unsafe.Pointer(in), int(inlen))
		ctx.buflen += inlen
	}
	return 0
}

type hsk_blake2b_param__ struct {
	digest_length uint8
	key_length    uint8
	fanout        uint8
	depth         uint8
	leaf_length   uint32
	node_offset   uint32
	xof_length    uint32
	node_depth    uint8
	inner_length  uint8
	reserved      [14]uint8
	salt          [16]uint8
	personal      [16]uint8
}
type hsk_blake2b_param hsk_blake2b_param__

func hsk_blake2b_init0(ctx *hsk_blake2b_ctx) {
	var i uint64
	*ctx = hsk_blake2b_ctx{}
	for i = 0; i < 8; i++ {
		ctx.h[i] = hsk_blake2b_IV[i]
	}
}
func hsk_blake2b_init_param(ctx *hsk_blake2b_ctx, P *hsk_blake2b_param) int {
	var (
		p *uint8 = &P.digest_length
		i uint64
	)
	hsk_blake2b_init0(ctx)
	for i = 0; i < 8; i++ {
		ctx.h[i] ^= load64(unsafe.Add(unsafe.Pointer(p), i*uint64(unsafe.Sizeof(uint64(0)))))
	}
	ctx.outlen = uint64(P.digest_length)
	return 0
}
func hsk_blake2b_init(ctx *hsk_blake2b_ctx, outlen uint64) int {
	var P [1]hsk_blake2b_param
	if outlen == 0 || outlen > uint64(HSK_BLAKE2B_OUTBYTES) {
		return -1
	}
	P[0].digest_length = uint8(outlen)
	P[0].key_length = 0
	P[0].fanout = 1
	P[0].depth = 1
	store32(unsafe.Pointer(&P[0].leaf_length), 0)
	store32(unsafe.Pointer(&P[0].node_offset), 0)
	store32(unsafe.Pointer(&P[0].xof_length), 0)
	P[0].node_depth = 0
	P[0].inner_length = 0
	*(*[14]uint8)(unsafe.Pointer(&P[0].reserved[0])) = [14]uint8{}
	*(*[16]uint8)(unsafe.Pointer(&P[0].salt[0])) = [16]uint8{}
	*(*[16]uint8)(unsafe.Pointer(&P[0].personal[0])) = [16]uint8{}
	return hsk_blake2b_init_param(ctx, &P[0])
}
func hsk_blake2b_is_lastblock(ctx *hsk_blake2b_ctx) int {
	return int(libc.BoolToInt(ctx.f[0] != 0))
}
func secure_zero_memory(v unsafe.Pointer, n uint64) {
	var memset_v func(unsafe.Pointer, int, uint64) unsafe.Pointer = func(arg1 unsafe.Pointer, arg2 int, arg3 uint64) unsafe.Pointer {
		return libc.MemSet(arg1, byte(int8(arg2)), int(arg3))
	}
	memset_v(v, 0, n)
}
func hsk_blake2b_set_lastnode(ctx *hsk_blake2b_ctx) {
	ctx.f[1] = 18446744073709551615
}
func hsk_blake2b_set_lastblock(ctx *hsk_blake2b_ctx) {
	if int(ctx.last_node) != 0 {
		hsk_blake2b_set_lastnode(ctx)
	}
	ctx.f[0] = 18446744073709551615
}
func store64(dst unsafe.Pointer, w uint64) {
	libc.MemCpy(dst, unsafe.Pointer(&w), int(unsafe.Sizeof(uint64(0))))
}
func hsk_blake2b_final(ctx *hsk_blake2b_ctx, out unsafe.Pointer, outlen uint64) int {
	var (
		buffer [64]uint8 = [64]uint8{}
		i      uint64
	)
	if out == nil || outlen < ctx.outlen {
		return -1
	}
	if hsk_blake2b_is_lastblock(ctx) != 0 {
		return -1
	}
	hsk_blake2b_increment_counter(ctx, ctx.buflen)
	hsk_blake2b_set_lastblock(ctx)
	libc.MemSet(unsafe.Pointer(&ctx.buf[ctx.buflen]), 0, int(HSK_BLAKE2B_BLOCKBYTES-hsk_blake2b_constant(ctx.buflen)))
	hsk_blake2b_compress(ctx, ctx.buf)
	for i = 0; i < 8; i++ {
		store64(unsafe.Pointer(&buffer[i*uint64(unsafe.Sizeof(uint64(0)))]), ctx.h[i])
	}
	libc.MemCpy(out, unsafe.Pointer(&buffer[0]), int(ctx.outlen))
	secure_zero_memory(unsafe.Pointer(&buffer[0]), uint64(64))
	return 0
}
func hsk_hash_blake256(data *uint8, data_len uint64, hash *uint8) {
	if hash == nil {
		panic("assert failed")
	}
	var ctx hsk_blake2b_ctx
	if hsk_blake2b_init(&ctx, 32) != 0 {
		panic("assert failed")
	}
	hsk_blake2b_update(&ctx, unsafe.Pointer(data), data_len)
	if hsk_blake2b_final(&ctx, unsafe.Pointer(hash), 32) != 0 {
		panic("assert failed")
	}
}
func hsk_header_sub_hash(hdr *hsk_header_t, hash *uint8) {
	var (
		size int = hsk_header_sub_size(hdr)
		sub  []uint8
	)
	hsk_header_sub_encode(hdr, &sub[0])
	hsk_hash_blake256(&sub[0], uint64(size), hash)
}
func hsk_header_mask_hash(hdr *hsk_header_t, hash *uint8) {
	var ctx hsk_blake2b_ctx
	if hsk_blake2b_init(&ctx, 32) != 0 {
		panic("assert failed")
	}
	hsk_blake2b_update(&ctx, unsafe.Pointer(&hdr.prev_block[0]), 32)
	hsk_blake2b_update(&ctx, unsafe.Pointer(&hdr.mask[0]), 32)
	if hsk_blake2b_final(&ctx, unsafe.Pointer(hash), 32) != 0 {
		panic("assert failed")
	}
}
func hsk_header_commit_hash(hdr *hsk_header_t, hash *uint8) {
	var (
		sub_hash  [32]uint8
		mask_hash [32]uint8
	)
	hsk_header_sub_hash(hdr, &sub_hash[0])
	hsk_header_mask_hash(hdr, &mask_hash[0])
	var ctx hsk_blake2b_ctx
	if hsk_blake2b_init(&ctx, 32) != 0 {
		panic("assert failed")
	}
	hsk_blake2b_update(&ctx, unsafe.Pointer(&sub_hash[0]), 32)
	hsk_blake2b_update(&ctx, unsafe.Pointer(&mask_hash[0]), 32)
	if hsk_blake2b_final(&ctx, unsafe.Pointer(hash), 32) != 0 {
		panic("assert failed")
	}
}
func hsk_header_pre_write(hdr *hsk_header_t, data **uint8) int {
	var (
		s           int = 0
		pad         [20]uint8
		commit_hash [32]uint8
	)
	hsk_header_padding(hdr, &pad[0], 20)
	hsk_header_commit_hash(hdr, &commit_hash[0])
	s += int(write_u32(data, hdr.nonce))
	s += int(write_u64(data, hdr.time))
	s += int(write_bytes(data, &pad[0], 20))
	s += int(write_bytes(data, &hdr.prev_block[0], 32))
	s += int(write_bytes(data, &hdr.name_root[0], 32))
	s += int(write_bytes(data, &commit_hash[0], 32))
	return s
}
func hsk_header_pre_size(hdr *hsk_header_t) int {
	return hsk_header_pre_write(hdr, nil)
}
func hsk_header_pre_encode(hdr *hsk_header_t, data *uint8) int {
	return hsk_header_pre_write(hdr, &data)
}
func hsk_hash_blake512(data *uint8, data_len uint64, hash *uint8) {
	if hash == nil {
		panic("assert failed")
	}
	var ctx hsk_blake2b_ctx
	if hsk_blake2b_init(&ctx, 64) != 0 {
		panic("assert failed")
	}
	hsk_blake2b_update(&ctx, unsafe.Pointer(data), data_len)
	if hsk_blake2b_final(&ctx, unsafe.Pointer(hash), 64) != 0 {
		panic("assert failed")
	}
}
func hsk_keccak_init(ctx *hsk_sha3_ctx, bits uint) {
	var rate uint = 1600 - bits*2
	*ctx = hsk_sha3_ctx{}
	ctx.block_size = rate / 8
	if rate > 1600 || (rate%64) != 0 {
		panic("assert failed")
	}
}
func hsk_sha3_256_init(ctx *hsk_sha3_ctx) {
	hsk_keccak_init(ctx, 256)
}

var hsk_keccak_round_constants [24]uint64 = [24]uint64{0x1, 0x8082, 0x800000000000808A, 0x8000000080008000, 0x808B, 0x80000001, 0x8000000080008081, 0x8000000000008009, 0x8A, 0x88, 0x80008009, 0x8000000A, 0x8000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008}

func hsk_keccak_theta(A *uint64) {
	var (
		x uint
		C [5]uint64
		D [5]uint64
	)
	for x = 0; x < 5; x++ {
		C[x] = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(x))) ^ *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(x+5))) ^ *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(x+10))) ^ *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(x+15))) ^ *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(x+20)))
	}
	D[0] = ((C[1])<<1 ^ (C[1])>>(64-1)) ^ C[4]
	D[1] = ((C[2])<<1 ^ (C[2])>>(64-1)) ^ C[0]
	D[2] = ((C[3])<<1 ^ (C[3])>>(64-1)) ^ C[1]
	D[3] = ((C[4])<<1 ^ (C[4])>>(64-1)) ^ C[2]
	D[4] = ((C[0])<<1 ^ (C[0])>>(64-1)) ^ C[3]
	for x = 0; x < 5; x++ {
		*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(x))) ^= D[x]
		*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(x+5))) ^= D[x]
		*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(x+10))) ^= D[x]
		*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(x+15))) ^= D[x]
		*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(x+20))) ^= D[x]
	}
}
func hsk_keccak_pi(A *uint64) {
	var A1 uint64
	A1 = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*1))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*1)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*6))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*6)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*9))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*9)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*22))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*22)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*14))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*14)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*20))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*20)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*2))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*2)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*12))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*12)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*13))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*13)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*19))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*19)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*23))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*23)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*15))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*15)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*4))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*4)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*24))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*24)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*21))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*21)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*8))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*8)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*16))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*16)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*5))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*5)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*3))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*3)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*18))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*18)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*17))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*17)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*11))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*11)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*7))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*7)) = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*10))
	*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*10)) = A1
}
func hsk_keccak_chi(A *uint64) {
	var i int
	for i = 0; i < 25; i += 5 {
		var (
			A0 uint64 = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+0)))
			A1 uint64 = *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+1)))
		)
		*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+0))) ^= ^A1 & *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+2)))
		*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+1))) ^= ^*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+2))) & *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+3)))
		*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+2))) ^= ^*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+3))) & *(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+4)))
		*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+3))) ^= ^*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+4))) & A0
		*(*uint64)(unsafe.Add(unsafe.Pointer(A), unsafe.Sizeof(uint64(0))*uintptr(i+4))) ^= ^A0 & A1
	}
}
func hsk_sha3_permutation(state *uint64) {
	var round int
	for round = 0; round < HSK_SHA3_ROUNDS; round++ {
		hsk_keccak_theta(state)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*1)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*1)))<<1 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*1)))>>(64-1)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*2)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*2)))<<62 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*2)))>>(64-62)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*3)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*3)))<<28 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*3)))>>(64-28)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*4)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*4)))<<27 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*4)))>>(64-27)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*5)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*5)))<<36 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*5)))>>(64-36)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*6)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*6)))<<44 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*6)))>>(64-44)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*7)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*7)))<<6 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*7)))>>(64-6)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*8)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*8)))<<55 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*8)))>>(64-55)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*9)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*9)))<<20 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*9)))>>(64-20)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*10)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*10)))<<3 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*10)))>>(64-3)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*11)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*11)))<<10 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*11)))>>(64-10)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*12)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*12)))<<43 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*12)))>>(64-43)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*13)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*13)))<<25 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*13)))>>(64-25)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*14)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*14)))<<39 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*14)))>>(64-39)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*15)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*15)))<<41 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*15)))>>(64-41)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*16)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*16)))<<45 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*16)))>>(64-45)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*17)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*17)))<<15 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*17)))>>(64-15)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*18)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*18)))<<21 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*18)))>>(64-21)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*19)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*19)))<<8 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*19)))>>(64-8)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*20)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*20)))<<18 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*20)))>>(64-18)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*21)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*21)))<<2 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*21)))>>(64-2)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*22)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*22)))<<61 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*22)))>>(64-61)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*23)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*23)))<<56 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*23)))>>(64-56)
		*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*24)) = (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*24)))<<14 ^ (*(*uint64)(unsafe.Add(unsafe.Pointer(state), unsafe.Sizeof(uint64(0))*24)))>>(64-14)
		hsk_keccak_pi(state)
		hsk_keccak_chi(state)
		*state ^= hsk_keccak_round_constants[round]
	}
}
func hsk_sha3_process_block(hash [25]uint64, block *uint64, block_size uint64) {
	hash[0] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*0))
	hash[1] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*1))
	hash[2] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*2))
	hash[3] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*3))
	hash[4] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*4))
	hash[5] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*5))
	hash[6] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*6))
	hash[7] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*7))
	hash[8] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*8))
	if block_size > 72 {
		hash[9] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*9))
		hash[10] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*10))
		hash[11] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*11))
		hash[12] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*12))
		if block_size > 104 {
			hash[13] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*13))
			hash[14] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*14))
			hash[15] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*15))
			hash[16] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*16))
			if block_size > 136 {
				hash[17] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*17))
				if block_size > 144 {
					hash[18] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*18))
					hash[19] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*19))
					hash[20] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*20))
					hash[21] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*21))
					hash[22] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*22))
					hash[23] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*23))
					hash[24] ^= *(*uint64)(unsafe.Add(unsafe.Pointer(block), unsafe.Sizeof(uint64(0))*24))
				}
			}
		}
	}
	hsk_sha3_permutation(&hash[0])
}
func hsk_sha3_update(ctx *hsk_sha3_ctx, msg *uint8, size uint64) {
	var (
		index      uint64 = uint64(ctx.rest)
		block_size uint64 = uint64(ctx.block_size)
	)
	if ctx.rest&HSK_SHA3_FINALIZED != 0 {
		return
	}
	ctx.rest = (ctx.rest + uint(size)) % uint(block_size)
	if index != 0 {
		var left uint64 = block_size - index
		libc.MemCpy(unsafe.Add(unsafe.Pointer((*byte)(unsafe.Pointer(&ctx.message[0]))), index), unsafe.Pointer(msg), int(func() uint64 {
			if size < left {
				return size
			}
			return left
		}()))
		if size < left {
			return
		}
		hsk_sha3_process_block(ctx.hash, &ctx.message[0], block_size)
		msg = (*uint8)(unsafe.Add(unsafe.Pointer(msg), left))
		size -= left
	}
	for size >= block_size {
		var aligned_message_block *uint64
//		if ((int64(uintptr(unsafe.Pointer((*byte)(unsafe.Pointer(msg)))) - uintptr(nil))) & 7) == 0 {
		if ((int64(uintptr(unsafe.Pointer((*byte)(unsafe.Pointer(msg)))) - uintptr(0))) & 7) == 0 {
			aligned_message_block = (*uint64)(unsafe.Pointer(msg))
		} else {
			libc.MemCpy(unsafe.Pointer(&ctx.message[0]), unsafe.Pointer(msg), int(block_size))
			aligned_message_block = &ctx.message[0]
		}
		hsk_sha3_process_block(ctx.hash, aligned_message_block, block_size)
		msg = (*uint8)(unsafe.Add(unsafe.Pointer(msg), block_size))
		size -= block_size
	}
	if size != 0 {
		libc.MemCpy(unsafe.Pointer(&ctx.message[0]), unsafe.Pointer(msg), int(size))
	}
}
func hsk_sha3_final(ctx *hsk_sha3_ctx, result *uint8) {
	var (
		digest_length uint64 = uint64(100 - ctx.block_size/2)
		block_size    uint64 = uint64(ctx.block_size)
	)
	if (ctx.rest & HSK_SHA3_FINALIZED) == 0 {
		libc.MemSet(unsafe.Add(unsafe.Pointer((*byte)(unsafe.Pointer(&ctx.message[0]))), ctx.rest), 0, int(block_size-uint64(ctx.rest)))
		*(*byte)(unsafe.Add(unsafe.Pointer((*byte)(unsafe.Pointer(&ctx.message[0]))), ctx.rest)) |= 0x6
		*(*byte)(unsafe.Add(unsafe.Pointer((*byte)(unsafe.Pointer(&ctx.message[0]))), block_size-1)) |= 0x80
		hsk_sha3_process_block(ctx.hash, &ctx.message[0], block_size)
		ctx.rest = HSK_SHA3_FINALIZED
	}
	if block_size <= digest_length {
		panic("assert failed")
	}
	if result != nil {
		libc.MemCpy(unsafe.Pointer(result), unsafe.Pointer(&ctx.hash[0]), int(digest_length))
	}
}
func hsk_header_cache(hdr *hsk_header_t) *uint8 {
	if hdr.cache {
		stdio.Printf("already in cache\n")
	}
	if hdr.cache {
		return &hdr.hash[0]
	}
	var size int = hsk_header_pre_size(hdr)
	var pre []uint8
	var pad8 [8]uint8
	var pad32 [32]uint8
	var left [64]uint8
	var right [32]uint8
	hsk_header_padding(hdr, &pad8[0], 8)
	hsk_header_padding(hdr, &pad32[0], 32)
	hsk_header_pre_encode(hdr, &pre[0])
	hsk_hash_blake512(&pre[0], uint64(size), &left[0])
	var s_ctx hsk_sha3_ctx
	hsk_sha3_256_init(&s_ctx)
	hsk_sha3_update(&s_ctx, &pre[0], uint64(size))
	hsk_sha3_update(&s_ctx, &pad8[0], 8)
	hsk_sha3_final(&s_ctx, &right[0])
	var b_ctx hsk_blake2b_ctx
	if hsk_blake2b_init(&b_ctx, 32) != 0 {
		panic("assert failed")
	}
	hsk_blake2b_update(&b_ctx, unsafe.Pointer(&left[0]), 64)
	hsk_blake2b_update(&b_ctx, unsafe.Pointer(&pad32[0]), 32)
	hsk_blake2b_update(&b_ctx, unsafe.Pointer(&right[0]), 32)
	if hsk_blake2b_final(&b_ctx, unsafe.Pointer(&hdr.hash[0]), 32) != 0 {
		panic("assert failed")
	}
	for i := int(0); i < 32; i++ {
		hdr.hash[i] ^= hdr.mask[i]
	}
	hdr.cache = true
	return &hdr.hash[0]
}

var hexdigs [16]byte = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

func fill_test_header(hdr *hsk_header_t) {
	var (
		i int
		c int
	)
	hdr.nonce = 1234567
	hdr.time = 1761496325
	for i = 0; i < 32; i++ {
		c = int(hexdigs[i%16])
		hdr.prev_block[i] = uint8(int8(c))
		hdr.name_root[i] = uint8(int8(c))
		if i < 24 {
			hdr.extra_nonce[i] = uint8(int8(c))
		}
		hdr.reserved_root[i] = uint8(int8(c))
		hdr.witness_root[i] = uint8(int8(c))
		hdr.merkle_root[i] = uint8(int8(c))
		hdr.hash[i] = uint8(int8(c))
		hdr.work[i] = uint8(int8(c))
	}
	hdr.bits = 1234567
	hdr.cache = false
	hdr.height = 0
}
func make_test_header() *hsk_header_t {
	var hdr *hsk_header_t
	hdr = new(hsk_header_t)
	fill_test_header(hdr)
	return hdr
}
func main() {
	var (
		hdr   *hsk_header_t
		cache *uint8
		size  int
		p     *uint8
	)
	size = int(unsafe.Sizeof(hsk_header_t{}))
	stdio.Printf("Size of header: %d bytes\n", size)
	hdr = make_test_header()
	hdr.cache = false
	stdio.Printf("Header Contents:")
	p = (*uint8)(unsafe.Pointer(hdr))
	for i := int(0); i < size; i++ {
		if i%16 == 0 {
			stdio.Printf("\n")
		}
		stdio.Printf("%2x ", *(*uint8)(unsafe.Add(unsafe.Pointer(p), i)))
	}
	stdio.Printf("\n")
	cache = hsk_header_cache(hdr)
	stdio.Printf("Header hash:\n")
	for i := int(0); i < 32; i++ {
		stdio.Printf("%x", *(*uint8)(unsafe.Add(unsafe.Pointer(cache), i)))
	}
	stdio.Printf("\n")
}
