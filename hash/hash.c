#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define hsk_sha3_max_permutation_size 25
#define hsk_sha3_max_rate_in_qwords 24

typedef struct hsk_sha3_ctx
{
  uint64_t hash[hsk_sha3_max_permutation_size];
  uint64_t message[hsk_sha3_max_rate_in_qwords];
  unsigned rest;
  unsigned block_size;
} hsk_sha3_ctx;

typedef struct hsk_header_s
{
	// Preheader.
	uint32_t nonce;
	uint64_t time;
	uint8_t prev_block[32];
	uint8_t name_root[32];

	// Subheader.
	uint8_t extra_nonce[24];
	uint8_t reserved_root[32];
	uint8_t witness_root[32];
	uint8_t merkle_root[32];
	uint32_t version;
	uint32_t bits;

	// Mask.
	uint8_t mask[32];

	bool cache;
	uint8_t hash[32];
	uint32_t height;
	uint8_t work[32];

	struct hsk_header_s *next;
} hsk_header_t;

void hsk_header_padding(const hsk_header_t *hdr, uint8_t *pad, size_t size)
{
	assert(hdr && pad);

	size_t i;

	for (i = 0; i < size; i++) pad[i] = hdr->prev_block[i % 32] ^ hdr->name_root[i % 32];
}

static inline size_t write_bytes(uint8_t **data, const uint8_t *bytes, size_t size)
{
	if (data == NULL || *data == NULL) return size;
	memcpy(*data, bytes, size);
	*data += size;
	return size;
}

static inline size_t write_u32(uint8_t **data, uint32_t out)
{
  if (data == NULL || *data == NULL) return 4;
#ifndef HSK_BIG_ENDIAN
  memcpy(*data, &out, 4);
#else
  (*data)[0] = (uint8_t)out;
  (*data)[1] = (uint8_t)(out >> 8);
  (*data)[2] = (uint8_t)(out >> 16);
  (*data)[3] = (uint8_t)(out >> 24);
#endif
  *data += 4;
  return 4;
}

static inline size_t write_u64(uint8_t **data, uint64_t out)
{
  if (data == NULL || *data == NULL) return 8;
#ifndef HSK_BIG_ENDIAN
  memcpy(*data, &out, 8);
#else
  (*data)[0] = (uint8_t)out;
  (*data)[1] = (uint8_t)(out >> 8);
  (*data)[2] = (uint8_t)(out >> 16);
  (*data)[3] = (uint8_t)(out >> 24);
  (*data)[4] = (uint8_t)(out >> 32);
  (*data)[5] = (uint8_t)(out >> 40);
  (*data)[6] = (uint8_t)(out >> 48);
  (*data)[7] = (uint8_t)(out >> 56);
#endif
  *data += 8;
  return 8;
}

int hsk_header_sub_write(const hsk_header_t *hdr, uint8_t **data)
{
  int s = 0;
  s += write_bytes(data, hdr->extra_nonce, 24);
  s += write_bytes(data, hdr->reserved_root, 32);
  s += write_bytes(data, hdr->witness_root, 32);
  s += write_bytes(data, hdr->merkle_root, 32);
  s += write_u32(data, hdr->version);
  s += write_u32(data, hdr->bits);
  return s;
}

int hsk_header_sub_size(const hsk_header_t *hdr)
{
  return hsk_header_sub_write(hdr, NULL);
}

int hsk_header_sub_encode(const hsk_header_t *hdr, uint8_t *data)
{
  return hsk_header_sub_write(hdr, &data);
}

enum hsk_blake2b_constant
{
  HSK_BLAKE2B_BLOCKBYTES = 128,
  HSK_BLAKE2B_OUTBYTES = 64,
  HSK_BLAKE2B_KEYBYTES = 64,
  HSK_BLAKE2B_SALTBYTES = 16,
  HSK_BLAKE2B_PERSONALBYTES = 16
};

typedef struct hsk_blake2b_ctx__
{
	uint64_t h[8];
	uint64_t t[2];
	uint64_t f[2];
	uint8_t buf[HSK_BLAKE2B_BLOCKBYTES];
	size_t buflen;
	size_t outlen;
	uint8_t last_node;
} hsk_blake2b_ctx;

static void hsk_blake2b_increment_counter(hsk_blake2b_ctx *ctx, const uint64_t inc)
{
  ctx->t[0] += inc;
  ctx->t[1] += (ctx->t[0] < inc);
}

static const uint8_t hsk_blake2b_sigma[12][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

#if !defined(__cplusplus) \
  && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
  #if defined(_MSC_VER)
    #define HSK_BLAKE2_INLINE __inline
  #elif defined(__GNUC__)
    #define HSK_BLAKE2_INLINE __inline__
  #else
    #define HSK_BLAKE2_INLINE
  #endif
#else
  #define HSK_BLAKE2_INLINE inline
#endif

static HSK_BLAKE2_INLINE
uint64_t load64(const void *src) {
#ifndef HSK_BIG_ENDIAN
  uint64_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint64_t)(p[0]) <<  0) |
         ((uint64_t)(p[1]) <<  8) |
         ((uint64_t)(p[2]) << 16) |
         ((uint64_t)(p[3]) << 24) |
         ((uint64_t)(p[4]) << 32) |
         ((uint64_t)(p[5]) << 40) |
         ((uint64_t)(p[6]) << 48) |
         ((uint64_t)(p[7]) << 56);
#endif
}

static HSK_BLAKE2_INLINE
void store32(void *dst, uint32_t w) {
#ifndef HSK_BIG_ENDIAN
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
#endif
}

static HSK_BLAKE2_INLINE uint64_t rotr64(const uint64_t w, const unsigned c)
{
  return (w >> c) | (w << (64 - c));
}

#define G(r, i, a, b, c, d)                     \
  do {                                          \
    a = a + b + m[hsk_blake2b_sigma[r][2*i+0]]; \
    d = rotr64(d ^ a, 32);                      \
    c = c + d;                                  \
    b = rotr64(b ^ c, 24);                      \
    a = a + b + m[hsk_blake2b_sigma[r][2*i+1]]; \
    d = rotr64(d ^ a, 16);                      \
    c = c + d;                                  \
    b = rotr64(b ^ c, 63);                      \
  } while (0)

#define ROUND(r)                       \
  do {                                 \
    G(r, 0, v[0], v[4], v[8], v[12]);  \
    G(r, 1, v[1], v[5], v[9], v[13]);  \
    G(r, 2, v[2], v[6], v[10], v[14]); \
    G(r, 3, v[3], v[7], v[11], v[15]); \
    G(r, 4, v[0], v[5], v[10], v[15]); \
    G(r, 5, v[1], v[6], v[11], v[12]); \
    G(r, 6, v[2], v[7], v[8], v[13]);  \
    G(r, 7, v[3], v[4], v[9], v[14]);  \
  } while (0)

static const uint64_t hsk_blake2b_IV[8] =
{
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static void hsk_blake2b_compress(hsk_blake2b_ctx *ctx, const uint8_t block[HSK_BLAKE2B_BLOCKBYTES])
{
	uint64_t m[16];
	uint64_t v[16];
	size_t i;

	for (i = 0; i < 16; i++) m[i] = load64(block + i * sizeof(m[i]));

	for (i = 0; i < 8; i++) v[i] = ctx->h[i];

	v[8] = hsk_blake2b_IV[0];
	v[9] = hsk_blake2b_IV[1];
	v[10] = hsk_blake2b_IV[2];
	v[11] = hsk_blake2b_IV[3];
	v[12] = hsk_blake2b_IV[4] ^ ctx->t[0];
	v[13] = hsk_blake2b_IV[5] ^ ctx->t[1];
	v[14] = hsk_blake2b_IV[6] ^ ctx->f[0];
	v[15] = hsk_blake2b_IV[7] ^ ctx->f[1];

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (i = 0; i < 8; i++) ctx->h[i] = ctx->h[i] ^ v[i] ^ v[i + 8];
}

#undef G
#undef ROUND

int hsk_blake2b_update(hsk_blake2b_ctx *ctx, const void *pin, size_t inlen)
{
	const unsigned char *in = (const unsigned char *)pin;

	if (inlen > 0)
	{
		size_t left = ctx->buflen;
		size_t fill = HSK_BLAKE2B_BLOCKBYTES - left;

		if (inlen > fill)
		{
			ctx->buflen = 0;
			memcpy(ctx->buf + left, in, fill);

			hsk_blake2b_increment_counter(ctx, HSK_BLAKE2B_BLOCKBYTES);
			hsk_blake2b_compress(ctx, ctx->buf);

			in += fill;
			inlen -= fill;

			while (inlen > HSK_BLAKE2B_BLOCKBYTES)
			{
				hsk_blake2b_increment_counter(ctx, HSK_BLAKE2B_BLOCKBYTES);
				hsk_blake2b_compress(ctx, in);
				in += HSK_BLAKE2B_BLOCKBYTES;
				inlen -= HSK_BLAKE2B_BLOCKBYTES;
			}
		}

		memcpy(ctx->buf + ctx->buflen, in, inlen);
		ctx->buflen += inlen;
	}

	return 0;
}

#if defined(_MSC_VER)
#define HSK_BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define HSK_BLAKE2_PACKED(x) x __attribute__((packed))
#endif

HSK_BLAKE2_PACKED(struct hsk_blake2b_param__
{
  uint8_t digest_length;
  uint8_t key_length;
  uint8_t fanout;
  uint8_t depth;
  uint32_t leaf_length;
  uint32_t node_offset;
  uint32_t xof_length;
  uint8_t node_depth;
  uint8_t inner_length;
  uint8_t reserved[14];
  uint8_t salt[HSK_BLAKE2B_SALTBYTES];
  uint8_t personal[HSK_BLAKE2B_PERSONALBYTES];
});

typedef struct hsk_blake2b_param__ hsk_blake2b_param;

static void hsk_blake2b_init0(hsk_blake2b_ctx *ctx)
{
  size_t i;

  memset(ctx, 0, sizeof(hsk_blake2b_ctx));

  for (i = 0; i < 8; i++) ctx->h[i] = hsk_blake2b_IV[i];
}

int hsk_blake2b_init_param(hsk_blake2b_ctx *ctx, const hsk_blake2b_param *P)
{
  const uint8_t *p = (const uint8_t *)(P);
  size_t i;

  hsk_blake2b_init0(ctx);

  for (i = 0; i < 8; i++) ctx->h[i] ^= load64(p + sizeof(ctx->h[i]) * i);

  ctx->outlen = P->digest_length;

  return 0;
}

int hsk_blake2b_init(hsk_blake2b_ctx *ctx, size_t outlen)
{
  hsk_blake2b_param P[1];

  if ((!outlen) || (outlen > HSK_BLAKE2B_OUTBYTES)) return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length = 0;
  P->fanout = 1;
  P->depth = 1;
  store32(&P->leaf_length, 0);
  store32(&P->node_offset, 0);
  store32(&P->xof_length, 0);
  P->node_depth = 0;
  P->inner_length = 0;
  memset(P->reserved, 0, sizeof(P->reserved));
  memset(P->salt, 0, sizeof(P->salt));
  memset(P->personal, 0, sizeof(P->personal));

  return hsk_blake2b_init_param(ctx, P);
}

static int hsk_blake2b_is_lastblock(const hsk_blake2b_ctx *ctx)
{
  return ctx->f[0] != 0;
}

/* prevents compiler optimizing out memset() */
static HSK_BLAKE2_INLINE void secure_zero_memory(void *v, size_t n)
{
  static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
  memset_v(v, 0, n);
}

static void hsk_blake2b_set_lastnode(hsk_blake2b_ctx *ctx)
{
  ctx->f[1] = (uint64_t)-1;
}

static void hsk_blake2b_set_lastblock(hsk_blake2b_ctx *ctx)
{
  if (ctx->last_node) hsk_blake2b_set_lastnode(ctx);
  ctx->f[0] = (uint64_t)-1;
}

static HSK_BLAKE2_INLINE void store64(void *dst, uint64_t w)
{
#ifndef HSK_BIG_ENDIAN
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
  p[4] = (uint8_t)(w >> 32);
  p[5] = (uint8_t)(w >> 40);
  p[6] = (uint8_t)(w >> 48);
  p[7] = (uint8_t)(w >> 56);
#endif
}

int hsk_blake2b_final(hsk_blake2b_ctx *ctx, void *out, size_t outlen)
{
  uint8_t buffer[HSK_BLAKE2B_OUTBYTES] = {0};
  size_t i;

  if (out == NULL || outlen < ctx->outlen) return -1;

  if (hsk_blake2b_is_lastblock(ctx)) return -1;

  hsk_blake2b_increment_counter(ctx, ctx->buflen);
  hsk_blake2b_set_lastblock(ctx);
  memset(ctx->buf + ctx->buflen, 0, HSK_BLAKE2B_BLOCKBYTES - ctx->buflen);
  hsk_blake2b_compress(ctx, ctx->buf);

  for (i = 0; i < 8; i++)
    store64(buffer + sizeof(ctx->h[i]) * i, ctx->h[i]);

  memcpy(out, buffer, ctx->outlen);
  secure_zero_memory(buffer, sizeof(buffer));

  return 0;
}

void hsk_hash_blake256(const uint8_t *data, size_t data_len, uint8_t *hash)
{
	assert(hash != NULL);
	hsk_blake2b_ctx ctx;
	assert(hsk_blake2b_init(&ctx, 32) == 0);
	hsk_blake2b_update(&ctx, data, data_len);
	assert(hsk_blake2b_final(&ctx, hash, 32) == 0);
}

void hsk_header_sub_hash(const hsk_header_t *hdr, uint8_t *hash)
{
	int size = hsk_header_sub_size(hdr);
	uint8_t sub[size];
	hsk_header_sub_encode(hdr, sub);
	hsk_hash_blake256(sub, size, hash);
}

void hsk_header_mask_hash(const hsk_header_t *hdr, uint8_t *hash)
{
	hsk_blake2b_ctx ctx;
	assert(hsk_blake2b_init(&ctx, 32) == 0);
	hsk_blake2b_update(&ctx, hdr->prev_block, 32);
	hsk_blake2b_update(&ctx, hdr->mask, 32);
	assert(hsk_blake2b_final(&ctx, hash, 32) == 0);
}

void hsk_header_commit_hash(const hsk_header_t *hdr, uint8_t *hash)
{
	uint8_t sub_hash[32];
	uint8_t mask_hash[32];

	hsk_header_sub_hash(hdr, sub_hash);
	hsk_header_mask_hash(hdr, mask_hash);

	hsk_blake2b_ctx ctx;
	assert(hsk_blake2b_init(&ctx, 32) == 0);
	hsk_blake2b_update(&ctx, sub_hash, 32);
	hsk_blake2b_update(&ctx, mask_hash, 32);
	assert(hsk_blake2b_final(&ctx, hash, 32) == 0);
}

int hsk_header_pre_write(const hsk_header_t *hdr, uint8_t **data)
{
	int s = 0;
	uint8_t pad[20];
	uint8_t commit_hash[32];

	hsk_header_padding(hdr, pad, 20);
	hsk_header_commit_hash(hdr, commit_hash);

	s += write_u32(data, hdr->nonce);
	s += write_u64(data, hdr->time);
	s += write_bytes(data, pad, 20);
	s += write_bytes(data, hdr->prev_block, 32);
	s += write_bytes(data, hdr->name_root, 32);
	s += write_bytes(data, commit_hash, 32);
	return s;
}

int hsk_header_pre_size(const hsk_header_t *hdr)
{
	return hsk_header_pre_write(hdr, NULL);
}

int hsk_header_pre_encode(const hsk_header_t *hdr, uint8_t *data)
{
	return hsk_header_pre_write(hdr, &data);
}

void hsk_hash_blake512(const uint8_t *data, size_t data_len, uint8_t *hash)
{
	assert(hash != NULL);
	hsk_blake2b_ctx ctx;
	assert(hsk_blake2b_init(&ctx, 64) == 0);
	hsk_blake2b_update(&ctx, data, data_len);
	assert(hsk_blake2b_final(&ctx, hash, 64) == 0);
}

static void hsk_keccak_init(hsk_sha3_ctx *ctx, unsigned bits)
{
  unsigned rate = 1600 - bits * 2;

  memset(ctx, 0, sizeof(hsk_sha3_ctx));
  ctx->block_size = rate / 8;
  assert(rate <= 1600 && (rate % 64) == 0);
}

void hsk_sha3_256_init(hsk_sha3_ctx *ctx)
{
  hsk_keccak_init(ctx, 256);
}

#define IS_ALIGNED_64(p) (0 == (7 & ((const char *)(p) - (const char *)0)))

#define HSK_SHA3_ROUNDS 24
#define HSK_SHA3_FINALIZED 0x80000000

#ifdef HSK_BIG_ENDIAN
#define le2me_64(x) bswap_64(x)
#define me64_to_le_str(to, from, length) \
  swap_copy_u64_to_str((to), (from), (length))
#else
#define le2me_64(x) (x)
#define me64_to_le_str(to, from, length) \
  memcpy((to), (from), (length))
#endif

#if defined(_MSC_VER) || defined(__BORLANDC__)
#define I64(x) x##ui64
#else
#define I64(x) x##ULL
#endif

static uint64_t hsk_keccak_round_constants[HSK_SHA3_ROUNDS] =
{
  I64(0x0000000000000001), I64(0x0000000000008082),
  I64(0x800000000000808A), I64(0x8000000080008000),
  I64(0x000000000000808B), I64(0x0000000080000001),
  I64(0x8000000080008081), I64(0x8000000000008009),
  I64(0x000000000000008A), I64(0x0000000000000088),
  I64(0x0000000080008009), I64(0x000000008000000A),
  I64(0x000000008000808B), I64(0x800000000000008B),
  I64(0x8000000000008089), I64(0x8000000000008003),
  I64(0x8000000000008002), I64(0x8000000000000080),
  I64(0x000000000000800A), I64(0x800000008000000A),
  I64(0x8000000080008081), I64(0x8000000000008080),
  I64(0x0000000080000001), I64(0x8000000080008008)
};

#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))

static void hsk_keccak_theta(uint64_t *A)
{
  unsigned int x;
  uint64_t C[5], D[5];

  for (x = 0; x < 5; x++)
    C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];

  D[0] = ROTL64(C[1], 1) ^ C[4];
  D[1] = ROTL64(C[2], 1) ^ C[0];
  D[2] = ROTL64(C[3], 1) ^ C[1];
  D[3] = ROTL64(C[4], 1) ^ C[2];
  D[4] = ROTL64(C[0], 1) ^ C[3];

  for (x = 0; x < 5; x++) {
    A[x] ^= D[x];
    A[x + 5] ^= D[x];
    A[x + 10] ^= D[x];
    A[x + 15] ^= D[x];
    A[x + 20] ^= D[x];
  }
}

static void hsk_keccak_pi(uint64_t *A)
{
  uint64_t A1;

  A1 = A[1];
  A[1] = A[6];
  A[6] = A[9];
  A[9] = A[22];
  A[22] = A[14];
  A[14] = A[20];
  A[20] = A[2];
  A[2] = A[12];
  A[12] = A[13];
  A[13] = A[19];
  A[19] = A[23];
  A[23] = A[15];
  A[15] = A[4];
  A[4] = A[24];
  A[24] = A[21];
  A[21] = A[8];
  A[8] = A[16];
  A[16] = A[5];
  A[5] = A[3];
  A[3] = A[18];
  A[18] = A[17];
  A[17] = A[11];
  A[11] = A[7];
  A[7] = A[10];
  A[10] = A1;
}

static void hsk_keccak_chi(uint64_t *A)
{
  int i;
  for (i = 0; i < 25; i += 5)
  {
    uint64_t A0 = A[0 + i], A1 = A[1 + i];
    A[0 + i] ^= ~A1 & A[2 + i];
    A[1 + i] ^= ~A[2 + i] & A[3 + i];
    A[2 + i] ^= ~A[3 + i] & A[4 + i];
    A[3 + i] ^= ~A[4 + i] & A0;
    A[4 + i] ^= ~A0 & A1;
  }
}

static void hsk_sha3_permutation(uint64_t *state)
{
  int round;
  for (round = 0; round < HSK_SHA3_ROUNDS; round++)
  {
    hsk_keccak_theta(state);

    state[1] = ROTL64(state[1], 1);
    state[2] = ROTL64(state[2], 62);
    state[3] = ROTL64(state[3], 28);
    state[4] = ROTL64(state[4], 27);
    state[5] = ROTL64(state[5], 36);
    state[6] = ROTL64(state[6], 44);
    state[7] = ROTL64(state[7], 6);
    state[8] = ROTL64(state[8], 55);
    state[9] = ROTL64(state[9], 20);
    state[10] = ROTL64(state[10], 3);
    state[11] = ROTL64(state[11], 10);
    state[12] = ROTL64(state[12], 43);
    state[13] = ROTL64(state[13], 25);
    state[14] = ROTL64(state[14], 39);
    state[15] = ROTL64(state[15], 41);
    state[16] = ROTL64(state[16], 45);
    state[17] = ROTL64(state[17], 15);
    state[18] = ROTL64(state[18], 21);
    state[19] = ROTL64(state[19], 8);
    state[20] = ROTL64(state[20], 18);
    state[21] = ROTL64(state[21], 2);
    state[22] = ROTL64(state[22], 61);
    state[23] = ROTL64(state[23], 56);
    state[24] = ROTL64(state[24], 14);

    hsk_keccak_pi(state);
    hsk_keccak_chi(state);

    *state ^= hsk_keccak_round_constants[round];
  }
}

static void hsk_sha3_process_block(uint64_t hash[25], const uint64_t *block, size_t block_size)
{
  hash[0] ^= le2me_64(block[0]);
  hash[1] ^= le2me_64(block[1]);
  hash[2] ^= le2me_64(block[2]);
  hash[3] ^= le2me_64(block[3]);
  hash[4] ^= le2me_64(block[4]);
  hash[5] ^= le2me_64(block[5]);
  hash[6] ^= le2me_64(block[6]);
  hash[7] ^= le2me_64(block[7]);
  hash[8] ^= le2me_64(block[8]);

  if (block_size > 72) {
    hash[9] ^= le2me_64(block[9]);
    hash[10] ^= le2me_64(block[10]);
    hash[11] ^= le2me_64(block[11]);
    hash[12] ^= le2me_64(block[12]);

    if (block_size > 104) {
      hash[13] ^= le2me_64(block[13]);
      hash[14] ^= le2me_64(block[14]);
      hash[15] ^= le2me_64(block[15]);
      hash[16] ^= le2me_64(block[16]);

      if (block_size > 136) {
        hash[17] ^= le2me_64(block[17]);

        if (block_size > 144) {
          hash[18] ^= le2me_64(block[18]);
          hash[19] ^= le2me_64(block[19]);
          hash[20] ^= le2me_64(block[20]);
          hash[21] ^= le2me_64(block[21]);
          hash[22] ^= le2me_64(block[22]);
          hash[23] ^= le2me_64(block[23]);
          hash[24] ^= le2me_64(block[24]);
        }
      }
    }
  }

  hsk_sha3_permutation(hash);
}

void hsk_sha3_update(hsk_sha3_ctx *ctx, const unsigned char *msg, size_t size)
{
  size_t index = (size_t)ctx->rest;
  size_t block_size = (size_t)ctx->block_size;

  if (ctx->rest & HSK_SHA3_FINALIZED)
    return;

  ctx->rest = (unsigned)((ctx->rest + size) % block_size);

  if (index) {
    size_t left = block_size - index;
    memcpy((char *)ctx->message + index, msg, (size < left ? size : left));

    if (size < left)
      return;

    hsk_sha3_process_block(ctx->hash, ctx->message, block_size);
    msg += left;
    size -= left;
  }

  while (size >= block_size) {
    uint64_t *aligned_message_block;

    if (IS_ALIGNED_64(msg)) {
      aligned_message_block = (uint64_t *)msg;
    } else {
      memcpy(ctx->message, msg, block_size);
      aligned_message_block = ctx->message;
    }

    hsk_sha3_process_block(ctx->hash, aligned_message_block, block_size);
    msg += block_size;
    size -= block_size;
  }

  if (size)
    memcpy(ctx->message, msg, size);
}

void hsk_sha3_final(hsk_sha3_ctx *ctx, unsigned char *result)
{
  size_t digest_length = 100 - ctx->block_size / 2;
  const size_t block_size = ctx->block_size;

  if (!(ctx->rest & HSK_SHA3_FINALIZED))
  {
    memset((char *)ctx->message + ctx->rest, 0, block_size - ctx->rest);
    ((char *)ctx->message)[ctx->rest] |= 0x06;
    ((char *)ctx->message)[block_size - 1] |= 0x80;

    hsk_sha3_process_block(ctx->hash, ctx->message, block_size);
    ctx->rest = HSK_SHA3_FINALIZED;
  }

  assert(block_size > digest_length);

  if (result) me64_to_le_str(result, ctx->hash, digest_length);
}

const uint8_t *hsk_header_cache(hsk_header_t *hdr)
{
	if (hdr->cache) printf("already in cache\n");

	if (hdr->cache) return hdr->hash;

// WORK
	int size = hsk_header_pre_size(hdr);
	uint8_t pre[size];
	uint8_t pad8[8];
	uint8_t pad32[32];
	uint8_t left[64];
	uint8_t right[32];

	// Generate pads.
	hsk_header_padding(hdr, pad8, 8);
	hsk_header_padding(hdr, pad32, 32);

	// Generate left.
	hsk_header_pre_encode(hdr, pre);
	hsk_hash_blake512(pre, size, left);

	// Generate right.
	hsk_sha3_ctx s_ctx;
	hsk_sha3_256_init(&s_ctx);
	hsk_sha3_update(&s_ctx, pre, size);
	hsk_sha3_update(&s_ctx, pad8, 8);
	hsk_sha3_final(&s_ctx, right);

	// Generate hash.
	hsk_blake2b_ctx b_ctx;
	assert(hsk_blake2b_init(&b_ctx, 32) == 0);
	hsk_blake2b_update(&b_ctx, left, 64);
	hsk_blake2b_update(&b_ctx, pad32, 32);
	hsk_blake2b_update(&b_ctx, right, 32);
	assert(hsk_blake2b_final(&b_ctx, hdr->hash, 32) == 0);

	// XOR PoW hash with arbitrary bytes.
	// This can be used by mining pools to
	// mitigate block witholding attacks.

	for(int i = 0; i < 32; i++) hdr->hash[i] ^= hdr->mask[i];

	hdr->cache = true;

	return hdr->hash;
}

char hexdigs[16] = 
{
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
	'f'
};

void fill_test_header(hsk_header_t *hdr)
{
	int i;
	int c;

	hdr->nonce = 1234567;
	hdr->time = 1761496325;
	for(i = 0; i < 32; ++i)
	{
		c = hexdigs[i%16];
		hdr->prev_block[i] = c;
		hdr->name_root[i] = c;
		if(i < 24) hdr->extra_nonce[i] = c;
		hdr->reserved_root[i] = c;
		hdr->witness_root[i] = c;
		hdr->merkle_root[i] = c;
		hdr->hash[i] = c;
		hdr->work[i] = c;
	}
	hdr->bits = 1234567;
	hdr->cache = 0;
	hdr->height = 0;
}

hsk_header_t *make_test_header(void)
{
	hsk_header_t *hdr;

	hdr = calloc(1,sizeof(hsk_header_t));
	fill_test_header(hdr);

	return hdr;
}

int main()
{
	hsk_header_t *hdr;
	const uint8_t *cache;
	int size;
	uint8_t *p;

	/* Print the size of the header struct. */

	size = sizeof(hsk_header_t);
	printf("Size of header: %d bytes\n",size);

	/* Create test data. A fake header. */

	hdr = make_test_header();
	hdr->cache = 0;

	// Print the bytes in the header as hex uint8_t.

	printf("Header Contents:");
	p = (uint8_t *) hdr;
	for(int i = 0; i < size; ++i)
	{
		if(i % 16 == 0) printf("\n");
		printf("%2x ",p[i]);
	}
	printf("\n");

	/* Calculate the header's hash */
	cache = hsk_header_cache(hdr);

	/* Print it. */

	printf("Header hash:\n");
	for(int i = 0; i < 32; ++i) printf("%x",cache[i]);
	printf("\n");
}
