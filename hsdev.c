#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <uv.h>

#include "bio.h"

#define HSK_MAX_HOST 128

#define HSK_MSG_VERSION 0
#define HSK_MSG_VERACK 1
#define HSK_MSG_PING 2
#define HSK_MSG_PONG 3
#define HSK_MSG_GETADDR 4
#define HSK_MSG_ADDR 5
#define HSK_MSG_GETHEADERS 10
#define HSK_MSG_HEADERS 11
#define HSK_MSG_SENDHEADERS 12
#define HSK_MSG_GETPROOF 26
#define HSK_MSG_PROOF 27
#define HSK_MSG_UNKNOWN 255

/* From pool.h */
#define HSK_BUFFER_SIZE 32768
#define HSK_POOL_SIZE 8
#define HSK_STATE_DISCONNECTED 0
#define HSK_STATE_CONNECTING 2
#define HSK_STATE_CONNECTED 3
#define HSK_STATE_READING 4
#define HSK_STATE_HANDSHAKE 5
#define HSK_STATE_DISCONNECTING 6
#define HSK_MAX_AGENT 255
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* From constants.h */

#define HSK_MAX_MESSAGE (8 * 1000 * 1000)
#define HSK_USER_AGENT "/"PACKAGE_NAME":"PACKAGE_VERSION"/"
#define HSK_PROTO_VERSION 1
#define HSK_SERVICES 0
#define HSK_MAX_DATA_SIZE 668
#define HSK_MAX_VALUE_SIZE 512

static const uint8_t HSK_ZERO_HASH[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_NS_IP "127.0.0.1"
#define HSK_RS_IP "127.0.0.1"
#define HSK_RS_A "127.0.0.1"

static const char HSK_TRUST_ANCHOR[] = ". DS 35215 13 2 "
  "7C50EA94A63AEECB65B510D1EAC1846C973A89D4AB292287D5A4D715136B57A3";

static const char HSK_KSK_2010[] = ". DS 19036 8 2 "
  "49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5";

static const char HSK_KSK_2017[] = ". DS 20326 8 2 "
  "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

// the remainder are all from the "mainnet" section:

#define HSK_NETWORK_NAME "main"
#define HSK_MAGIC 0x5b6ef2d3
#define HSK_PORT 12038
#define HSK_BRONTIDE_PORT 44806
#define HSK_NS_PORT 5349
#define HSK_RS_PORT 5350

#define HSK_BITS 0x1c00ffff

static const uint8_t HSK_LIMIT[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t HSK_CHAINWORK[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x75, 0xb5, 0xa2, 0xb7, 0xbf, 0x52, 0x2d, 0x45
};

#define HSK_TARGET_WINDOW 144
#define HSK_TARGET_SPACING (10 * 60)
#define HSK_TARGET_TIMESPAN (HSK_TARGET_WINDOW * HSK_TARGET_SPACING)
#define HSK_MIN_ACTUAL (HSK_TARGET_TIMESPAN / 4)
#define HSK_MAX_ACTUAL (HSK_TARGET_TIMESPAN * 4)
#define HSK_TREE_INTERVAL 36
#define HSK_TARGET_RESET false
#define HSK_NO_RETARGETTING false
#define HSK_GENESIS HSK_GENESIS_MAIN

#define HSK_CHECKPOINT HSK_CHECKPOINT_MAIN
#define HSK_STORE_CHECKPOINT_WINDOW 2000

#define HSK_MAX_TIP_AGE (24 * 60 * 60)
// end of inclusion from constants.h

/* From error.h */
#define HSK_SUCCESS 0
#define HSK_EOK 0
#define HSK_ENOMEM 1
#define HSK_ETIMEOUT 2
#define HSK_EFAILURE 3
#define HSK_EBADARGS 4
#define HSK_EENCODING 5

// Proofs
#define HSK_EPROOFOK 0
#define HSK_EHASHMISMATCH 6
#define HSK_ESAMEKEY 7
#define HSK_ESAMEPATH 8
#define HSK_ENEGDEPTH 9
#define HSK_EPATHMISMATCH 10
#define HSK_ETOODEEP 11
#define HSK_EUNKNOWNERROR 12
#define HSK_EMALFORMEDNODE 13
#define HSK_EINVALIDNODE 14
#define HSK_EEARLYEND 15
#define HSK_ENORESULT 16
#define HSK_EUNEXPECTEDNODE 17
#define HSK_ERECORDMISMATCH 18

// POW
#define HSK_ENEGTARGET 19
#define HSK_EHIGHHASH 20

// Chain
#define HSK_ETIMETOONEW 21
#define HSK_EDUPLICATE 22
#define HSK_EDUPLICATEORPHAN 23
#define HSK_ETIMETOOOLD 24
#define HSK_EBADDIFFBITS 25
#define HSK_EORPHAN 26

// Brontide
#define HSK_EACTONE 27
#define HSK_EACTTWO 28
#define HSK_EACTTHREE 29
#define HSK_EBADSIZE 30
#define HSK_EBADTAG 31

// Max
#define HSK_MAXERROR 32
// end of inclusion from error.h

static const uint8_t hsk_ip4_mapped[12] =
{
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xff, 0xff
};

typedef struct hsk_addr_s
{
	uint8_t type;
	uint8_t ip[36];
	uint16_t port;
	uint8_t key[33];
} hsk_addr_t;

typedef struct
{
	uint64_t time;
	uint64_t services;
	hsk_addr_t addr;
} hsk_netaddr_t;

typedef struct hsk_addrentry_s {
  hsk_addr_t addr;
  uint64_t time;
  uint64_t services;
  int32_t attempts;
  int64_t last_success;
  int64_t last_attempt;
  int32_t ref_count;
  bool used;
  bool removed;
} hsk_addrentry_t;

typedef uint32_t (*hsk_map_hash_func)(const void *key);
typedef bool (*hsk_map_equal_func)(const void *a, const void *b);
typedef void (*hsk_map_free_func)(void *ptr);

typedef struct hsk_map_s
{
	uint32_t n_buckets;
	uint32_t size;
	uint32_t n_occupied;
	uint32_t upper_bound;
	uint32_t *flags;
	void **keys;
	void **vals;
	bool is_map;
	hsk_map_hash_func hash_func;
	hsk_map_equal_func equal_func;
	hsk_map_free_func free_func;
} hsk_map_t;

#define HSK_TIMEDATA_LIMIT 200

typedef struct hsk_timedata_s
{
	size_t sample_len;
	int64_t samples[HSK_TIMEDATA_LIMIT];
	hsk_map_t known;
	int64_t offset;
	bool checked;
} hsk_timedata_t;

typedef struct hsk_addrman_s {
  hsk_timedata_t *td;
  size_t size;
  hsk_addrentry_t *addrs;
  hsk_map_t map;
  hsk_map_t banned;
} hsk_addrman_t;

typedef struct
{
	uint8_t cmd;
} hsk_msg_t;

typedef struct
{
	uint8_t cmd;
	uint32_t version;
	uint64_t services;
	uint64_t time;
	hsk_netaddr_t remote;
	uint64_t nonce;
	char agent[256];
	uint32_t height;
	uint8_t no_relay;
} hsk_version_msg_t;

typedef struct
{
	uint8_t cmd;
} hsk_verack_msg_t;

typedef struct
{
	uint8_t cmd;
	uint64_t nonce;
} hsk_ping_msg_t;

typedef struct
{
	uint8_t cmd;
	uint64_t nonce;
} hsk_pong_msg_t;

typedef struct
{
	uint8_t cmd;
} hsk_getaddr_msg_t;

typedef struct
{
	uint8_t cmd;
	size_t addr_count;
	hsk_netaddr_t addrs[1000];
} hsk_addr_msg_t;

typedef struct
{
	uint8_t cmd;
	size_t hash_count;
	uint8_t hashes[64][32];
	uint8_t stop[32];
} hsk_getheaders_msg_t;

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

typedef struct
{
	uint8_t cmd;
	size_t header_count;
	hsk_header_t *headers;
} hsk_headers_msg_t;

typedef struct
{
	uint8_t cmd;
} hsk_sendheaders_msg_t;

typedef struct
{
	uint8_t cmd;
	uint8_t root[32];
	uint8_t key[32];
} hsk_getproof_msg_t;

typedef struct hsk_chain_s
{
	int64_t height;
	uint32_t init_height;
	hsk_header_t *tip;
	hsk_header_t *genesis;
	bool synced;
	hsk_timedata_t *td;
	hsk_map_t hashes;
	hsk_map_t heights;
	hsk_map_t orphans;
	hsk_map_t prevs;
	char *prefix;
} hsk_chain_t;

typedef struct hsk_peer_s
{
	void *pool;
	hsk_chain_t *chain;
	uv_loop_t *loop;
	uv_tcp_t socket;
// NOTE Brontide has to do with Bitcoin Lightning network.
// No need for it here.
//	hsk_brontide_t *brontide;
void *brontide;
	uint64_t id;
	char host[HSK_MAX_HOST];
	char agent[HSK_MAX_AGENT];
	hsk_addr_t addr;
	int state;
	uint8_t read_buffer[HSK_BUFFER_SIZE];
	int headers;
	int proofs;
	int64_t height;
	hsk_map_t names;
	int64_t getheaders_time;
	int64_t version_time;
	int64_t last_ping;
	int64_t last_pong;
	int64_t min_ping;
	int64_t ping_timer;
	uint64_t challenge;
	int64_t conn_time;
	int64_t last_send;
	int64_t last_recv;
	bool msg_hdr;
	uint8_t *msg;
	size_t msg_pos;
	size_t msg_len;
	uint8_t msg_cmd;
	struct hsk_peer_s *next;
} hsk_peer_t;

/** Opaque data structure that holds context information (precomputed tables etc.).
 *
 *  The purpose of context structures is to cache large precomputed data tables
 *  that are expensive to construct, and also to maintain the randomization data
 *  for blinding.
 *
 *  Do not create a new context object for each operation, as construction is
 *  far slower than all other API calls (~100 times slower than an ECDSA
 *  verification).
 *
 *  A constructed context can safely be used from multiple threads
 *  simultaneously, but API call that take a non-const pointer to a context
 *  need exclusive access to it. In particular this is the case for
 *  hsk_secp256k1_context_destroy and hsk_secp256k1_context_randomize.
 *
 *  Regarding randomization, either do it once at creation time (in which case
 *  you do not need any locking for the other calls), or use a read-write lock.
 */
typedef struct hsk_secp256k1_context_struct hsk_secp256k1_context;

// ec.h 
typedef hsk_secp256k1_context hsk_ec_t;

// pool.h...
typedef void (*hsk_resolve_cb)(const char *name, int status, bool exists, const uint8_t *data, size_t data_len, const void *arg);

typedef struct hsk_name_req_s
{
	char name[256];
	uint8_t hash[32];
	uint8_t root[32];
	hsk_resolve_cb callback;
	void *arg;
	int64_t time;
	struct hsk_name_req_s *next;
} hsk_name_req_t;

typedef struct hsk_pool_s
{
	uv_loop_t *loop;
// hsk_ec_t is from (very complicated) secp256k1
//	hsk_ec_t *ec;
void *ec;
	uint8_t key_[32];
	uint8_t *key;
	uint8_t pubkey[33];
	hsk_timedata_t td;
	hsk_chain_t chain;
	hsk_addrman_t am;
	uv_timer_t *timer;
	uint64_t peer_id;
	hsk_map_t peers;
	hsk_peer_t *head;
	hsk_peer_t *tail;
	int size;
	int max_size;
	hsk_name_req_t *pending;
	int pending_count;
	int64_t block_time;
	int64_t getheaders_time;
	char *user_agent;
} hsk_pool_t;

typedef struct hsk_write_data_s
{
	hsk_peer_t *peer;
	void *data;
	bool should_free;
} hsk_write_data_t;

void hsk_addr_init(hsk_addr_t *addr)
{
	assert(addr);
	memset(addr, 0x00, sizeof(hsk_addr_t));
}

void hsk_netaddr_init(hsk_netaddr_t *na)
{
	if (na == NULL) return;
	na->time = 0;
	na->services = 0;
	hsk_addr_init(&na->addr);
}

const char *hsk_msg_str(uint8_t cmd)
{
	switch(cmd)
	{
		case HSK_MSG_VERSION:	return "version";
		case HSK_MSG_VERACK:	return "verack";
		case HSK_MSG_PING:	return "ping";
		case HSK_MSG_PONG:	return "pong";
		case HSK_MSG_GETADDR:	return "getaddr";
		case HSK_MSG_ADDR:	return "addr";
		case HSK_MSG_GETHEADERS: return "getheaders";
		case HSK_MSG_HEADERS:	return "headers";
		case HSK_MSG_SENDHEADERS: return "sendheaders";
		case HSK_MSG_GETPROOF:	return "getproof";
		case HSK_MSG_PROOF:	return "proof";
		default:		return "unknown";
	}
}

typedef struct hsk_proof_node_s {
  uint8_t prefix[32];
  uint16_t prefix_size;
  uint8_t node[32];
} hsk_proof_node_t;

typedef struct hsk_proof_s {
  uint8_t type;
  uint16_t depth;
  hsk_proof_node_t *nodes;
  uint16_t node_count;
  uint8_t *prefix;
  uint16_t prefix_size;
  uint8_t *left;
  uint8_t *right;
  uint8_t *nx_key;
  uint8_t *nx_hash;
  uint8_t *value;
  uint16_t value_size;
} hsk_proof_t;

typedef struct
{
  uint8_t cmd;
  uint8_t root[32];
  uint8_t key[32];
  hsk_proof_t proof;
} hsk_proof_msg_t;

void hsk_msg_init(hsk_msg_t *msg)
{
	if (msg == NULL) return;

	switch (msg->cmd)
	{
		case HSK_MSG_VERSION:
			hsk_version_msg_t *m = (hsk_version_msg_t *)msg;
			m = (hsk_version_msg_t *)msg;
			m->cmd = HSK_MSG_VERSION;
			m->version = 0;
			m->services = 0;
			m->time = 0;
			hsk_netaddr_init(&m->remote);
			m->nonce = 0;
			memset(m->agent, 0, 256);
			m->height = 0;
			m->no_relay = true;
			break;
		case HSK_MSG_VERACK:
//			hsk_verack_msg_t *m = (hsk_verack_msg_t *)msg;
			hsk_verack_msg_t *verack_m = (hsk_verack_msg_t *)msg;
			verack_m->cmd = HSK_MSG_VERACK;
			break;
/*
		case HSK_MSG_PING:
			hsk_ping_msg_t *m = (hsk_ping_msg_t *)msg;
			m->cmd = HSK_MSG_PING;
			m->nonce = 0;
			break;
		case HSK_MSG_PONG:
			hsk_pong_msg_t *m;
			m = (hsk_pong_msg_t *)msg;
			m->cmd = HSK_MSG_PONG;
			m->nonce = 0;
			break;
		case HSK_MSG_GETADDR:
			hsk_getaddr_msg_t *m = (hsk_getaddr_msg_t *)msg;
			m->cmd = HSK_MSG_GETADDR;
			break;
		case HSK_MSG_GETHEADERS:
			hsk_getheaders_msg_t *m = (hsk_getheaders_msg_t *)msg;
			m->cmd = HSK_MSG_GETHEADERS;
			int i;
			for (i = 0; i < 64; i++)
			memset(m->hashes[i], 0, 32);
			memset(m->stop, 0, 32);
			break;
		case HSK_MSG_HEADERS:
			hsk_headers_msg_t *m = (hsk_headers_msg_t *)msg;
			m->cmd = HSK_MSG_HEADERS;
			m->header_count = 0;
			m->headers = NULL;
			break;
		case HSK_MSG_SENDHEADERS:
			hsk_sendheaders_msg_t *m = (hsk_sendheaders_msg_t *)msg;
			m->cmd = HSK_MSG_SENDHEADERS;
			break;
		case HSK_MSG_GETPROOF:
			hsk_getproof_msg_t *m = (hsk_getproof_msg_t *)msg;
			m->cmd = HSK_MSG_GETPROOF;
			memset(m->root, 0, 32);
			memset(m->key, 0, 32);
			break;
		case HSK_MSG_PROOF:
			hsk_proof_msg_t *m = (hsk_proof_msg_t *)msg;
			m->cmd = HSK_MSG_PROOF;
			memset(m->root, 0, 32);
			memset(m->key, 0, 32);
			hsk_proof_init(&m->proof);
			break;
*/
	}
}

bool hsk_netaddr_read(uint8_t **data, size_t *data_len, hsk_netaddr_t *na)
{
	if (!read_u64(data, data_len, &na->time)) return false;
	if (!read_u64(data, data_len, &na->services)) return false;
	if (!read_u8(data, data_len, &na->addr.type)) return false;
	if (!read_bytes(data, data_len, na->addr.ip, 36)) return false;

	// Make sure we ignore trailing bytes
	// if the address is an IP address.
	if (na->addr.type == 0) memset(&na->addr.ip[16], 0x00, 20);
	if (!read_u16(data, data_len, &na->addr.port)) return false;
	if (!read_bytes(data, data_len, na->addr.key, 33)) return false;

	return true;
}

int hsk_netaddr_write(const hsk_netaddr_t *na, uint8_t **data)
{
	int s = 0;

	s += write_u64(data, na->time);
	s += write_u64(data, na->services);
	s += write_u8(data, na->addr.type);
	s += write_bytes(data, na->addr.ip, 36);
	s += write_u16(data, na->addr.port);
	s += write_bytes(data, na->addr.key, 33);

	return s;
}

bool hsk_version_msg_read(uint8_t **data, size_t *data_len, hsk_version_msg_t *msg)
{
	uint8_t size;
	uint8_t no_relay;

	if( ! read_u32(data, data_len, &msg->version))	return false;
	if( ! read_u64(data, data_len, &msg->services))	return false;
	if( ! read_u64(data, data_len, &msg->time))	return false;
	if( ! hsk_netaddr_read(data, data_len, &msg->remote)) return false;
	if( ! read_u64(data, data_len, &msg->nonce))	return false;

	if( ! read_u8(data, data_len, &size))			return false;
	if( ! read_ascii(data, data_len, msg->agent, (size_t)size)) return false;
	if( ! read_u32(data, data_len, &msg->height))		return false;

	if( ! read_u8(data, data_len, &no_relay)) return false;

	msg->no_relay = no_relay == 1;

	return true;
}

int hsk_version_msg_write(hsk_version_msg_t *msg, uint8_t **data)
{
	int s = 0;
	size_t size;

	s += write_u32(data, msg->version);
	s += write_u64(data, msg->services);
	s += write_u64(data, msg->time);
	s += hsk_netaddr_write(&msg->remote, data);
	s += write_u64(data, msg->nonce);

	size = strlen(msg->agent);

	s += write_u8(data, size);
	s += write_bytes(data, (uint8_t *)msg->agent, size);
	s += write_u32(data, msg->height);
	s += write_u8(data, msg->no_relay ? 1 : 0);

	return s;
}

bool hsk_addr_is_mapped(const hsk_addr_t *addr)
{
	assert(addr);
	return memcmp(addr->ip, hsk_ip4_mapped, sizeof(hsk_ip4_mapped)) == 0;
}

static const uint8_t hsk_tor_onion[6] =
{
	0xfd, 0x87, 0xd8, 0x7e,
	0xeb, 0x43
};

bool hsk_addr_is_onion(const hsk_addr_t *addr)
{
	assert(addr);
	return memcmp(addr->ip, hsk_tor_onion, sizeof(hsk_tor_onion)) == 0;
}

bool hsk_addr_is_ip6(const hsk_addr_t *addr)
{
	assert(addr);
	return !hsk_addr_is_mapped(addr) && !hsk_addr_is_onion(addr);
}

const uint8_t *hsk_addr_get_ip(const hsk_addr_t *addr)
{
	assert(addr);
	if(hsk_addr_is_ip6(addr)) return addr->ip;
	return &addr->ip[12];
}

int hsk_addr_get_af(const hsk_addr_t *addr)
{
	assert(addr);
	return hsk_addr_is_mapped(addr) ? AF_INET : AF_INET6;
}

/* From the uv source */

#define UV__INET_ADDRSTRLEN         16
#define UV__INET6_ADDRSTRLEN        46

static int inet_ntop4(const unsigned char *src, char *dst, size_t size)
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[UV__INET_ADDRSTRLEN];
	int l;

	l = snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
	if(l <= 0 || (size_t) l >= size) return UV_ENOSPC;
	strncpy(dst, tmp, size);
	dst[size - 1] = '\0';

	return 0;
}

static int inet_ntop6(const unsigned char *src, char *dst, size_t size)
{
	/*
	* Note that int32_t and int16_t need only be "at least" large enough
	* to contain a value of the specified size.  On some systems, like
	* Crays, there is no such thing as an integer variable with 16 bits.
	* Keep this in mind if you think this function should have been coded
	* to use pointer overlays.  All the world's not a VAX.
	*/
	char tmp[UV__INET6_ADDRSTRLEN], *tp;
	struct { int base, len; } best, cur;
	unsigned int words[sizeof(struct in6_addr) / sizeof(uint16_t)];
	int i;

	/*
	* Preprocess:
	*  Copy the input (bytewise) array into a wordwise array.
	*  Find the longest run of 0x00's in src[] for :: shorthanding.
	*/
	memset(words, '\0', sizeof words);
	for(i = 0; i < (int) sizeof(struct in6_addr); i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	best.len = 0;
	cur.base = -1;
	cur.len = 0;

	for(i = 0; i < (int) ARRAY_SIZE(words); i++)
	{
		if(words[i] == 0)
		{
			if(cur.base == -1) cur.base = i, cur.len = 1;
			else cur.len++;
		}
		else
		{
			if (cur.base != -1)
			{
				if (best.base == -1 || cur.len > best.len) best = cur;
				cur.base = -1;
			}
		}
	}

	if(cur.base != -1)
	{
		if (best.base == -1 || cur.len > best.len) best = cur;
	}

	if (best.base != -1 && best.len < 2) best.base = -1;

	/*
	* Format the result.
	*/

	tp = tmp;

	for(i = 0; i < (int) ARRAY_SIZE(words); i++)
	{
		/* Are we inside the best run of 0x00's? */

		if (best.base != -1 && i >= best.base && i < (best.base + best.len))
		{
			if (i == best.base)
			*tp++ = ':';
			continue;
		}

		/* Are we following an initial run of 0x00s or any real hex? */

		if (i != 0) *tp++ = ':';

		/* Is this address an encapsulated IPv4? */

		if (i == 6 && best.base == 0 && (best.len == 6
		|| (best.len == 7 && words[7] != 0x0001)
		|| (best.len == 5 && words[5] == 0xffff)))
		{
			int err = inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp));
			if (err) return err;
			tp += strlen(tp);
			break;
		}
		tp += sprintf(tp, "%x", words[i]);
	}

	/* Was it a trailing run of 0x00's? */

	if (best.base != -1 && (best.base + best.len) == ARRAY_SIZE(words))

	*tp++ = ':';
	*tp++ = '\0';

	/*
	* Check for overflow, copy, and we're done.
	*/

	if ((size_t)(tp - tmp) > size)
	{
		return UV_ENOSPC;
	}
	strcpy(dst, tmp);

	return 0;
}

int uv_inet_ntop(int af, const void* src, char* dst, size_t size)
{
	switch(af)
	{
		case AF_INET:
			return (inet_ntop4(src, dst, size));
		case AF_INET6:
			return (inet_ntop6(src, dst, size));
		default:
			return UV_EAFNOSUPPORT;
	}
	/* NOTREACHED */
}

bool hsk_addr_to_string(const hsk_addr_t *addr, char *dst, size_t dst_len, uint16_t fb)
{
	assert(addr && dst);

	int af = hsk_addr_get_af(addr);
	const uint8_t *ip = hsk_addr_get_ip(addr);
	uint16_t port = addr->port;

	if (uv_inet_ntop(af, ip, dst, dst_len) != 0) return false;

	if (fb)
	{
		size_t len = strlen(dst);
		size_t need = af == AF_INET6 ? 9 : 7;

		if (dst_len - len < need) return false;

		if (!port) port = fb;

		char tmp[HSK_MAX_HOST];

		if (af == AF_INET6)
		{
			assert(len + need < HSK_MAX_HOST);
			sprintf(tmp, "[%s]:%u", dst, port);
		}
		else sprintf(tmp, "%s:%u", dst, port);

		strcpy(dst, tmp);
	}

	return true;
}

void hsk_version_msg_print(const hsk_version_msg_t *msg, const char *prefix)
{
	assert(msg);

	char remote[HSK_MAX_HOST];

	assert(hsk_addr_to_string(&msg->remote.addr, remote, HSK_MAX_HOST, 1));

	printf("%sversion msg\n", prefix);
	printf("%s  version=%u\n", prefix, msg->version);
	printf("%s  services=%" PRIu64 "\n", prefix, msg->services);
	printf("%s  time=%" PRIu64 "\n", prefix, msg->time);
	printf("%s  remote=%s\n", prefix, remote);
	printf("%s  nonce=%" PRIu64 "\n", prefix, msg->nonce);
	printf("%s  agent=%s\n", prefix, msg->agent);
	printf("%s  height=%u\n", prefix, msg->height);
	printf("%s  no_relay=%u\n", prefix, (unsigned int)msg->no_relay);
}

bool hsk_verack_msg_read(uint8_t **data, size_t *data_len, hsk_verack_msg_t *msg)
{
	return true;
}

int hsk_verack_msg_write(const hsk_verack_msg_t *msg, uint8_t **data)
{
	return 0;
}

bool hsk_msg_read(uint8_t **data, size_t *data_len, hsk_msg_t *msg)
{
	switch (msg->cmd)
	{
		case HSK_MSG_VERSION:
			return hsk_version_msg_read(data, data_len, (hsk_version_msg_t *)msg);
		case HSK_MSG_VERACK:
			return hsk_verack_msg_read(data, data_len, (hsk_verack_msg_t *)msg);
/*
		case HSK_MSG_PING:
			return hsk_ping_msg_read(data, data_len, (hsk_ping_msg_t *)msg);
		case HSK_MSG_PONG:
			return hsk_pong_msg_read(data, data_len, (hsk_pong_msg_t *)msg);
		case HSK_MSG_GETADDR:
			return hsk_getaddr_msg_read(data, data_len, (hsk_getaddr_msg_t *)msg);
		case HSK_MSG_ADDR:
			return hsk_addr_msg_read(data, data_len, (hsk_addr_msg_t *)msg);
		case HSK_MSG_GETHEADERS:
			return hsk_getheaders_msg_read(data, data_len, (hsk_getheaders_msg_t *)msg);
		case HSK_MSG_HEADERS:
			return hsk_headers_msg_read(data, data_len, (hsk_headers_msg_t *)msg);
		case HSK_MSG_SENDHEADERS:
			return hsk_sendheaders_msg_read(data, data_len, (hsk_sendheaders_msg_t *)msg);
		case HSK_MSG_GETPROOF:
			return hsk_getproof_msg_read(data, data_len, (hsk_getproof_msg_t *)msg);
		case HSK_MSG_PROOF:
			return hsk_proof_msg_read(data, data_len, (hsk_proof_msg_t *)msg);
*/
		default:
			return false;
	}
}

int hsk_msg_write(const hsk_msg_t *msg, uint8_t **data)
{
	switch (msg->cmd)
	{
		case HSK_MSG_VERSION:
			return hsk_version_msg_write((hsk_version_msg_t *)msg, data);
		case HSK_MSG_VERACK:
			return hsk_verack_msg_write((hsk_verack_msg_t *)msg, data);
/*
		case HSK_MSG_PING:
			return hsk_ping_msg_write((hsk_ping_msg_t *)msg, data);
		case HSK_MSG_PONG:
			return hsk_pong_msg_write((hsk_pong_msg_t *)msg, data);
		case HSK_MSG_GETADDR:
			return hsk_getaddr_msg_write((hsk_getaddr_msg_t *)msg, data);
		case HSK_MSG_ADDR:
			return hsk_addr_msg_write((hsk_addr_msg_t *)msg, data);
		case HSK_MSG_GETHEADERS:
			return hsk_getheaders_msg_write((hsk_getheaders_msg_t *)msg, data);
		case HSK_MSG_HEADERS:
			return hsk_headers_msg_write((hsk_headers_msg_t *)msg, data);
		case HSK_MSG_SENDHEADERS:
			return hsk_sendheaders_msg_write((hsk_sendheaders_msg_t *)msg, data);
		case HSK_MSG_GETPROOF:
			return hsk_getproof_msg_write((hsk_getproof_msg_t *)msg, data);
		case HSK_MSG_PROOF:
			return hsk_proof_msg_write((hsk_proof_msg_t *)msg, data);
*/
		default:
			return -1;
	}
}

bool hsk_msg_decode(const uint8_t *data, size_t data_len, hsk_msg_t *msg)
{
	return hsk_msg_read((uint8_t **)&data, &data_len, msg);
}

// TODO: defined, but never called?
int hsk_msg_encode(const hsk_msg_t *msg, uint8_t *data)
{
	return hsk_msg_write(msg, &data);
}

int hsk_msg_size(const hsk_msg_t *msg)
{
	return hsk_msg_write(msg, NULL);
}

static void hsk_peer_log(hsk_peer_t *peer, const char *fmt, ...)
{
	printf("peer %" PRIu64 " (%s): ", peer->id, peer->host);

	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

/* From map.c */

#define __hsk_fsize(m) ((m) < 16 ? 1 : (m) >> 4)
#define __hsk_iseither(f, i) ((f[i >> 4] >> ((i & 0xfu) << 1)) & 3)
#define hsk_map_exists(map, i) (!__hsk_iseither((map)->flags, (i)))

void hsk_map_reset(hsk_map_t *map)
{
  if (map && map->flags)
  {
    memset(map->flags, 0xaa, __hsk_fsize(map->n_buckets) * sizeof(uint32_t));

    map->size = 0;
    map->n_occupied = 0;
  }
}

void hsk_map_clear(hsk_map_t *map)
{
  if (map->is_map && map->free_func)
  {
    uint32_t k;

    for (k = 0; k < map->n_buckets; k++)
    {
      if (!hsk_map_exists(map, k)) continue;

      void *value = map->vals[k];

      if (value) map->free_func(value);
    }
  }

  hsk_map_reset(map);
}

void hsk_map_uninit(hsk_map_t *map)
{
  if (!map) return;

  hsk_map_clear(map);

  if (map->keys)
  {
    free(map->keys);
    map->keys = NULL;
  }

  if (map->flags)
  {
    free(map->flags);
    map->flags = NULL;
  }

  if (map->vals)
  {
    free(map->vals);
    map->vals = NULL;
  }
}

static void hsk_peer_uninit(hsk_peer_t *peer)
{
  if (!peer) return;

/*
  if (peer->brontide != NULL)
  {
    hsk_brontide_uninit(peer->brontide);
    free(peer->brontide);
    peer->brontide = NULL;
  }
*/

  hsk_map_uninit(&peer->names);

  if (peer->msg)
  {
    free(peer->msg);
    peer->msg = NULL;
  }
}

static void hsk_peer_free(hsk_peer_t *peer)
{
  if (!peer) return;

  hsk_peer_uninit(peer);

  free(peer);
}

static void after_close(uv_handle_t *handle)
{
	hsk_peer_t *peer = (hsk_peer_t *)handle->data;
	assert(peer);
	handle->data = NULL;
	peer->state = HSK_STATE_DISCONNECTED;
	hsk_peer_log(peer, "closed peer\n");
	hsk_peer_free(peer);
}

#define __hsk_isempty(f, i) ((f[i >> 4] >> ((i & 0xfu) << 1)) & 2)
#define __hsk_isdel(f, i) ((f[i >> 4] >> ((i & 0xfu) << 1)) & 1)
#define __hsk_set_isdel_true(f, i) (f[i >> 4] |= 1ul << ((i & 0xfu) << 1))

uint32_t hsk_map_lookup(const hsk_map_t *map, const void *key)
{
  if (map->n_buckets == 0) return 0;

  uint32_t step = 0;
  uint32_t mask = map->n_buckets - 1;
  uint32_t k = map->hash_func(key);
  uint32_t i = k & mask;
  uint32_t last = i;

  while (!__hsk_isempty(map->flags, i)
  && (__hsk_isdel(map->flags, i) || !map->equal_func(map->keys[i], key)))
  {
    i = (i + (++step)) & mask;
    if (i == last) return map->n_buckets;
  }

  return __hsk_iseither(map->flags, i) ? map->n_buckets : i;
}

void hsk_map_delete(hsk_map_t *map, uint32_t x)
{
  if (x != map->n_buckets && !__hsk_iseither(map->flags, x))
  {
    __hsk_set_isdel_true(map->flags, x);
    map->size -= 1;
  }
}

#define hsk_map_exists(map, i) (!__hsk_iseither((map)->flags, (i)))

bool hsk_map_del(hsk_map_t *map, const void *key)
{
  uint32_t k = hsk_map_lookup(map, key);

  if (k == map->n_buckets) return false;

  if (!hsk_map_exists(map, k)) return false;

  hsk_map_delete(map, k);

  return true;
}

static void hsk_peer_remove(hsk_peer_t *peer)
{
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (!peer) return;

  if (!pool->head) return;

  if (pool->head == peer)
  {
    if (pool->tail == peer) pool->tail = NULL;
    pool->head = peer->next;
    peer->next = NULL;
    assert(pool->size > 0);
    pool->size -= 1;
    assert(hsk_map_del(&pool->peers, &peer->addr));
    return;
  }

  hsk_peer_t *prev;

  // O(n), but who cares.
  for (prev = pool->head; prev; prev = prev->next)
  {
    if (prev->next == peer) break;
  }

  if (!prev) return;

  if (pool->tail == peer) pool->tail = prev;

  prev->next = peer->next;

  assert(pool->size > 0);
  pool->size -= 1;

  assert(hsk_map_del(&pool->peers, &peer->addr));
}

typedef uint32_t hsk_map_iter_t;

#define hsk_map_begin(map) ((hsk_map_iter_t)0)
#define hsk_map_end(map) ((map)->n_buckets)
#define hsk_map_exists(map, i) (!__hsk_iseither((map)->flags, (i)))
#define hsk_map_key(map, i) ((map)->keys[i])
#define hsk_map_value(map, i) ((map)->vals[i])

static void hsk_peer_timeout_reqs(hsk_peer_t *peer)
{
  hsk_map_t *map = &peer->names;
  hsk_map_iter_t i;

  for (i = hsk_map_begin(map); i != hsk_map_end(map); i++)
  {
    if (!hsk_map_exists(map, i)) continue;

    hsk_name_req_t *req = (hsk_name_req_t *)hsk_map_value(map, i);
    hsk_name_req_t *next;

    assert(req);

    hsk_map_delete(map, i);

    for (; req; req = next)
    {
      next = req->next;
      req->callback( req->name, HSK_ETIMEOUT, false, NULL, 0, req->arg);
      free(req);
    }
  }

  hsk_map_reset(map);
}

static int hsk_peer_close(hsk_peer_t *peer)
{
  switch (peer->state) {
    case HSK_STATE_DISCONNECTING:
      return HSK_SUCCESS;
    case HSK_STATE_HANDSHAKE:
/*
      if (peer->brontide != NULL)
        hsk_brontide_destroy(peer->brontide);
*/
    case HSK_STATE_READING:
      assert(uv_read_stop((uv_stream_t *)&peer->socket) == 0);
    case HSK_STATE_CONNECTED:
    case HSK_STATE_CONNECTING:
      uv_close((uv_handle_t *)&peer->socket, after_close);
      hsk_peer_log(peer, "closing peer\n");
      break;
    case HSK_STATE_DISCONNECTED:
      hsk_peer_log(peer, "closed peer (never opened)\n");
      hsk_peer_remove(peer);
      hsk_peer_free(peer);
      return HSK_SUCCESS;
    default:
      assert(false);
      break;
  }

  peer->state = HSK_STATE_DISCONNECTING;
  // hsk_pool_merge_reqs(peer->pool, &peer->names);
  hsk_peer_timeout_reqs(peer);
  hsk_peer_remove(peer);

  return HSK_SUCCESS;
}

static int hsk_peer_destroy(hsk_peer_t *peer)
{
	return hsk_peer_close(peer);
}

static void after_write(uv_write_t *req, int status)
{
  hsk_write_data_t *wd = (hsk_write_data_t *)req->data;
  hsk_peer_t *peer = wd->peer;

  if (wd->data && wd->should_free)
  {
    free(wd->data);
    wd->data = NULL;
  }

  free(wd);
  req->data = NULL;

  free(req);

  if (status != 0)
  {
    hsk_peer_log(peer, "write error: %s\n", uv_strerror(status));
    hsk_peer_destroy(peer);
    return;
  }
}

int64_t hsk_now(void)
{
  time_t n = time(NULL);
  assert(n >= 0);
  return (int64_t)n;
}

static int hsk_peer_write_raw(hsk_peer_t *peer, uint8_t *data, size_t data_len, bool should_free)
{
  if (peer->state == HSK_STATE_DISCONNECTING)
    return HSK_SUCCESS;

  int rc = HSK_SUCCESS;
  hsk_write_data_t *wd = NULL;
  uv_write_t *req = NULL;

  wd = (hsk_write_data_t *)malloc(sizeof(hsk_write_data_t));

  if (!wd)
  {
    rc = HSK_ENOMEM;
    goto fail;
  }

  req = (uv_write_t *)malloc(sizeof(uv_write_t));

  if (!req)
  {
    rc = HSK_ENOMEM;
    goto fail;
  }

  wd->peer = peer;
  wd->data = (void *)data;
  wd->should_free = should_free;

  req->data = (void *)wd;

  uv_stream_t *stream = (uv_stream_t *)&peer->socket;

  uv_buf_t bufs[] =
  {
    { .base = (char *)data, .len = data_len }
  };

  int status = uv_write(req, stream, bufs, 1, after_write);

  if (status != 0)
  {
    hsk_peer_log(peer, "failed writing: %s\n", uv_strerror(status));
    hsk_peer_destroy(peer);
    rc = HSK_EFAILURE;
    goto fail;
  }

  peer->last_send = hsk_now();

  return rc;

fail:
  if (wd) free(wd);
  if (req) free(req);
  if (data && should_free) free(data);

  return rc;
}

static int hsk_peer_write(hsk_peer_t *peer, uint8_t *data, size_t data_len, bool should_free)
{
  if (peer->state != HSK_STATE_HANDSHAKE) return HSK_SUCCESS;

  assert(should_free);

  int rc;
/*
  if (peer->brontide != NULL)
  {
    rc = hsk_brontide_write(peer->brontide, data, data_len);
  }
  else
  {
*/
    rc = hsk_peer_write_raw(peer, data, data_len, true);
/*
 }
*/
  return rc;
}

static int hsk_peer_send(hsk_peer_t *peer, const hsk_msg_t *msg)
{
  int msg_size = hsk_msg_size(msg);
  assert(msg_size != -1);

  size_t size = 9 + msg_size;
  uint8_t *data = malloc(size);

  if (!data) return HSK_ENOMEM;

  uint8_t *buf = data;

  // Magic Number
  write_u32(&buf, HSK_MAGIC);

  // Command
  write_u8(&buf, msg->cmd);

  // Msg Size
  write_u32(&buf, msg_size);

  // Msg
  hsk_msg_write(msg, &buf);

  return hsk_peer_write(peer, data, size, true);
}

int64_t hsk_timedata_now(hsk_timedata_t *td)
{
  return hsk_now() + td->offset;
}

void *hsk_map_get(const hsk_map_t *map, const void *key)
{
  uint32_t k = hsk_map_lookup(map, key);

  if (k == map->n_buckets) return NULL;

  if (!hsk_map_exists(map, k)) return NULL;

  return map->vals[k];
}

const hsk_addrentry_t *hsk_addrman_get(const hsk_addrman_t *am, const hsk_addr_t *addr)
{
  return hsk_map_get(&am->map, addr);
}

void hsk_addr_copy(hsk_addr_t *addr, const hsk_addr_t *other)
{
  assert(addr && other);
  memcpy((void *)addr, (void *)other, sizeof(hsk_addr_t));
}

// Taken from:
// https://github.com/wahern/dns/blob/master/src/dns.c
#ifndef _HSK_RANDOM
#if defined(HAVE_ARC4RANDOM)  \
  || defined(__OpenBSD__)     \
  || defined(__FreeBSD__)     \
  || defined(__NetBSD__)      \
  || defined(__APPLE__)
#define _HSK_RANDOM arc4random
#elif defined(__linux)
#define _HSK_RANDOM random
#else
#define _HSK_RANDOM rand
#endif
#endif

uint32_t hsk_random(void)
{
	// RAND_MAX may be only 0x7fff on Windows.
	// Double up to guarantee 32 bits of randomness.
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/rand-max
	uint32_t n = _HSK_RANDOM();
	return (n << 16) ^ _HSK_RANDOM();
}

uint64_t hsk_nonce(void)
{
	return (((uint64_t)hsk_random()) << 32) + hsk_random();
}

static int hsk_peer_send_version(hsk_peer_t *peer)
{
	hsk_peer_log(peer, "sending version\n");
	hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

	hsk_version_msg_t msg = { .cmd = HSK_MSG_VERSION };
	hsk_msg_init((hsk_msg_t *)&msg);

	msg.version = HSK_PROTO_VERSION;
	msg.services = HSK_SERVICES;
	msg.time = hsk_timedata_now(&pool->td);

	const hsk_addrentry_t *entry = hsk_addrman_get(&pool->am, &peer->addr);

	if (entry)
	{
		msg.remote.time = entry->time;
		msg.remote.services = entry->services;
	}

	hsk_addr_copy(&msg.remote.addr, &peer->addr);

	msg.nonce = hsk_nonce();
	strcpy(msg.agent, pool->user_agent);
	msg.height = (uint32_t)pool->chain.height;

	peer->version_time = hsk_now();

	return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int hsk_peer_send_verack(hsk_peer_t *peer)
{
  hsk_peer_log(peer, "sending verack\n");
  hsk_version_msg_t msg = { .cmd = HSK_MSG_VERACK };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int hsk_peer_send_ping(hsk_peer_t *peer, uint64_t nonce)
{
  hsk_ping_msg_t msg =
  {
    .cmd = HSK_MSG_PING,
    .nonce = nonce
  };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int hsk_peer_send_pong(hsk_peer_t *peer, uint64_t nonce)
{
  hsk_pong_msg_t msg =
  {
    .cmd = HSK_MSG_PONG,
    .nonce = nonce
  };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

static int hsk_peer_send_sendheaders(hsk_peer_t *peer)
{
  hsk_peer_log(peer, "sending sendheaders\n");
  hsk_version_msg_t msg = { .cmd = HSK_MSG_SENDHEADERS };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

#define hsk_sha3_max_permutation_size 25
#define hsk_sha3_max_rate_in_qwords 24

static int hsk_peer_send_getaddr(hsk_peer_t *peer)
{
  hsk_peer_log(peer, "sending getaddr\n");
  hsk_version_msg_t msg = { .cmd = HSK_MSG_GETADDR };
  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

enum hsk_blake2b_constant {
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

typedef struct hsk_sha3_ctx
{
  uint64_t hash[hsk_sha3_max_permutation_size];
  uint64_t message[hsk_sha3_max_rate_in_qwords];
  unsigned rest;
  unsigned block_size;
} hsk_sha3_ctx;

void hsk_header_padding(const hsk_header_t *hdr, uint8_t *pad, size_t size)
{
  assert(hdr && pad);

  size_t i;

  for (i = 0; i < size; i++) pad[i] = hdr->prev_block[i % 32] ^ hdr->name_root[i % 32];
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

static const uint64_t hsk_blake2b_IV[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

#if defined(_MSC_VER)
#define HSK_BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define HSK_BLAKE2_PACKED(x) x __attribute__((packed))
#endif

HSK_BLAKE2_PACKED(struct hsk_blake2b_param__ {
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

static void hsk_blake2b_compress( hsk_blake2b_ctx *ctx, const uint8_t block[HSK_BLAKE2B_BLOCKBYTES])
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

  for (i = 0; i < 8; i++)
    ctx->h[i] = ctx->h[i] ^ v[i] ^ v[i + 8];
}

#undef G
#undef ROUND

int hsk_blake2b_update(hsk_blake2b_ctx *ctx, const void *pin, size_t inlen)
{
  const unsigned char * in = (const unsigned char *)pin;

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

static int hsk_blake2b_is_lastblock(const hsk_blake2b_ctx *ctx)
{
  return ctx->f[0] != 0;
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

/* prevents compiler optimizing out memset() */
static HSK_BLAKE2_INLINE void secure_zero_memory(void *v, size_t n)
{
  static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
  memset_v(v, 0, n);
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

int hsk_header_pre_encode(const hsk_header_t *hdr, uint8_t *data)
{
  return hsk_header_pre_write(hdr, &data);
}

int hsk_header_pre_size(const hsk_header_t *hdr)
{
  return hsk_header_pre_write(hdr, NULL);
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

#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))

static void
hsk_keccak_theta(uint64_t *A) {
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

#define HSK_SHA3_ROUNDS 24
#define HSK_SHA3_FINALIZED 0x80000000

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

#ifdef HSK_BIG_ENDIAN
#define le2me_64(x) bswap_64(x)
#define me64_to_le_str(to, from, length) \
  swap_copy_u64_to_str((to), (from), (length))
#else
#define le2me_64(x) (x)
#define me64_to_le_str(to, from, length) \
  memcpy((to), (from), (length))
#endif

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

#define IS_ALIGNED_64(p) (0 == (7 & ((const char *)(p) - (const char *)0)))

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
  if (hdr->cache) return hdr->hash;

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
  int i;
  for (i = 0; i < 32; i++) hdr->hash[i] ^= hdr->mask[i];

  hdr->cache = true;

  return hdr->hash;
}

void hsk_header_hash(hsk_header_t *hdr, uint8_t *hash)
{
  memcpy(hash, hsk_header_cache(hdr), 32);
}

hsk_header_t *hsk_chain_get_by_height(const hsk_chain_t *chain, uint32_t height)
{
  return hsk_map_get(&chain->heights, &height);
}

void hsk_chain_get_locator(const hsk_chain_t *chain, hsk_getheaders_msg_t *msg)
{
  assert(chain && msg);

  int i = 0;
  hsk_header_t *tip = chain->tip;
  int64_t height = chain->height;
  int64_t step = 1;

  hsk_header_hash(tip, msg->hashes[i++]);

  while (height > 0)
  {
    height -= step;

    if (height < 0) height = 0;

    if (i > 10) step *= 2;

    if (i == sizeof(msg->hashes) - 1) height = 0;

    hsk_header_t *hdr = hsk_chain_get_by_height(chain, (uint32_t)height);

    // Due to checkpoint initialization
    // we may not have any headers from here
    // down to genesis
    if (!hdr) continue;

    hsk_header_hash(hdr, msg->hashes[i++]);
  }

  msg->hash_count = i;
}

static int hsk_peer_send_getheaders(hsk_peer_t *peer, const uint8_t *stop)
{
  hsk_peer_log(peer, "sending getheaders\n");
  hsk_getheaders_msg_t msg = { .cmd = HSK_MSG_GETHEADERS };

  hsk_msg_init((hsk_msg_t *)&msg);

  hsk_chain_get_locator(peer->chain, &msg);

  if (stop) memcpy(msg.stop, stop, 32);

  peer->getheaders_time = hsk_now();

  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}

/*
static int hsk_peer_send_getproof(hsk_peer_t *peer, const uint8_t *name_hash, const uint8_t *root)
{
  hsk_getproof_msg_t msg = { .cmd = HSK_MSG_GETPROOF };
  hsk_msg_init((hsk_msg_t *)&msg);

  memcpy(msg.key, name_hash, 32);
  memcpy(msg.root, root, 32);

  return hsk_peer_send(peer, (hsk_msg_t *)&msg);
}
*/

bool hsk_map_has(const hsk_map_t *map, const void *key)
{
  uint32_t k = hsk_map_lookup(map, key);

  if (k == map->n_buckets) return false;
  if (!hsk_map_exists(map, k)) return false;

  return true;
}

hsk_addr_t *hsk_addr_alloc(void)
{
  hsk_addr_t *addr = (hsk_addr_t *)malloc(sizeof(hsk_addr_t));
  if (addr) hsk_addr_init(addr);
  return addr;
}

hsk_addr_t *hsk_addr_clone(const hsk_addr_t *other)
{
  assert(other);

  hsk_addr_t *addr = hsk_addr_alloc();

  if (!addr) return NULL;

  hsk_addr_copy(addr, other);

  return addr;
}

#define __hsk_roundup32(x) \
  do {                     \
    --(x);                 \
    (x) |= (x) >> 1;       \
    (x) |= (x) >> 2;       \
    (x) |= (x) >> 4;       \
    (x) |= (x) >> 8;       \
    (x) |= (x) >> 16;      \
    ++(x);                 \
  } while (0)

static const double __hsk_hash_upper = 0.77;

#define __hsk_set_isempty_false(f, i) (f[i >> 4] &= ~(2ul << ((i & 0xfu) << 1)))

int hsk_map_resize(hsk_map_t *map, uint32_t new_n_buckets)
{
  // This function uses 0.25*n_buckets bytes of working space
  // instead of [sizeof(key_t+val_t)+.25]*n_buckets.

  uint32_t *new_flags = 0;
  uint32_t j = 1;

  {
    __hsk_roundup32(new_n_buckets);

    if (new_n_buckets < 4)
      new_n_buckets = 4;

    if (map->size >= (uint32_t)(new_n_buckets * __hsk_hash_upper + 0.5)) {
      // requested size is too small
      j = 0;
    } else {
      // hash table size to be changed (shrink or expand); rehash
      new_flags = (uint32_t *)malloc(
        __hsk_fsize(new_n_buckets) * sizeof(uint32_t));

      if (!new_flags)
        return -1;

      memset(new_flags, 0xaa,
        __hsk_fsize(new_n_buckets) * sizeof(uint32_t));

      if (map->n_buckets < new_n_buckets) {  /* expand */
        void **new_keys = (void **)realloc(
          map->keys, new_n_buckets * sizeof(void *));

        if (!new_keys) {
          free(new_flags);
          return -1;
        }

        map->keys = new_keys;

        if (map->is_map) {
          void **new_vals = (void **)realloc(
            (void *)map->vals, new_n_buckets * sizeof(void *));

          if (!new_vals) {
            free(new_flags);
            return -1;
          }

          map->vals = new_vals;
        }
      }
      // otherwise shrink
    }
  }

  if (j) {
    // rehashing is needed
    for (j = 0; j < map->n_buckets; j++) {
      if (__hsk_iseither(map->flags, j) == 0) {
        uint32_t new_mask = new_n_buckets - 1;
        void *key = map->keys[j];
        void *val = NULL;

        if (map->is_map)
          val = map->vals[j];

        __hsk_set_isdel_true(map->flags, j);

        // kick-out process; sort of like in cuckoo hashing
        for (;;) {
          uint32_t k = map->hash_func(key);
          uint32_t i = k & new_mask;
          uint32_t step = 0;

          while (!__hsk_isempty(new_flags, i))
            i = (i + (++step)) & new_mask;

          __hsk_set_isempty_false(new_flags, i);

          // kick out the existing element
          if (i < map->n_buckets && __hsk_iseither(map->flags, i) == 0) {
            {
              void *tmp = map->keys[i];
              map->keys[i] = key;
              key = tmp;
            }

            if (map->is_map) {
              void *tmp = map->vals[i];
              map->vals[i] = val;
              val = tmp;
            }

            // mark it as deleted in the old hash table
            __hsk_set_isdel_true(map->flags, i);
          } else {
            // write the element and jump out of the loop
            map->keys[i] = key;
            if (map->is_map)
              map->vals[i] = val;
            break;
          }
        }
      }
    }

    // shrink the hash table
    if (map->n_buckets > new_n_buckets) {
      map->keys = (void **)realloc(
        (void *)map->keys, new_n_buckets * sizeof(void *));

      if (map->is_map) {
        map->vals = (void **)realloc(
          (void *)map->vals, new_n_buckets * sizeof(void *));
      }
    }

    // free the working space
    free(map->flags);
    map->flags = new_flags;
    map->n_buckets = new_n_buckets;
    map->n_occupied = map->size;
    map->upper_bound = (uint32_t)(map->n_buckets * __hsk_hash_upper + 0.5);
  }

  return 0;
}

#define __hsk_set_isboth_false(f, i) (f[i >> 4] &= ~(3ul << ((i & 0xfu) << 1)))

uint32_t hsk_map_put(hsk_map_t *map, const void *key, int *ret)
{
  uint32_t x;

  // update the hash table
  if (map->n_occupied >= map->upper_bound)
  {
    if (map->n_buckets > (map->size << 1))
    {
      // clear "deleted" elements
      if (hsk_map_resize(map, map->n_buckets - 1) < 0)
      {
        if (ret) *ret = -1;
        return map->n_buckets;
      }
    }
    else if (hsk_map_resize(map, map->n_buckets + 1) < 0)
    {
      // expand the hash table
      if (ret) *ret = -1;
      return map->n_buckets;
    }
  }

  // TODO: to implement automatically shrinking
  // resize() already support shrinking

  {
    uint32_t mask = map->n_buckets - 1;
    uint32_t step = 0;
    uint32_t site = map->n_buckets;
    uint32_t k = map->hash_func(key);
    uint32_t i = k & mask;
    uint32_t last;

    x = map->n_buckets;

    if (__hsk_isempty(map->flags, i))
    {
      // for speed up
      x = i;
    }
    else
    {
      last = i;

      while (!__hsk_isempty(map->flags, i)
      && (__hsk_isdel(map->flags, i) || !map->equal_func(map->keys[i], key)))
      {
        if (__hsk_isdel(map->flags, i)) site = i;

        i = (i + (++step)) & mask;

        if (i == last)
	{
          x = site;
          break;
        }
      }

      if (x == map->n_buckets)
      {
        if (__hsk_isempty(map->flags, i) && site != map->n_buckets)
          x = site;
        else
          x = i;
      }
    }
  }

  if (__hsk_isempty(map->flags, x))
  {
    // not present at all
    map->keys[x] = (void *)key;
    __hsk_set_isboth_false(map->flags, x);
    map->size += 1;
    map->n_occupied += 1;
    if (ret)
      *ret = 1;
  } else if (__hsk_isdel(map->flags, x)) {
    // deleted
    map->keys[x] = (void *)key;
    __hsk_set_isboth_false(map->flags, x);
    map->size += 1;
    if (ret)
      *ret = 2;
  } else {
    // present and not deleted
    map->keys[x] = (void *)key;
    if (ret)
      *ret = 0;
  }

  return x;
}

bool hsk_map_set(hsk_map_t *map, const void *key, void *value)
{
  int ret;
  uint32_t k = hsk_map_put(map, key, &ret);

  if (ret == -1) return false;

  map->vals[k] = value;

  return true;
}

static void hsk_timedata_insert(hsk_timedata_t *td, int64_t sample)
{
  int start = 0;
  int end = td->sample_len - 1;
  int i = -1;

  while (start <= end)
  {
    int pos = (start + end) >> 1;
    int64_t cmp = td->samples[pos] - sample;

    if (cmp == 0)
    {
      i = pos;
      break;
    }

    if (cmp < 0) start = pos + 1;
    else end = pos - 1;
  }

  if (i == -1)
    i = start;

  assert(td->sample_len + 1 <= HSK_TIMEDATA_LIMIT);

  int j;
  for (j = i + 1; j < td->sample_len + 1; j++)
    td->samples[j] = td->samples[j - 1];

  td->samples[i] = sample;
  td->sample_len += 1;
}

static void hsk_timedata_log(hsk_timedata_t *td, const char *fmt, ...)
{
  printf("timedata: ");

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

int hsk_timedata_add(hsk_timedata_t *td, const hsk_addr_t *addr, int64_t time)
{
  if (td->sample_len >= HSK_TIMEDATA_LIMIT) return HSK_SUCCESS;

  if (hsk_map_has(&td->known, addr)) return HSK_SUCCESS;

  hsk_addr_t *id = hsk_addr_clone(addr);

  if (!id) return HSK_ENOMEM;

  if (!hsk_map_set(&td->known, (void *)id, (void *)id))
  {
    free(id);
    return HSK_ENOMEM;
  }

  int64_t sample = time - hsk_now();

  hsk_timedata_insert(td, sample);

  if (td->sample_len >= 5 && (td->sample_len % 2) == 1)
  {
    int64_t median = td->samples[td->sample_len >> 1];

    if (median < 0)
      median = -median;

    if (median >= 70 * 60) {
      if (!td->checked) {
        bool match = false;
        int i;

        for (i = 0; i < td->sample_len; i++) {
          int64_t offset = td->samples[i];

          if (offset < 0)
            offset = -offset;

          if (offset != 0 && offset < 5 * 60) {
            match = true;
            break;
          }
        }

        if (!match) {
          td->checked = true;
          hsk_timedata_log(td, "WARNING: timing mismatch!");
        }
      }

      median = 0;
    }

    td->offset = median;

    hsk_timedata_log(td, "added new time sample\n");
    hsk_timedata_log(td, "  new adjusted time: %" PRId64 "\n", hsk_timedata_now(td));
    hsk_timedata_log(td, "  offset: %" PRId64 "\n", td->offset);
  }

  return HSK_SUCCESS;
}

bool hsk_addrman_mark_ack(hsk_addrman_t *am, const hsk_addr_t *addr, uint64_t services)
{
  hsk_addrentry_t *entry = hsk_map_get(&am->map, addr);

  if (!entry) return false;

  int64_t now = hsk_timedata_now(am->td);

  entry->services |= services;

  entry->last_success = now;
  entry->last_attempt = now;
  entry->attempts = 0;
  entry->used = true;

  return true;
}

static int hsk_peer_handle_version(hsk_peer_t *peer, const hsk_version_msg_t *msg)
{
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  hsk_peer_log(peer, "received version: %s (%u)\n", msg->agent, msg->height);
  peer->height = (int64_t)msg->height;
  strcpy(peer->agent, msg->agent);

  hsk_timedata_add(&pool->td, &peer->addr, msg->time);
  hsk_addrman_mark_ack(&pool->am, &peer->addr, msg->services);

  hsk_peer_send_verack(peer);

  // At this point, we've sent a version and received VERACK.
  // The peer sent us their version and we sent back a VERACK.
  // The handshake is complete, start syncing.
  int rc = hsk_peer_send_sendheaders(peer);

  if (rc != HSK_SUCCESS) return rc;

  // Discover more peers
  rc = hsk_peer_send_getaddr(peer);

  if (rc != HSK_SUCCESS) return rc;

  // Start syncing
  return hsk_peer_send_getheaders(peer, NULL);
}

static int hsk_peer_handle_verack(hsk_peer_t *peer, const hsk_verack_msg_t *msg)
{
  hsk_peer_log(peer, "received verack\n");

  peer->version_time = 0;

  // VERACK is boring, no need to respond.
  return HSK_SUCCESS;
}

static int hsk_peer_handle_ping(hsk_peer_t *peer, const hsk_ping_msg_t *msg)
{
  return hsk_peer_send_pong(peer, msg->nonce);
}

#ifdef HSK_DEBUG_LOG
#define hsk_pool_debug hsk_pool_log
#define hsk_peer_debug hsk_peer_log
#else
#define hsk_pool_debug(...) do {} while (0)
#define hsk_peer_debug(...) do {} while (0)
#endif

static int hsk_peer_handle_pong(hsk_peer_t *peer, const hsk_pong_msg_t *msg)
{
  if (!peer->challenge)
  {
    hsk_peer_log(peer, "peer sent an unsolicited pong\n");
    return HSK_SUCCESS;
  }

  if (msg->nonce != peer->challenge)
  {
    if (msg->nonce == 0)
    {
      hsk_peer_log(peer, "peer sent a zero nonce\n");
      peer->challenge = 0;
      return HSK_SUCCESS;
    }
    hsk_peer_log(peer, "peer sent the wrong nonce\n");
    return HSK_SUCCESS;
  }

  hsk_peer_debug(peer, "received pong\n");

  int64_t now = hsk_now();

  if (now >= peer->last_ping)
  {
    int64_t min = now - peer->last_ping;
    peer->last_pong = now;
    if (!peer->min_ping)
      peer->min_ping = min;
    peer->min_ping = peer->min_ping < min ? peer->min_ping : min;
  }
  else
  {
    hsk_peer_log(peer, "timing mismatch\n");
  }

  peer->challenge = 0;

  return HSK_SUCCESS;
}

bool
hsk_addr_is_ip4(const hsk_addr_t *addr) {
  assert(addr);
  return hsk_addr_is_mapped(addr);
}

bool hsk_addr_is_rfc1918(const hsk_addr_t *addr)
{
  assert(addr);

  if (!hsk_addr_is_ip4(addr)) return false;
  if (addr->ip[12] == 10) return true;
  if (addr->ip[12] == 192 && addr->ip[13] == 168) return true;
  if (addr->ip[12] == 172 && (addr->ip[13] >= 16 && addr->ip[13] <= 31)) return true;

  return false;
}

bool hsk_addr_is_rfc2544(const hsk_addr_t *addr)
{
  assert(addr);

  if (!hsk_addr_is_ip4(addr)) return false;
  if (addr->ip[12] == 198 && (addr->ip[13] == 18 || addr->ip[13] == 19)) return true;
  if (addr->ip[12] == 169 && addr->ip[13] == 254) return true;

  return false;
}

bool hsk_addr_is_rfc3927(const hsk_addr_t *addr)
{
  assert(addr);

  if (!hsk_addr_is_ip4(addr)) return false;
  if (addr->ip[12] == 169 && addr->ip[13] == 254) return true;
  return false;
}

bool hsk_addr_is_rfc6598(const hsk_addr_t *addr)
{
  assert(addr);

  if (!hsk_addr_is_ip4(addr)) return false;

  if (addr->ip[12] == 100 && (addr->ip[13] >= 64 && addr->ip[13] <= 127)) return true;

  return false;
}

bool hsk_addr_is_rfc5737(const hsk_addr_t *addr)
{
  assert(addr);

  if (!hsk_addr_is_ip4(addr)) return false;
  if (addr->ip[12] == 192 && (addr->ip[13] == 0 && addr->ip[14] == 2)) return true;
  if (addr->ip[12] == 198 && addr->ip[13] == 51 && addr->ip[14] == 100) return true;
  if (addr->ip[12] == 203 && addr->ip[13] == 0 && addr->ip[14] == 113) return true;

  return false;
}

bool hsk_addr_is_rfc3849(const hsk_addr_t *addr)
{
  assert(addr);

  if (addr->ip[0] == 0x20 && addr->ip[1] == 0x01 && addr->ip[2] == 0x0d && addr->ip[3] == 0xb8) return true;

  return false;
}

bool hsk_addr_is_rfc3964(const hsk_addr_t *addr) {
  assert(addr);

  if (addr->ip[0] == 0x20 && addr->ip[1] == 0x02)
    return true;

  return false;
}

static const uint8_t hsk_rfc6052[12] = {
  0x00, 0x64, 0xff, 0x9b,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static const uint8_t hsk_rfc4862[8] = {
  0xfe, 0x80, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static const uint8_t hsk_rfc6145[12] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0xff, 0xff, 0x00, 0x00
};

bool
hsk_addr_is_rfc6052(const hsk_addr_t *addr) {
  assert(addr);
  return memcmp(addr->ip, hsk_rfc6052, sizeof(hsk_rfc6052)) == 0;
}

bool
hsk_addr_is_rfc4380(const hsk_addr_t *addr) {
  assert(addr);

  if (addr->ip[0] == 0x20 && addr->ip[1] == 0x01
      && addr->ip[2] == 0x00 && addr->ip[3] == 0x00) {
    return true;
  }

  return false;
}

bool
hsk_addr_is_rfc4862(const hsk_addr_t *addr) {
  assert(addr);
  return memcmp(addr->ip, hsk_rfc4862, sizeof(hsk_rfc4862)) == 0;
}

bool
hsk_addr_is_rfc4193(const hsk_addr_t *addr) {
  assert(addr);

  if ((addr->ip[0] & 0xfe) == 0xfc)
    return true;

  return false;
}

bool
hsk_addr_is_rfc6145(const hsk_addr_t *addr) {
  assert(addr);
  return memcmp(addr->ip, hsk_rfc6145, sizeof(hsk_rfc6145)) == 0;
}

bool
hsk_addr_is_rfc4843(const hsk_addr_t *addr) {
  assert(addr);

  if (addr->ip[0] == 0x20 && addr->ip[1] == 0x01
      && addr->ip[2] == 0x00 && (addr->ip[3] & 0xf0) == 0x10) {
    return true;
  }

  return false;
}

static const uint8_t hsk_local_ip[16] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01
};

bool
hsk_addr_is_local(const hsk_addr_t *addr) {
  assert(addr);

  if (hsk_addr_is_ip4(addr)) {
    if (addr->ip[12] == 127 && addr->ip[13] == 0)
      return true;
    return false;
  }

  if (memcmp(addr->ip, hsk_local_ip, sizeof(hsk_local_ip)) == 0)
    return true;

  return false;
}

static const uint8_t hsk_shifted[9] =
{
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0xff,
  0xff
};

static const uint8_t hsk_zero_ip[16] =
{
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

bool hsk_addr_is_null(const hsk_addr_t *addr)
{
  assert(addr);

  if (hsk_addr_is_ip4(addr))
  {
    // 0.0.0.0
    return addr->ip[12] == 0
        && addr->ip[13] == 0
        && addr->ip[14] == 0
        && addr->ip[15] == 0;
  }

  // ::
  return memcmp(addr->ip, hsk_zero_ip, 16) == 0;
}

bool hsk_addr_is_broadcast(const hsk_addr_t *addr)
{
  assert(addr);

  if (!hsk_addr_is_ip4(addr)) return false;

  // 255.255.255.255
  return addr->ip[12] == 255
      && addr->ip[13] == 255
      && addr->ip[14] == 255
      && addr->ip[15] == 255;
}

bool hsk_addr_is_valid(const hsk_addr_t *addr)
{
  assert(addr);

  if (addr->type != 0) return false;
  if (memcmp(addr->ip, hsk_shifted, sizeof(hsk_shifted)) == 0) return false;
  if (hsk_addr_is_null(addr)) return false;
  if (hsk_addr_is_broadcast(addr)) return false;
  if (hsk_addr_is_rfc3849(addr)) return false;

  return true;
}

bool hsk_addr_is_routable(const hsk_addr_t *addr)
{
  assert(addr);

  if (!hsk_addr_is_valid(addr)) return false;
  if (hsk_addr_is_rfc1918(addr)) return false;
  if (hsk_addr_is_rfc2544(addr)) return false;
  if (hsk_addr_is_rfc3927(addr)) return false;
  if (hsk_addr_is_rfc4862(addr)) return false;
  if (hsk_addr_is_rfc6598(addr)) return false;
  if (hsk_addr_is_rfc5737(addr)) return false;
  if (hsk_addr_is_rfc4193(addr) && !hsk_addr_is_onion(addr)) return false;
  if (hsk_addr_is_rfc4843(addr)) return false;
  if (hsk_addr_is_local(addr)) return false;

  return true;
}

static const uint8_t hsk_zero_pub[33] =
{
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00
};

bool hsk_addr_has_key(const hsk_addr_t *addr)
{
  assert(addr);
  return memcmp(addr->key, (void *)hsk_zero_pub, sizeof(hsk_zero_pub)) != 0;
}

#define HSK_MAX_REFS 8

static void hsk_addrman_log(const hsk_addrman_t *am, const char *fmt, ...)
{
  printf("addrman: ");

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

#define HSK_ADDR_MAX 2000
#define HSK_HORIZON_DAYS 30
#define HSK_RETRIES 3
#define HSK_MIN_FAIL_DAYS 7
#define HSK_MAX_FAILURES 10
#define HSK_MAX_REFS 8
#define HSK_BAN_TIME (24 * 60 * 60)

#define HSK_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define HSK_MIN(x, y) (((x) < (y)) ? (x) : (y))

static bool hsk_addrman_is_stale(const hsk_addrman_t *am, const hsk_addrentry_t *entry)
{
  int64_t now = hsk_timedata_now(am->td);

  if (entry->last_attempt && entry->last_attempt >= now - 60) return false;

  if (entry->time > now + 10 * 60) return true;

  if (entry->time == 0) return true;

  if (now - entry->time > HSK_HORIZON_DAYS * 24 * 60 * 60) return true;

  if (entry->last_success == 0 && entry->attempts >= HSK_RETRIES) return true;

  if (now - entry->last_success > HSK_MIN_FAIL_DAYS * 24 * 60 * 60) {
    if (entry->attempts >= HSK_MAX_FAILURES) return true;
  }

  return false;
}

hsk_addrentry_t *hsk_addrman_alloc_entry(hsk_addrman_t *am, bool *alloc)
{
  if (am->size == HSK_ADDR_MAX) {
    int i;
    for (i = 0; i < HSK_MIN(am->size, 10); i++) {
      int index = hsk_random() % am->size;
      hsk_addrentry_t *entry = &am->addrs[index];
      if (hsk_addrman_is_stale(am, entry)) {
        hsk_map_del(&am->map, &entry->addr);
        *alloc = false;
        return entry;
      }
    }
    *alloc = false;
    return NULL;
  }

  assert(am->size < HSK_ADDR_MAX);

  hsk_addrentry_t *entry = &am->addrs[am->size];

  am->size += 1;

  *alloc = true;

  return entry;
}

bool hsk_addrman_add_entry(hsk_addrman_t *am, const hsk_netaddr_t *na, bool src)
{
  hsk_addrentry_t *entry = hsk_map_get(&am->map, &na->addr);

  char host[HSK_MAX_HOST];
  hsk_addr_to_string(&na->addr, host, HSK_MAX_HOST, HSK_BRONTIDE_PORT);

  if (entry) {
    int penalty = 2 * 60 * 60;
    int interval = 24 * 60 * 60;
    int64_t now = hsk_timedata_now(am->td);

    if (!src)
      penalty = 0;

    entry->services |= na->services;

    if (now - na->time < 24 * 60 * 60)
      interval = 60 * 60;

    if (entry->time < na->time - interval - penalty)
      entry->time = na->time;

    if (entry->time && na->time <= entry->time)
      return false;

    if (entry->used)
      return false;

    assert(entry->ref_count > 0);

    if (entry->ref_count == HSK_MAX_REFS)
      return false;

    assert(entry->ref_count < HSK_MAX_REFS);

    uint32_t factor = 1;

    int i;
    for (i = 0; i < entry->ref_count; i++)
      factor *= 2;

    if (factor == 0)
      return false;

    if ((hsk_random() % factor) != 0)
      return false;

    entry->ref_count += 1;

    hsk_addrman_log(am, "saw existing addr: %s\n", host);

    return true;
  }

  bool alloc = false;
  entry = hsk_addrman_alloc_entry(am, &alloc);

  if (!entry)
    return false;

  hsk_addr_copy(&entry->addr, &na->addr);
  entry->time = na->time;
  entry->services = na->services;
  entry->attempts = 0;
  entry->last_success = 0;
  entry->last_attempt = 0;
  entry->ref_count = 1;
  entry->used = false;
  entry->removed = false;

  if (!hsk_map_set(&am->map, &entry->addr, entry)) {
    if (alloc)
      am->size -= 1;
    return false;
  }

  hsk_addrman_log(am, "added addr: %s\n", host);

  return true;
}

bool hsk_addrman_add_na(hsk_addrman_t *am, const hsk_netaddr_t *na)
{
  return hsk_addrman_add_entry(am, na, true);
}

static int hsk_peer_handle_addr(hsk_peer_t *peer, hsk_addr_msg_t *msg)
{
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  if (msg->addr_count > 1000) return HSK_EFAILURE;

  hsk_peer_log(peer, "received %u addrs\n", msg->addr_count);

  int64_t now = hsk_timedata_now(&pool->td);

  int i;
  for (i = 0; i < msg->addr_count; i++)
  {
    hsk_netaddr_t *addr = &msg->addrs[i];

    if (!hsk_addr_is_routable(&addr->addr)) continue;

    if (!(addr->services & 1)) continue;

    if (addr->time <= 100000000 || addr->time > now + 10 * 60)
      addr->time = now - 5 * 24 * 60 * 60;

    if (addr->addr.port == 0) continue;

    if (hsk_addr_has_key(&addr->addr)) continue;

    hsk_addrman_add_na(&pool->am, addr);
  }

  return HSK_SUCCESS;
}

bool hsk_pow_to_target(uint32_t bits, uint8_t *target)
{
  assert(target);

  memset(target, 0, 32);

  if (bits == 0) return false;

  // No negatives.
  if ((bits >> 23) & 1) return false;

  uint32_t exponent = bits >> 24;
  uint32_t mantissa = bits & 0x7fffff;

  uint32_t shift;

  if (exponent <= 3)
  {
    mantissa >>= 8 * (3 - exponent);
    shift = 0;
  }
  else
  {
    shift = (exponent - 3) & 31;
  }

  int i = 31 - shift;

  while (mantissa && i >= 0) {
    target[i--] = (uint8_t)mantissa;
    mantissa >>= 8;
  }

  // Overflow
  if (mantissa)
    return false;

  return true;
}

int hsk_header_verify_pow(const hsk_header_t *hdr)
{
  uint8_t target[32];

  if (!hsk_pow_to_target(hdr->bits, target)) return HSK_ENEGTARGET;

  uint8_t hash[32];

  hsk_header_hash((hsk_header_t *)hdr, hash);

  if (memcmp(hash, target, 32) > 0) return HSK_EHIGHHASH;

  return HSK_SUCCESS;
}

hsk_header_t *hsk_header_clone(const hsk_header_t *hdr)
{
  if (!hdr) return NULL;

  hsk_header_t *copy = malloc(sizeof(hsk_header_t));

  if (!copy) return NULL;

  memcpy((void *)copy, (void *)hdr, sizeof(hsk_header_t));
  copy->next = NULL;

  return copy;
}

static void hsk_chain_log(const hsk_chain_t *chain, const char *fmt, ...)
{
  printf("chain (%u): ", (uint32_t)chain->height);

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

static inline char to_char(uint8_t n)
{
  if (n >= 0x00 && n <= 0x09) return n + '0';
  if (n >= 0x0a && n <= 0x0f) return (n - 0x0a) + 'a';

  return -1;
}

bool hsk_hex_encode(const uint8_t *data, size_t data_len, char *str)
{
  if (data == NULL && data_len != 0) return false;

  if (str == NULL) return false;

  size_t size = data_len << 1;

  int i;
  int p = 0;

  for (i = 0; i < size; i++)
  {
    char ch;

    if (i & 1)
    {
      ch = to_char(data[p] & 15);
      p += 1;
    }
    else
    {
      ch = to_char(data[p] >> 4);
    }

    if (ch == -1) return false;

    str[i] = ch;
  }

  str[i] = '\0';

  return true;
}

const char *hsk_hex_encode32(const uint8_t *data)
{
  static char str[65];
  assert(hsk_hex_encode(data, 32, str));
  return str;
}

static const char *errstrs[] =
{
  "ESUCCESS",
  "ENOMEM",
  "ETIMEOUT",
  "EFAILURE",
  "EBADARGS",
  "EENCODING",
  "EHASHMISMATCH",
  "ESAMEKEY",
  "ESAMEPATH",
  "ENEGDEPTH",
  "EPATHMISMATCH",
  "ETOODEEP",
  "EUNKNOWNERROR",
  "EMALFORMEDNODE",
  "EINVALIDNODE",
  "EEARLYEND",
  "ENORESULT",
  "EUNEXPECTEDNODE",
  "ERECORDMISMATCH",
  "ENEGTARGET",
  "EHIGHHASH",
  "ETIMETOONEW",
  "EDUPLICATE",
  "EDIPLICATEORPHAN",
  "ETIMETOOOLD",
  "EBADDDIFFBITS",
  "EORPHAN",
  "EACTONE",
  "EACTTWO",
  "EACTTHREE",
  "EBADSIZE",
  "EBADTAG",
  "EUNKNOWN"
};

const char *hsk_strerror(int code)
{
  if (code < 0 || code > HSK_MAXERROR) return errstrs[HSK_MAXERROR];
  return errstrs[code];
}

hsk_header_t *hsk_chain_get(const hsk_chain_t *chain, const uint8_t *hash)
{
  return hsk_map_get(&chain->hashes, hash);
}

static int qsort_cmp(const void *a, const void *b)
{
  int64_t x = *((int64_t *)a);
  int64_t y = *((int64_t *)b);

  if (x < y) return -1;
  if (x > y) return 1;

  return 0;
}

static int64_t hsk_chain_get_mtp(const hsk_chain_t *chain, const hsk_header_t *prev)
{
  assert(chain);

  if (!prev)
    return 0;

  int timespan = 11;
  int64_t median[11];
  size_t size = 0;
  int i;

  for (i = 0; i < timespan && prev; i++)
  {
    median[i] = (int64_t)prev->time;
    prev = hsk_map_get(&chain->hashes, prev->prev_block);
    size += 1;
  }

  qsort((void *)median, size, sizeof(int64_t), qsort_cmp);

  return median[size >> 1];
}

static void hsk_header_swap(hsk_header_t **x, hsk_header_t **y)
{
  hsk_header_t *z = *x;
  *x = *y;
  *y = z;
}

static hsk_header_t *hsk_chain_suitable_block(const hsk_chain_t *chain, const hsk_header_t *prev)
{
  hsk_header_t *z = (hsk_header_t *)prev;
  assert(z);

  hsk_header_t *y = hsk_map_get(&chain->hashes, z->prev_block);
  assert(y);

  hsk_header_t *x = hsk_map_get(&chain->hashes, y->prev_block);
  assert(x);

  if (x->time > z->time) hsk_header_swap(&x, &z);
  if (x->time > y->time) hsk_header_swap(&x, &y);
  if (y->time > z->time) hsk_header_swap(&y, &z);

  return y;
}

hsk_header_t *hsk_chain_get_ancestor(const hsk_chain_t *chain, const hsk_header_t *hdr, uint32_t height)
{
  assert(height >= 0);
  assert(height <= hdr->height);

  hsk_header_t *h = (hsk_header_t *)hdr;

  while (h->height != height)
  {
    h = hsk_map_get(&chain->hashes, h->prev_block);
    assert(h);
  }

  return h;
}

#define HSK_BN_SIZE (64 / 4)
#define HSK_BN_MSB ((uint64_t)0x80000000)
#define HSK_BN_MAX ((uint64_t)0xffffffff)

typedef struct hsk_bn_s {
  uint32_t array[HSK_BN_SIZE];
} hsk_bn_t;

void
hsk_bn_init(hsk_bn_t *n) {
  assert(n && "n is null");

  int i;
  for (i = 0; i < HSK_BN_SIZE; i++)
    n->array[i] = 0;
}

void hsk_bn_from_array(hsk_bn_t *n, const uint8_t *array, size_t size)
{
  assert(n && "n is null");
  assert(array && "array is null");

  hsk_bn_init(n);

  int j = (size / 4) - 1;
  int i = 0;

  for (; j >= 0; j--)
  {
    n->array[j] = ((uint32_t)array[i++]) << 24;
    n->array[j] |= ((uint32_t)array[i++]) << 16;
    n->array[j] |= ((uint32_t)array[i++]) << 8;
    n->array[j] |= ((uint32_t)array[i++]);
  }
}

void hsk_bn_from_int(hsk_bn_t *n, uint64_t i)
{
  assert(n && "n is null");

  hsk_bn_init(n);

  n->array[0] = (uint32_t)i;
  n->array[1] = (uint32_t)(i >> 32);
}

void hsk_bn_sub(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c)
{
  assert(a && "a is null");
  assert(b && "b is null");
  assert(c && "c is null");

  uint64_t res;
  uint64_t tmp1;
  uint64_t tmp2;
  int borrow = 0;

  int i;
  for (i = 0; i < HSK_BN_SIZE; i++)
  {
    // + number_base
    tmp1 = (uint64_t)a->array[i] + (HSK_BN_MAX + 1);
    tmp2 = (uint64_t)b->array[i] + borrow;;
    res = (tmp1 - tmp2);

    // "modulo number_base" == "% (number_base - 1)"
    // if number_base is 2^N
    c->array[i] = (uint32_t)(res & HSK_BN_MAX);
    borrow = (res <= HSK_BN_MAX);
  }
}

static void _lshift_word(hsk_bn_t *a, int nwords)
{
  assert(a && "a is null");
  assert(nwords >= 0 && "no negative shifts");

  int i;

  // Shift whole words
  for (i = (HSK_BN_SIZE - 1); i >= nwords; i--) a->array[i] = a->array[i - nwords];

  // Zero pad shifted words.
  for (; i >= 0; i--) a->array[i] = 0;
}

void hsk_bn_add(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c)
{
  assert(a && "a is null");
  assert(b && "b is null");
  assert(c && "c is null");

  uint64_t tmp;
  int carry = 0;

  int i;
  for (i = 0; i < HSK_BN_SIZE; i++)
  {
    tmp = (uint64_t)a->array[i] + (uint64_t)b->array[i] + carry;
    carry = (tmp > HSK_BN_MAX);
    c->array[i] = (tmp & HSK_BN_MAX);
  }
}

void hsk_bn_assign(hsk_bn_t *dst, const hsk_bn_t *src)
{
  assert(dst && "dst is null");
  assert(src && "src is null");

  int i;
  for (i = 0; i < HSK_BN_SIZE; i++) dst->array[i] = src->array[i];
}

void hsk_bn_mul(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c)
{
  assert(a && "a is null");
  assert(b && "b is null");
  assert(c && "c is null");

  hsk_bn_t row;
  hsk_bn_t tmp;
  hsk_bn_t cc;
  int i, j;

  hsk_bn_init(&cc);

  for (i = 0; i < HSK_BN_SIZE; i++)
  {
    hsk_bn_init(&row);

    for (j = 0; j < HSK_BN_SIZE; j++)
    {
      if (i + j < HSK_BN_SIZE)
      {
        hsk_bn_init(&tmp);

        uint64_t intermediate = ((uint64_t)a->array[i] * (uint64_t)b->array[j]);

        hsk_bn_from_int(&tmp, intermediate);
        _lshift_word(&tmp, i + j);
        hsk_bn_add(&tmp, &row, &row);
      }
    }

    hsk_bn_add(&cc, &row, &cc);
  }

  hsk_bn_assign(c, &cc);
}

int hsk_bn_cmp(const hsk_bn_t *a, const hsk_bn_t *b)
{
  assert(a && "a is null");
  assert(b && "b is null");

  int i = HSK_BN_SIZE;

  do {
    // Decrement first, to start
    // with last array element
    i -= 1;

    if (a->array[i] > b->array[i]) return 1;
    else if (a->array[i] < b->array[i]) return -1;
  } while (i != 0);

  return 0;
}

static void _lshift_one_bit(hsk_bn_t *a)
{
  assert(a && "a is null");

  int i;
  for (i = (HSK_BN_SIZE - 1); i > 0; i--)
  {
    a->array[i] = (a->array[i] << 1) | (a->array[i - 1] >> ((8 * 4) - 1));
  }

  a->array[0] <<= 1;
}

static void _rshift_one_bit(hsk_bn_t *a)
{
  assert(a && "a is null");

  int i;
  for (i = 0; i < (HSK_BN_SIZE - 1); i++)
  {
    a->array[i] = (a->array[i] >> 1)
      | (a->array[i + 1] << ((8 * 4) - 1));
  }

  a->array[HSK_BN_SIZE - 1] >>= 1;
}

int hsk_bn_is_zero(const hsk_bn_t *n)
{
  assert(n && "n is null");

  int i;
  for (i = 0; i < HSK_BN_SIZE; i++)
  {
    if (n->array[i]) return 0;
  }

  return 1;
}

void hsk_bn_or(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c)
{
  assert(a && "a is null");
  assert(b && "b is null");
  assert(c && "c is null");

  int i;
  for (i = 0; i < HSK_BN_SIZE; i++) c->array[i] = (a->array[i] | b->array[i]);
}

void hsk_bn_div(const hsk_bn_t *a, const hsk_bn_t *b, hsk_bn_t *c)
{
  assert(a && "a is null");
  assert(b && "b is null");
  assert(c && "c is null");

  hsk_bn_t current;
  hsk_bn_t denom;
  hsk_bn_t tmp;

  // int current = 1;
  hsk_bn_from_int(&current, 1);
  // denom = b
  hsk_bn_assign(&denom, b);
  // tmp = a
  hsk_bn_assign(&tmp, a);

  const uint64_t half_max = 1 + (uint64_t)(HSK_BN_MAX / 2);
  bool overflow = false;

  // while (denom <= a) {
  while (hsk_bn_cmp(&denom, a) != 1)
  {
    if (denom.array[HSK_BN_SIZE - 1] >= half_max)
    {
      overflow = true;
      break;
    }

    // current <<= 1;
    _lshift_one_bit(&current);

    // denom <<= 1;
    _lshift_one_bit(&denom);
  }

  if (!overflow) {
    // denom >>= 1;
    _rshift_one_bit(&denom);
    // current >>= 1;
    _rshift_one_bit(&current);
  }

  // int answer = 0;
  hsk_bn_init(c);

  // while (current != 0)
  while (!hsk_bn_is_zero(&current)) {
    // if (dividend >= denom)
    if (hsk_bn_cmp(&tmp, &denom) != -1)  {
      // dividend -= denom;
      hsk_bn_sub(&tmp, &denom, &tmp);
      // answer |= current;
      hsk_bn_or(c, &current, c);
    }

    // current >>= 1;
    _rshift_one_bit(&current);

    // denom >>= 1;
    _rshift_one_bit(&denom);
  }

  // return answer;
}

void hsk_bn_lshift(hsk_bn_t *a, hsk_bn_t *b, int nbits)
{
  assert(a && "a is null");
  assert(b && "b is null");
  assert(nbits >= 0 && "no negative shifts");

  // Handle shift in multiples of word-size
  const int nbits_pr_word = 4 * 8;
  int nwords = nbits / nbits_pr_word;

  if (nwords != 0)
  {
    _lshift_word(a, nwords);
    nbits -= (nwords * nbits_pr_word);
  }

  if (nbits != 0)
  {
    int i;
    for (i = (HSK_BN_SIZE - 1); i > 0; i--)
    {
      a->array[i] = (a->array[i] << nbits) | (a->array[i - 1] >> ((8 * 4) - nbits));
    }

    a->array[i] <<= nbits;
  }

  hsk_bn_assign(b, a);
}

void hsk_bn_to_array(const hsk_bn_t *n, uint8_t *array, size_t size)
{
  assert(n && "n is null");
  assert(array && "array is null");

  int j = (size / 4) - 1;
  int i = 0;

  for (; j >= 0; j--)
  {
    array[i++] = (uint8_t)(n->array[j] >> 24);
    array[i++] = (uint8_t)(n->array[j] >> 16);
    array[i++] = (uint8_t)(n->array[j] >> 8);
    array[i++] = (uint8_t)n->array[j];
  }
}

bool hsk_pow_to_bits(const uint8_t *target, uint32_t *bits)
{
  assert(target && bits);

  int i;

  for (i = 0; i < 32; i++)
  {
    if (target[i] != 0) break;
  }

  uint32_t exponent = 32 - i;

  if (exponent == 0)
  {
    *bits = 0;
    return true;
  }

  uint32_t mantissa = 0;

  if (exponent <= 3)
  {
    switch (exponent)
    {
      case 3:
        mantissa |= ((uint32_t)target[29]) << 16;
      case 2:
        mantissa |= ((uint32_t)target[30]) << 8;
      case 1:
        mantissa |= (uint32_t)target[31];
    }
    mantissa <<= 8 * (3 - exponent);
  } else {
    int shift = exponent - 3;
    for (; i < 32 - shift; i++) {
      mantissa <<= 8;
      mantissa |= target[i];
    }
  }

  if (mantissa & 0x800000) {
    mantissa >>= 8;
    exponent += 1;
  }

  *bits = (exponent << 24) | mantissa;

  return true;
}

static uint32_t hsk_chain_retarget(const hsk_chain_t *chain, const hsk_header_t *first, const hsk_header_t *last)
{
  assert(chain && first && last);
  assert(last->height >= first->height);

  uint8_t *limit = (uint8_t *)HSK_LIMIT;

  hsk_bn_t target_bn;
  hsk_bn_t last_bn;
  hsk_bn_t spacing_bn;
  hsk_bn_t actual_bn;
  hsk_bn_t max_bn;
  hsk_bn_t limit_bn;

  uint8_t target[32];
  uint32_t cmpct;

  hsk_bn_from_array(&target_bn, first->work, 32);
  hsk_bn_from_array(&last_bn, last->work, 32);

  hsk_bn_from_int(&spacing_bn, (uint64_t)HSK_TARGET_SPACING);

  hsk_bn_sub(&last_bn, &target_bn, &target_bn);
  hsk_bn_mul(&target_bn, &spacing_bn, &target_bn);

  int64_t actual = last->time - first->time;

  if (actual < HSK_MIN_ACTUAL) actual = HSK_MIN_ACTUAL;

  if (actual > HSK_MAX_ACTUAL) actual = HSK_MAX_ACTUAL;

  hsk_bn_from_int(&actual_bn, (uint64_t)actual);

  hsk_bn_div(&target_bn, &actual_bn, &target_bn);

  if (hsk_bn_is_zero(&target_bn)) return HSK_BITS;

  hsk_bn_t one_bn;
  hsk_bn_from_int(&one_bn, 1);

  hsk_bn_from_int(&max_bn, 1);
  hsk_bn_lshift(&max_bn, &max_bn, 256);

  hsk_bn_div(&max_bn, &target_bn, &target_bn);
  hsk_bn_sub(&target_bn, &one_bn, &target_bn);

  hsk_bn_from_array(&limit_bn, limit, 32);

  if (hsk_bn_cmp(&target_bn, &limit_bn) > 0) return HSK_BITS;

  hsk_bn_to_array(&target_bn, target, 32);

  assert(hsk_pow_to_bits(target, &cmpct));

  return cmpct;
}

static uint32_t hsk_chain_get_target(const hsk_chain_t *chain, int64_t time, const hsk_header_t *prev)
{
  assert(chain);

  // Genesis
  if (!prev)
  {
    assert(time == chain->genesis->time);
    return HSK_BITS;
  }

  if (HSK_NO_RETARGETTING) return HSK_BITS;

  if (HSK_TARGET_RESET)
  {
    // Special behavior for testnet:
    if (time > (int64_t)prev->time + HSK_TARGET_SPACING * 2)
      return HSK_BITS;
   }

  if (prev->height < 144 + 2) return HSK_BITS;

  hsk_header_t *last = hsk_chain_suitable_block(chain, prev);

  int64_t height = prev->height - 144;
  hsk_header_t *ancestor = hsk_chain_get_ancestor(chain, prev, height);
  hsk_header_t *first = hsk_chain_suitable_block(chain, ancestor);

  return hsk_chain_retarget(chain, first, last);
}

/*
#define HSK_BN_SIZE (64 / 4)
#define HSK_BN_MSB ((uint64_t)0x80000000)
#define HSK_BN_MAX ((uint64_t)0xffffffff)

typedef struct hsk_bn_s
{
  uint32_t array[HSK_BN_SIZE];
} hsk_bn_t;
*/

void hsk_bn_inc(hsk_bn_t *n)
{
  assert(n && "n is null");

  uint32_t res;
  uint64_t tmp; // copy of n

  int i;
  for (i = 0; i < HSK_BN_SIZE; i++)
  {
    tmp = n->array[i];
    res = tmp + 1;
    n->array[i] = res;

    if (res > tmp) break;
  }
}

bool hsk_header_get_proof(const hsk_header_t *hdr, uint8_t *proof)
{
  uint8_t target[32];

  if (!hsk_pow_to_target(hdr->bits, target))
    return false;

  hsk_bn_t max_bn;
  hsk_bn_from_int(&max_bn, 1);
  hsk_bn_lshift(&max_bn, &max_bn, 256);

  hsk_bn_t target_bn;
  hsk_bn_from_array(&target_bn, target, 32);
  hsk_bn_inc(&target_bn);

  // (1 << 256) / (target + 1)
  hsk_bn_div(&max_bn, &target_bn, &target_bn);

  hsk_bn_to_array(&target_bn, proof, 32);

  return true;
}

bool hsk_header_calc_work(hsk_header_t *hdr, const hsk_header_t *prev)
{
  if (!prev) return hsk_header_get_proof(hdr, hdr->work);

  hsk_bn_t prev_bn;
  hsk_bn_from_array(&prev_bn, prev->work, 32);

  uint8_t proof[32];

  if (!hsk_header_get_proof(hdr, proof))
    return false;

  hsk_bn_t proof_bn;
  hsk_bn_from_array(&proof_bn, proof, 32);

  hsk_bn_add(&prev_bn, &proof_bn, &proof_bn);
  hsk_bn_to_array(&proof_bn, hdr->work, 32);

  return true;
}

bool hsk_header_equal(hsk_header_t *a, hsk_header_t *b)
{
  return memcmp(hsk_header_cache(a), hsk_header_cache(b), 32) == 0;
}

static hsk_header_t *hsk_chain_find_fork(const hsk_chain_t *chain, hsk_header_t *fork, hsk_header_t *longer)
{
  assert(chain && fork && longer);

  while (!hsk_header_equal(fork, longer))
  {
    while (longer->height > fork->height)
    {
      longer = hsk_map_get(&chain->hashes, longer->prev_block);
      if (!longer) return NULL;
    }

    if (hsk_header_equal(fork, longer)) return fork;

    fork = hsk_map_get(&chain->hashes, fork->prev_block);

    if (!fork) return NULL;
  }

  return fork;
}

static void hsk_chain_reorganize(hsk_chain_t *chain, hsk_header_t *competitor)
{
  assert(chain && competitor);

  hsk_header_t *tip = chain->tip;
  hsk_header_t *fork = hsk_chain_find_fork(chain, tip, competitor);

  assert(fork);

  // Blocks to disconnect.
  hsk_header_t *disconnect = NULL;
  hsk_header_t *entry = tip;
  hsk_header_t *tail = NULL;
  while (!hsk_header_equal(entry, fork)) {
    assert(!entry->next);

    if (!disconnect)
      disconnect = entry;

    if (tail)
      tail->next = entry;

    tail = entry;

    entry = hsk_map_get(&chain->hashes, entry->prev_block);
    assert(entry);
  }

  // Blocks to connect.
  entry = competitor;
  hsk_header_t *connect = NULL;
  while (!hsk_header_equal(entry, fork)) {
    assert(!entry->next);

    // Build the list backwards.
    if (connect)
      entry->next = connect;

    connect = entry;

    entry = hsk_map_get(&chain->hashes, entry->prev_block);
    assert(entry);
  }

  // Disconnect blocks.
  hsk_header_t *c, *n;
  for (c = disconnect; c; c = n) {
    n = c->next;
    c->next = NULL;
    hsk_map_del(&chain->heights, &c->height);
  }

  // Connect blocks (backwards, save last).
  for (c = connect; c; c = n) {
    n = c->next;
    c->next = NULL;

    if (!n) // halt on last
      break;

    assert(hsk_map_set(&chain->heights, &c->height, (void *)c));
  }
}

static bool hsk_chain_has_work(const hsk_chain_t *chain)
{
  return memcmp(chain->tip->work, HSK_CHAINWORK, 32) >= 0;
}

static void hsk_chain_maybe_sync(hsk_chain_t *chain)
{
  if (chain->synced) return;

  int64_t now = hsk_timedata_now(chain->td);

  if (((int64_t)chain->tip->time) < now - HSK_MAX_TIP_AGE) return;

  if (!hsk_chain_has_work(chain)) return;

  hsk_chain_log(chain, "chain is fully synced\n");
  chain->synced = true;
}

// Version 0 header store file serialization:
// Size    Data
//  4       network magic
//  1       version (0)
//  4       start height
//  32      total chainwork excluding block at start height
//  35400   150 x 236-byte serialized block headers

#define HSK_STORE_VERSION 0
#define HSK_STORE_HEADERS_COUNT 150
#define HSK_STORE_CHECKPOINT_SIZE 35441
#define HSK_STORE_FILENAME "checkpoint"
#define HSK_STORE_EXTENSION ".dat"
#define HSK_STORE_PATH_RESERVED 32
#define HSK_STORE_PATH_MAX 1024

int hsk_header_write(const hsk_header_t *hdr, uint8_t **data)
{
  int s = 0;
  s += write_u32(data, hdr->nonce);
  s += write_u64(data, hdr->time);
  s += write_bytes(data, hdr->prev_block, 32);
  s += write_bytes(data, hdr->name_root, 32);
  s += write_bytes(data, hdr->extra_nonce, 24);
  s += write_bytes(data, hdr->reserved_root, 32);
  s += write_bytes(data, hdr->witness_root, 32);
  s += write_bytes(data, hdr->merkle_root, 32);
  s += write_u32(data, hdr->version);
  s += write_u32(data, hdr->bits);
  s += write_bytes(data, hdr->mask, 32);
  return s;
}

#if defined(_WIN32)
#  include <windows.h>
#  define HSK_PATH_SEP '\\'
#else
#  include <sys/stat.h>
#  define HSK_PATH_SEP '/'
#endif

static void hsk_store_filename(char *prefix, char *path, uint32_t height)
{
  sprintf(path, "%s%c%s_%s%s", prefix, HSK_PATH_SEP, HSK_STORE_FILENAME, HSK_NETWORK_NAME, HSK_STORE_EXTENSION);

  if (height > 0)
  {
    sprintf(path, "%s~%u", path, height);
  }
}

static void hsk_store_log(const char *fmt, ...)
{
  printf("store: ");

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}

void hsk_store_write(const hsk_chain_t *chain)
{
  // Serialize
  char buf[HSK_STORE_CHECKPOINT_SIZE];
  uint8_t *data = (uint8_t *)&buf;

  if (!write_u32be(&data, HSK_MAGIC)) goto fail;

  if (!write_u8(&data, HSK_STORE_VERSION)) goto fail;

  assert(chain->height % HSK_STORE_CHECKPOINT_WINDOW == 0);
  uint32_t height = chain->height - HSK_STORE_CHECKPOINT_WINDOW;
  if (!write_u32be(&data, height)) goto fail;

  hsk_header_t *prev = hsk_chain_get_by_height(chain, height - 1);
  if (!write_bytes(&data, prev->work, 32)) goto fail;

  for (int i = 0; i < HSK_STORE_HEADERS_COUNT; i++)
  {
    hsk_header_t *hdr = hsk_chain_get_by_height(chain, i + height);

    if (!hsk_header_write(hdr, &data)) goto fail;
  }

  // Prepare
  char path[HSK_STORE_PATH_MAX];
  char tmp[HSK_STORE_PATH_MAX];
  hsk_store_filename(chain->prefix, tmp, height);
  hsk_store_filename(chain->prefix, path, 0);

  // Open file
  FILE *file = fopen(tmp, "w");
  if (!file) {
    hsk_store_log("could not open temp file to write checkpoint: %s\n", tmp);
    return;
  }

  // Write temp
  size_t written = fwrite(&buf, 1, HSK_STORE_CHECKPOINT_SIZE, file);
  fclose(file);

  if (written != HSK_STORE_CHECKPOINT_SIZE) {
    hsk_store_log("could not write checkpoint to temp file: %s\n", tmp);
    return;
  } else {
    hsk_store_log("(%u) wrote temp checkpoint file: %s\n", height, tmp);
  }

  // Rename
#if defined(_WIN32)
  // Can not do the rename-file trick to guarantee atomicity on windows
  remove(path);
#endif
 
  if (rename(tmp, path) == 0) {
    hsk_store_log("(%u) wrote checkpoint file: %s\n", height, path);
    return;
  } else {
    hsk_store_log("(%u) failed to write checkpoint file: %s\n", height, path);
    return;
  }

fail:
  hsk_store_log("could not serialize checkpoint data\n");
}

static void hsk_chain_checkpoint_flush(hsk_chain_t *chain)
{
  // Setting is off
  if (!chain->prefix) return;

  // Skip first window after init to avoid re-writing the same checkpoint
  if (chain->height - chain->init_height <= HSK_STORE_CHECKPOINT_WINDOW) return;

  hsk_store_write(chain);
}

int hsk_chain_save(hsk_chain_t *chain, hsk_header_t *hdr)
{
    // Save the header
    if (!hsk_map_set(&chain->hashes, &hdr->hash, (void *)hdr)) return HSK_ENOMEM;

    if (!hsk_map_set(&chain->heights, &hdr->height, (void *)hdr))
    {
      hsk_map_del(&chain->hashes, &hdr->hash);
      return HSK_ENOMEM;
    }

    // Set the chain tip
    chain->height = hdr->height;
    chain->tip = hdr;

    hsk_chain_log(chain, "  added to main chain\n");
    hsk_chain_log(chain, "  new height: %u\n", (uint32_t)chain->height);

    hsk_chain_maybe_sync(chain);

    // Save batch of headers to disk
    if (chain->height % HSK_STORE_CHECKPOINT_WINDOW == 0)
      hsk_chain_checkpoint_flush(chain);

    return HSK_SUCCESS;
}

static int hsk_chain_insert(hsk_chain_t *chain, hsk_header_t *hdr, const hsk_header_t *prev)
{
  const uint8_t *hash = hsk_header_cache(hdr);
  int64_t mtp = hsk_chain_get_mtp(chain, prev);

  if ((int64_t)hdr->time <= mtp) {
    hsk_chain_log(chain, "  rejected: time-too-old\n");
    return HSK_ETIMETOOOLD;
  }

  uint32_t bits = hsk_chain_get_target(chain, hdr->time, prev);

  if (hdr->bits != bits) {
    hsk_chain_log(chain,
      "  rejected: bad-diffbits: %x != %x\n",
      hdr->bits, bits);
    return HSK_EBADDIFFBITS;
  }

  hdr->height = prev->height + 1;

  assert(hsk_header_calc_work(hdr, prev));

  // Less work than chain tip, this header is on a fork
  if (memcmp(hdr->work, chain->tip->work, 32) <= 0) {
    if (!hsk_map_set(&chain->hashes, hash, (void *)hdr))
      return HSK_ENOMEM;

    hsk_chain_log(chain, "  stored on alternate chain\n");
  } else {
    // More work than tip, but does not connect to tip: we have a reorg
    if (memcmp(hdr->prev_block, hsk_header_cache(chain->tip), 32) != 0) {
      hsk_chain_log(chain, "  reorganizing...\n");
      hsk_chain_reorganize(chain, hdr);
    }

    return hsk_chain_save(chain, hdr);
  }

  return HSK_SUCCESS;
}

size_t hsk_hex_encode_size(size_t data_len)
{
  return (data_len << 1) + 1;
}

static hsk_header_t *hsk_chain_resolve_orphan(hsk_chain_t *chain, const uint8_t *hash)
{
  hsk_header_t *orphan = hsk_map_get(&chain->prevs, hash);

  if (!orphan) return NULL;

  hsk_map_del(&chain->prevs, orphan->prev_block);
  hsk_map_del(&chain->orphans, hsk_header_cache(orphan));

  return orphan;
}

int hsk_chain_add(hsk_chain_t *chain, const hsk_header_t *h)
{
  if (!chain || !h) return HSK_EBADARGS;

  int rc = HSK_SUCCESS;
  hsk_header_t *hdr = hsk_header_clone(h);

  if (!hdr)
  {
    rc = HSK_ENOMEM;
    goto fail;
  }

  const uint8_t *hash = hsk_header_cache(hdr);

  hsk_chain_log(chain, "adding block: %s\n", hsk_hex_encode32(hash));
  hsk_chain_log(chain, "tree_root %s timestamp %d \n",
      hsk_hex_encode32(hdr->name_root), hdr->time);

  int64_t now = hsk_timedata_now(chain->td);

  if (hdr->time > now + 2 * 60 * 60) {
    hsk_chain_log(chain, "  rejected: time-too-new\n");
    rc = HSK_ETIMETOONEW;
    goto fail;
  }

  if (hsk_map_has(&chain->hashes, hash)) {
    hsk_chain_log(chain, "  rejected: duplicate\n");
    rc = HSK_EDUPLICATE;
    goto fail;
  }

  if (hsk_map_has(&chain->orphans, hash)) {
    hsk_chain_log(chain, "  rejected: duplicate-orphan\n");
    rc = HSK_EDUPLICATEORPHAN;
    goto fail;
  }

  rc = hsk_header_verify_pow(hdr);

  if (rc != HSK_SUCCESS) {
    hsk_chain_log(chain, "  rejected: pow error: %s\n", hsk_strerror(rc));
    goto fail;
  }

  hsk_header_t *prev = hsk_chain_get(chain, hdr->prev_block);

  if (!prev) {
    hsk_chain_log(chain, "  stored as orphan\n");

    if (chain->orphans.size > 10000) {
      hsk_chain_log(chain, "clearing orphans: %d\n", chain->orphans.size);
      hsk_map_clear(&chain->prevs);
      hsk_map_clear(&chain->orphans);
    }

    if (!hsk_map_set(&chain->orphans, hash, (void *)hdr)) {
      rc = HSK_ENOMEM;
      goto fail;
    }

    if (!hsk_map_set(&chain->prevs, hdr->prev_block, (void *)hdr)) {
      hsk_map_del(&chain->orphans, hash);
      rc = HSK_ENOMEM;
      goto fail;
    }

    return HSK_EORPHAN;
  }

  rc = hsk_chain_insert(chain, hdr, prev);

  if (rc != HSK_SUCCESS)
    goto fail;

  for (;;) {
    prev = hdr;
    hdr = hsk_chain_resolve_orphan(chain, hash);

    if (!hdr)
      break;

    hash = hsk_header_cache(hdr);

    rc = hsk_chain_insert(chain, hdr, prev);

    hsk_chain_log(chain, "resolved orphan: %s\n", hsk_hex_encode32(hash));

    if (rc != HSK_SUCCESS) {
      free(hdr);
      return rc;
    }
  }

  return rc;

fail:
  if (hdr)
    free(hdr);

  return rc;
}

typedef struct hsk_banned_t
{
  hsk_addr_t addr;
  uint16_t port;
  int64_t time;
} hsk_banned_t;

bool hsk_addrman_add_ban(hsk_addrman_t *am, const hsk_addr_t *addr)
{
  hsk_banned_t *entry = hsk_map_get(&am->banned, addr);

  int64_t now = hsk_now();

  if (entry)
  {
    entry->time = now;
    return true;
  }

  hsk_banned_t *ban = malloc(sizeof(hsk_banned_t));

  if (!ban) return false;

  hsk_addr_copy(&ban->addr, addr);
  ban->time = now;

  if (!hsk_map_set(&am->banned, &ban->addr, ban))
  {
    free(ban);
    return false;
  }

  return true;
}

bool hsk_addrman_is_banned(hsk_addrman_t *am, const hsk_addr_t *addr)
{
  hsk_banned_t *entry = hsk_map_get(&am->banned, addr);

  if (!entry) return false;

  int64_t now = hsk_now();

  if (now > entry->time + HSK_BAN_TIME)
  {
    hsk_map_del(&am->banned, &entry->addr);
    free(entry);
    return false;
  }

  return true;
}

static int hsk_peer_handle_headers(hsk_peer_t *peer, const hsk_headers_msg_t *msg)
{
  hsk_pool_t *pool = (hsk_pool_t *)peer->pool;

  hsk_peer_log(peer, "received %u headers\n", msg->header_count);

  if (msg->header_count == 0) return HSK_SUCCESS;

  if (msg->header_count > 2000) return HSK_EFAILURE;

  const uint8_t *last = NULL;
  hsk_header_t *hdr;

  for (hdr = msg->headers; hdr; hdr = hdr->next)
  {
    if (last && memcmp(hdr->prev_block, last, 32) != 0)
    {
      hsk_peer_log(peer, "invalid header chain\n");
      return HSK_EHASHMISMATCH;
    }

    last = hsk_header_cache(hdr);

    int rc = hsk_header_verify_pow(hdr);

    if (rc != HSK_SUCCESS)
    {
      hsk_peer_log(peer, "invalid header pow\n");
      return rc;
    }
  }

  bool orphan = false;

  for (hdr = msg->headers; hdr; hdr = hdr->next)
  {
    int rc = hsk_chain_add(peer->chain, hdr);

    if (rc == HSK_ETIMETOOOLD || rc == HSK_EBADDIFFBITS) {
      hsk_peer_log(peer, "failed adding block: %s\n", hsk_strerror(rc));

      if (!hsk_addrman_add_ban(&pool->am, &peer->addr))
        return HSK_ENOMEM;

      hsk_peer_destroy(peer);
      return rc;
    }

    if (rc == HSK_ETIMETOONEW) {
      hsk_peer_log(peer, "failed adding block: %s\n", hsk_strerror(rc));
      hsk_peer_destroy(peer);
      return rc;
    }

    if (rc == HSK_EORPHAN || rc == HSK_EDUPLICATEORPHAN) {
      if (!orphan)
        hsk_peer_log(peer, "failed adding orphan\n");
      orphan = true;
      continue;
    }

    if (rc != HSK_SUCCESS) {
      hsk_peer_log(peer, "failed adding block: %s\n", hsk_strerror(rc));
      if (rc == HSK_EDUPLICATE)
        continue;
      else
        return rc;
    }

    peer->headers += 1;
  }

  if (orphan) {
    hsk_header_t *hdr = msg->headers;
    const uint8_t *hash = hsk_header_cache(hdr);
    hsk_peer_log(peer, "peer sent orphan: %s\n", hsk_hex_encode32(hash));
    hsk_peer_log(peer, "peer sending orphan locator\n");
    hsk_peer_send_getheaders(peer, NULL);
    return HSK_SUCCESS;
  }

  pool->block_time = hsk_now();
  peer->getheaders_time = 0;

  if (msg->header_count == 2000) {
    hsk_peer_log(peer, "requesting more headers\n");
    return hsk_peer_send_getheaders(peer, NULL);
  }

  return HSK_SUCCESS;
}

/*
static int
hsk_peer_handle_proof(hsk_peer_t *peer, const hsk_proof_msg_t *msg) {
  hsk_peer_log(peer, "received proof: %s\n", hsk_hex_encode32(msg->key));

  hsk_name_req_t *reqs = hsk_map_get(&peer->names, msg->key);

  if (!reqs) {
    hsk_peer_log(peer,
      "received unsolicited proof: %s\n",
      hsk_hex_encode32(msg->key));
    return HSK_EBADARGS;
  }

  hsk_peer_log(peer, "received proof for: %s\n", reqs->name);

  if (memcmp(msg->root, reqs->root, 32) != 0) {
    hsk_peer_log(peer, "proof hash mismatch (why?)\n");
    return HSK_EHASHMISMATCH;
  }

  bool exists;
  uint8_t *data;
  size_t data_len;

  int rc = hsk_proof_verify(
    msg->root,
    msg->key,
    &msg->proof,
    &exists,
    &data,
    &data_len
  );

  if (rc != HSK_SUCCESS) {
    hsk_peer_log(peer, "invalid proof: %s\n", hsk_strerror(rc));
    return rc;
  }

  hsk_map_del(&peer->names, msg->key);

  hsk_name_req_t *req, *next;

  for (req = reqs; req; req = next) {
    next = req->next;

    req->callback(
      req->name,
      HSK_SUCCESS,
      exists,
      data,
      data_len,
      req->arg
    );

    free(req);
  }

  free(data);

  peer->proofs += 1;

  return HSK_SUCCESS;
}
*/

static int hsk_peer_handle_msg(hsk_peer_t *peer, const hsk_msg_t *msg)
{
  hsk_peer_debug(peer, "handling msg: %s\n", hsk_msg_str(msg->cmd));

  switch (msg->cmd)
  {
    case HSK_MSG_VERSION:
      return hsk_peer_handle_version(peer, (hsk_version_msg_t *)msg);
    case HSK_MSG_VERACK:
      return hsk_peer_handle_verack(peer, (hsk_verack_msg_t *)msg);
    case HSK_MSG_PING:
      return hsk_peer_handle_ping(peer, (hsk_ping_msg_t *)msg);
    case HSK_MSG_PONG:
      return hsk_peer_handle_pong(peer, (hsk_pong_msg_t *)msg);
    case HSK_MSG_GETADDR:
      hsk_peer_debug(peer, "cannot handle getaddr\n");
      return HSK_SUCCESS;
    case HSK_MSG_ADDR:
      return hsk_peer_handle_addr(peer, (hsk_addr_msg_t *)msg);
    case HSK_MSG_GETHEADERS:
      hsk_peer_debug(peer, "cannot handle getheaders\n");
      return HSK_SUCCESS;
    case HSK_MSG_HEADERS:
      return hsk_peer_handle_headers(peer, (hsk_headers_msg_t *)msg);
    case HSK_MSG_SENDHEADERS:
      hsk_peer_debug(peer, "cannot handle sendheaders\n");
      return HSK_SUCCESS;
/*
    case HSK_MSG_GETPROOF:
      hsk_peer_debug(peer, "cannot handle getproof\n");
      return HSK_SUCCESS;
    case HSK_MSG_PROOF:
      return hsk_peer_handle_proof(peer, (hsk_proof_msg_t *)msg);
*/
    case HSK_MSG_UNKNOWN:
    default:
      return HSK_SUCCESS;
  }
}

#define HSK_UDP_BUFFER 4096

/*
 * Types
 */

typedef struct hsk_cache_s
{
  hsk_map_t map;
} hsk_cache_t;

typedef struct
{
	uv_loop_t *loop;
	hsk_pool_t *pool;
	hsk_addr_t ip_;
	hsk_addr_t *ip;
	uv_udp_t *socket;
	hsk_ec_t *ec;
	hsk_cache_t cache;
	uint8_t key_[32];
	uint8_t *key;
	uint8_t pubkey[33];
	uint8_t read_buffer[HSK_UDP_BUFFER];
	bool receiving;
} hsk_ns_t;

static void alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
  hsk_ns_t *ns = (hsk_ns_t *)handle->data;

  if (!ns)
  {
    buf->base = NULL;
    buf->len = 0;
    return;
  }

  buf->base = (char *)ns->read_buffer;
  buf->len = sizeof(ns->read_buffer);
}

static int hsk_peer_parse_hdr(hsk_peer_t *peer, const uint8_t *msg, size_t msg_len)
{
  uint32_t magic;
  uint8_t *ms = (uint8_t *)msg;

  if (!read_u32(&ms, &msg_len, &magic)) {
    hsk_peer_log(peer, "invalid header\n");
    return HSK_EENCODING;
  }

  if (magic != HSK_MAGIC) {
    hsk_peer_log(peer, "invalid magic: %x\n", magic);
    return HSK_EENCODING;
  }

  uint8_t cmd;

  if (!read_u8(&ms, &msg_len, &cmd)) {
    hsk_peer_log(peer, "invalid command\n");
    return HSK_EENCODING;
  }

  const char *str = hsk_msg_str(cmd);

  uint32_t size;

  if (!read_u32(&ms, &msg_len, &size)) {
    hsk_peer_log(peer, "invalid header: %s\n", str);
    return HSK_EENCODING;
  }

  if (size > HSK_MAX_MESSAGE) {
    hsk_peer_log(peer, "invalid msg size: %s - %u\n", str, size);
    return HSK_EENCODING;
  }

  uint8_t *slab = realloc(peer->msg, size);

  if (!slab && size != 0)
    return HSK_ENOMEM;

  peer->msg_hdr = true;
  peer->msg = slab;
  peer->msg_pos = 0;
  peer->msg_len = size;
  peer->msg_cmd = cmd;

  hsk_peer_debug(peer, "received header: %s\n", str);
  hsk_peer_debug(peer, "  msg size: %u\n", peer->msg_len);

  return HSK_SUCCESS;
}

hsk_msg_t *hsk_msg_alloc(uint8_t cmd)
{
  hsk_msg_t *msg = NULL;

  switch (cmd) {
    case HSK_MSG_VERSION: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_version_msg_t));
      break;
    }
    case HSK_MSG_VERACK: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_verack_msg_t));
      break;
    }
    case HSK_MSG_PING: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_ping_msg_t));
      break;
    }
    case HSK_MSG_PONG: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_pong_msg_t));
      break;
    }
    case HSK_MSG_GETADDR: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_getaddr_msg_t));
      break;
    }
    case HSK_MSG_ADDR: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_addr_msg_t));
      break;
    }
    case HSK_MSG_GETHEADERS: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_getheaders_msg_t));
      break;
    }
    case HSK_MSG_HEADERS: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_headers_msg_t));
      break;
    }
    case HSK_MSG_SENDHEADERS: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_sendheaders_msg_t));
      break;
    }
    case HSK_MSG_GETPROOF: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_getproof_msg_t));
      break;
    }
    case HSK_MSG_PROOF: {
      msg = (hsk_msg_t *)malloc(sizeof(hsk_proof_msg_t));
      break;
    }
  }

  if (msg)
    msg->cmd = cmd;

  hsk_msg_init(msg);

  return msg;
}

// there is another copy of hsk_proof_uninit() in the code, in hnsd/proof-trie.c

void hsk_proof_uninit(hsk_proof_t *proof)
{
  assert(proof);

  if (proof->nodes) {
    free(proof->nodes);
    proof->nodes = NULL;
    proof->node_count = 0;
  }

  if (proof->prefix) {
    free(proof->prefix);
    proof->prefix = NULL;
    proof->prefix_size = 0;
  }

  if (proof->left) {
    free(proof->left);
    proof->left = NULL;
  }

  if (proof->right) {
    free(proof->right);
    proof->right = NULL;
  }

  if (proof->nx_key) {
    free(proof->nx_key);
    proof->nx_key = NULL;
  }

  if (proof->nx_hash) {
    free(proof->nx_hash);
    proof->nx_hash = NULL;
  }

  if (proof->value) {
    free(proof->value);
    proof->value = NULL;
    proof->value_size = 0;
  }
}

void hsk_msg_free(hsk_msg_t *msg)
{
  if (msg == NULL) return;

  switch (msg->cmd) {
    case HSK_MSG_VERSION: {
      hsk_version_msg_t *m = (hsk_version_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_VERACK: {
      hsk_verack_msg_t *m = (hsk_verack_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_PING: {
      hsk_ping_msg_t *m = (hsk_ping_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_PONG: {
      hsk_pong_msg_t *m = (hsk_pong_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_GETADDR: {
      hsk_getaddr_msg_t *m = (hsk_getaddr_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_ADDR: {
      hsk_addr_msg_t *m = (hsk_addr_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_GETHEADERS: {
      hsk_getheaders_msg_t *m = (hsk_getheaders_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_HEADERS: {
      hsk_headers_msg_t *m = (hsk_headers_msg_t *)msg;
      hsk_header_t *c, *n;
      for (c = m->headers; c; c = n) {
        n = c->next;
        free(c);
      }
      free(m);
      break;
    }
    case HSK_MSG_SENDHEADERS: {
      hsk_sendheaders_msg_t *m = (hsk_sendheaders_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_GETPROOF: {
      hsk_getproof_msg_t *m = (hsk_getproof_msg_t *)msg;
      free(m);
      break;
    }
    case HSK_MSG_PROOF: {
      hsk_proof_msg_t *m = (hsk_proof_msg_t *)msg;
      hsk_proof_uninit(&m->proof);
      free(m);
      break;
    }
  }
}

static int hsk_peer_parse(hsk_peer_t *peer, const uint8_t *msg, size_t msg_len)
{
  if (!peer->msg_hdr)
    return hsk_peer_parse_hdr(peer, msg, msg_len);

  int rc = HSK_SUCCESS;
  const char *str = hsk_msg_str(peer->msg_cmd);

  if (strcmp(str, "unknown") == 0) {
    hsk_peer_log(peer, "unknown command: %u\n", peer->msg_cmd);
    goto done;
  }

  hsk_msg_t *m = hsk_msg_alloc(peer->msg_cmd);

  if (!m) {
    rc = HSK_ENOMEM;
    goto done;
  }

  if (!hsk_msg_decode(msg, msg_len, m)) {
    hsk_peer_log(peer, "error parsing msg: %s\n", str);
    free(m);
    rc = HSK_EENCODING;
    goto done;
  }

  rc = hsk_peer_handle_msg(peer, m);
  hsk_msg_free(m);

done: ;
  uint8_t *slab = realloc(peer->msg, 9);

  if (!slab)
    return HSK_ENOMEM;

  peer->msg_hdr = false;
  peer->msg = slab;
  peer->msg_pos = 0;
  peer->msg_len = 9;
  peer->msg_cmd = 0;

  return rc;
}

static void hsk_peer_on_read(hsk_peer_t *peer, const uint8_t *data, size_t data_len)
{
  if (peer->state != HSK_STATE_HANDSHAKE) return;

  peer->last_recv = hsk_now();

  while (peer->msg_pos + data_len >= peer->msg_len)
  {
    assert(peer->msg_pos <= peer->msg_len);
    size_t need = peer->msg_len - peer->msg_pos;
    memcpy(peer->msg + peer->msg_pos, data, need);
    data += need;
    data_len -= need;
    if (hsk_peer_parse(peer, peer->msg, peer->msg_len) != 0)
    {
      hsk_peer_destroy(peer);
      return;
    }
  }

  memcpy(peer->msg + peer->msg_pos, data, data_len);
  peer->msg_pos += data_len;
}

static void after_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
  hsk_peer_t *peer = (hsk_peer_t *)stream->data;

  if (!peer) return;
  
  if (nread < 0)
  {
    if (nread != UV_EOF) hsk_peer_log(peer, "read error: %s\n", uv_strerror(nread));
    hsk_peer_destroy(peer);
    return;
  }
  
/*
  if (peer->brontide != NULL)
  {
    int r = hsk_brontide_on_read(peer->brontide, (uint8_t *)buf->base, (size_t)nread);
    if (r != HSK_SUCCESS)
    {
      hsk_peer_log(peer, "brontide_on_read failed: %s\n", hsk_strerror(r));
      hsk_peer_destroy(peer);
      return;
    }
  }
  else
  {
*/
    hsk_peer_on_read(peer, (uint8_t *)buf->base, (size_t)nread);
/*
  }
*/
}

static void on_connect(uv_connect_t *conn, int status)
{
  uv_tcp_t *socket = (uv_tcp_t *)conn->handle;
  free(conn);

  hsk_peer_t *peer = (hsk_peer_t *)socket->data;

  if (!peer || peer->state != HSK_STATE_CONNECTING)
    return;

  if (status != 0) {
    hsk_peer_log(peer, "failed connecting: %s\n", uv_strerror(status));
    hsk_peer_destroy(peer);
    return;
  }

  peer->state = HSK_STATE_CONNECTED;
  hsk_peer_log(peer, "connected\n");

  status = uv_read_start((uv_stream_t *)socket, alloc_buffer, after_read);

  if (status != 0) {
    hsk_peer_log(peer, "failed reading: %s\n", uv_strerror(status));
    hsk_peer_destroy(peer);
    return;
  }

  peer->state = HSK_STATE_READING;
  peer->conn_time = hsk_now();

/*
  if (peer->brontide != NULL)
  {
    int r = hsk_brontide_on_connect(peer->brontide);

    if (r != HSK_SUCCESS)
    {
      hsk_peer_log(peer, "brontide_on_connect failed: %s\n", hsk_strerror(r));
      hsk_peer_destroy(peer);
      return;
    }
    return;
  }
*/

  peer->state = HSK_STATE_HANDSHAKE;
  hsk_peer_send_version(peer);
}

int say_hello()
{
	printf("hello, world!\n");
}
