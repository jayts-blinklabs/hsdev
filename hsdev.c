#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/socket.h>
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

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

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

void hsk_msg_init(hsk_msg_t *msg)
{
	if (msg == NULL) return;

	switch (msg->cmd)
	{
		case HSK_MSG_VERSION:
			hsk_version_msg_t *m = (hsk_version_msg_t *)msg;
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
/*
		case HSK_MSG_VERACK:
			hsk_verack_msg_t *m = (hsk_verack_msg_t *)msg;
			m->cmd = HSK_MSG_VERACK;
			break;
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

int hsk_msg_encode(const hsk_msg_t *msg, uint8_t *data)
{
	return hsk_msg_write(msg, &data);
}

int hsk_msg_size(const hsk_msg_t *msg)
{
	return hsk_msg_write(msg, NULL);
}

int say_hello()
{
	printf("hello, world!\n");
}
