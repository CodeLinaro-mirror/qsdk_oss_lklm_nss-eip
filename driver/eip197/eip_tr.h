/*
 * Copyright (c) 2022, Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __EIP_TR_H
#define __EIP_TR_H

#define EIP_TR_INVAL_TIMEOUT msecs_to_jiffies(10)
#define EIP_TR_SIZE (sizeof(struct eip_tr) + EIP_HW_CTX_SIZE_LARGE_BYTES + L1_CACHE_BYTES)
#define EIP_TR_CTRL_CONTEXT_WORDS(x) (((x) & 0x3F) << 8)

struct eip_svc_entry;
typedef bool (*eip_tr_init_t) (struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo);

/*
 * eip_tr_stats
 *	Statistics for each transform record.
 */
struct eip_tr_stats {
	uint64_t tx_frags;	/* Total buffer fragments sent via this TR */
	uint64_t tx_pkts;	/* Total buffer sent via this TR */
	uint64_t tx_bytes;	/* Total bytes via this TR */
	uint64_t rx_frags;	/* Total buffer fragments received via this TR */
	uint64_t rx_pkts;	/* Total buffer received via this TR */
	uint64_t rx_bytes;	/* Total bytes recieved via this TR */
	uint64_t rx_error;	/* Total buffer droped due to HW error */
};

/*
 * eip_tr_template
 *	Template to hold callbacks.
 */
struct eip_tr_template {
	eip_tk_fill_t tk_fill;		/* cached Token fill method */
	eip_tr_callback_t cb;		/* completion callback to client */
	eip_tr_err_callback_t err_cb;	/* completion with error callback to client */
};

/*
 * eip_tr_crypto
 *	Crypto specific information.
 */
struct eip_tr_crypto {
	struct eip_tr_template enc;		/* Encode operation */
	struct eip_tr_template dec;		/* Decode operation */
	struct eip_tr_template auth;		/* Auth operation */
	void *app_data;			/* Opaque to pass with callback */
};

/*
 * eip_tr_ipsec
 *	IPsec specific information.
 */
struct eip_tr_ipsec {
	struct eip_tr_template op;	/* Transformation operation callback */
	void *app_data;			/* Opaque to pass with callback */
};

/*
 * eip_tr
 *	Transformation record allocated by HW for each session.
 */
struct eip_tr {
	struct list_head node;			/* Node under per context TR list */
	struct eip_ctx *ctx;			/* Parent context */

	union {
		struct eip_tr_crypto crypto;	/* Crypto information */
		struct eip_tr_ipsec ipsec;	/* IPsec information */
	};

	uint32_t tr_addr_type;			/* TR address with lower 2-bit representing type */
	uint32_t ctrl_words[2];			/* Initial HW control word */
	uint32_t nonce;				/* nonce passed during allocation */
	uint32_t tr_flags;			/* Flags for TR */
	uint16_t iv_len;			/* IV length for configured algo */
	uint16_t digest_len;			/* HMAC length for configured algo */

	struct eip_tr_stats __percpu *stats_pcpu;	/* Statistisc */
	struct kref ref;			/* Reference incremented per packet */

	enum eip_svc svc;			/* Service number */
	uint32_t *tr_ptr;			/* Transform record memory pointer */
	uint32_t inval_dummy_buf;		/* Dummy 4 byte buffer for Invalidation. */
	struct delayed_work inval_work;		/* Workqueue for Invalidation schedule */
};

const struct eip_svc_entry *eip_tr_skcipher_get_svc(void);
size_t eip_tr_skcipher_get_svc_len(void);
const struct eip_svc_entry *eip_tr_ahash_get_svc(void);
size_t eip_tr_ahash_get_svc_len(void);
const struct eip_svc_entry *eip_tr_aead_get_svc(void);
size_t eip_tr_aead_get_svc_len(void);
const struct eip_svc_entry *eip_tr_ipsec_get_svc(void);
size_t eip_tr_ipsec_get_svc_len(void);

bool eip_tr_ahash_key2digest(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo);
void eip_tr_get_stats(struct eip_tr *tr, struct eip_tr_stats *stats);
void eip_tr_final(struct kref *kref);
int eip_tr_classify_err(uint16_t cle_err, uint16_t tr_err);

/*
 * eip_tr_ref()
 *	Increment transform record reference.
 */
static inline struct eip_tr *eip_tr_ref(struct eip_tr *tr)
{
	kref_get(&tr->ref);
	return tr;
}

/*
 * eip_tr_deref()
 *	Decrement transform record reference.
 */
static inline void eip_tr_deref(struct eip_tr *tr)
{
	kref_put(&tr->ref, eip_tr_final);
}

#endif /* __EIP_TR_H */
