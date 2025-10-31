/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <net/dsfield.h>

#include "eip_priv.h"

/*
 * eip_tr_dtls_get_replay_words()
 */
static uint32_t eip_tr_dtls_get_replay_words(enum eip_dtls_replay replay)
{
	switch (replay) {
	case EIP_DTLS_REPLAY_NONE:
		return 0;
	case EIP_DTLS_REPLAY_64:
		return 2;
	case EIP_DTLS_REPLAY_128:
	default:
		return 4;
	}
}

/*
 * eip_tr_dtls_get_replay_seq_mask()
 */
static uint32_t eip_tr_dtls_get_replay_seq_mask(enum eip_dtls_replay replay)
{
	switch (replay) {
	case EIP_DTLS_REPLAY_NONE:
		return 0;
	case EIP_DTLS_REPLAY_64:
		return EIP_TR_DTLS_CTX0_SEQNO_MASK64;
	case EIP_DTLS_REPLAY_128:
	default:
		return EIP_TR_DTLS_CTX0_SEQNO_MASK128;
	}
}

/*
 * eip_tr_dtls_dec_cmn_init()
 *      Initialize the transform record for dtls Decapsulation.
 */
void eip_tr_dtls_dec_cmn_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo)
{
	struct eip_tr_info_dtls *dtls = &info->dtls;
	struct eip_tr_dtls *tr_dtls = &tr->dtls;
	struct eip_tr_base *crypto = &info->base;
	uint32_t *crypt_words = tr->hw_words;
	uint32_t *tr_words = tr->hw_words;
	uint32_t seq_offset = 0;
	uint8_t mask_sz;
	uint32_t size;
	uint32_t mode;

	/*
	 * First two words are Control words.
	 */
	tr_words[0] = algo->ctrl_words_0;
	tr_words[1] = algo->ctrl_words_1;

	/*
	 * Enable DTLS Decap specific fields in control words.
	 */
	tr_words[0] |= eip_tr_dtls_get_replay_seq_mask(dtls->replay);
	tr_words[1] |= EIP_TR_DTLS_CTX1_PRE_CRYPTO_DECAP;

	/*
	 * Crypto variable words starts from third words.
	 */
	crypt_words = &tr_words[2];

	/*
	 * Fill cipher key.
	 */
	memcpy(crypt_words, crypto->cipher.key_data, crypto->cipher.key_len);
	crypt_words += (crypto->cipher.key_len /  sizeof(uint32_t));

	/*
	 * Leave the space for inner & outer digest / GHASH key.
	 * For GCM we store only GHASH key of size auth_block_len
	 * and for other algo we store inner & outer digest each
	 * of size auth_state_len.
	 */
	size = algo->auth_state_len ? (algo->auth_state_len * 2) : algo->auth_block_len;
	crypt_words += (size / sizeof(uint32_t));

	/*
	 * DTLS specific fields for EIP96.
	 */
	*crypt_words++ = EIP_TR_DTLS_VERSION(dtls->version);	/* Version */
	*crypt_words++ = 0x0;	/* Sequence number */
	*crypt_words++ = EIP_TR_DTLS_EPOCH(ntohs(dtls->epoch)); /* b0-15 is Sequence & B16-31 is epoch */

	/*
	 * Sequence update should not be done when window check is disabled.
	 */
	if (dtls->replay != EIP_DTLS_REPLAY_NONE) {
		ptrdiff_t offset = crypt_words - tr_words - 2;

		WARN_ON(offset > U8_MAX);
		seq_offset = offset;
	}

	/*
	 * Set all bits to '1' in mask.
	 */
	mask_sz = eip_tr_dtls_get_replay_words(dtls->replay);
	while (mask_sz--)
		*crypt_words++ = 0xFFFFFFFF;

	/*
	 * Fill nonce.
	 */
	if (crypto->nonce)
		*crypt_words++ = crypto->nonce;

	/*
	 * Done with EIP crypto context words.
	 * Update relative information in control words.
	 */
	tr_words[0] |= EIP_TR_CTRL_CONTEXT_WORDS(crypt_words - tr_words - 2);

	/*
	 * Store the seq no offset, icv length and cipher block length
	 * to be used during token fill
	 */
	tr_dtls->seq_offset = seq_offset;
	tr->digest_len = algo->auth_digest_len;
	tr->blk_len = algo->cipher_blk_len;
	tr->iv_len = algo->iv_len;

	/*
	 * Assign the pre & post procesing callback for IP header
	 */
	tr_dtls->ops.pre = NULL;
	tr_dtls->ops.post = NULL;
	tr_dtls->bypass_len = 0;
	tr_dtls->tk_hdr |= EIP_TR_DTLS_DECAP_TOKEN;

	mode = dtls->flags & (EIP_TR_DTLS_FLAG_UDPLITE | EIP_TR_DTLS_FLAG_CAPWAP | EIP_TR_DTLS_FLAG_IPV6);

	switch (mode) {
	case (EIP_TR_DTLS_FLAG_IPV6):
	case (EIP_TR_DTLS_FLAG_UDPLITE):
	case (EIP_TR_DTLS_FLAG_UDPLITE | EIP_TR_DTLS_FLAG_IPV6):
		WARN_ON(1);
		break;

	/* DTLS-CAPWAP IPv6 tunnel */
	case (EIP_TR_DTLS_FLAG_CAPWAP | EIP_TR_DTLS_FLAG_IPV6 | EIP_TR_DTLS_FLAG_UDPLITE):
	case (EIP_TR_DTLS_FLAG_CAPWAP | EIP_TR_DTLS_FLAG_IPV6):
		tr_words[65] |= EIP_TR_DTLS_IPV6_EN;
		tr_words[68] |= EIP_TR_DTLS_OHDR_PROTO(EIP_TR_DTLS_CAPWAP_OHDR_PROTO_V6_IN);
		tr_dtls->remove_len += sizeof(struct eip_capwap_hdr);
		tr_dtls->tk_hdr |= EIP_TR_DTLS_DECAP_TOKEN_CAPWAP;
		break;

	/* DTLS-CAPWAP IPv4 tunnel */
	case (EIP_TR_DTLS_FLAG_CAPWAP | EIP_TR_DTLS_FLAG_UDPLITE):
	case (EIP_TR_DTLS_FLAG_CAPWAP):
		tr_words[68] |= EIP_TR_DTLS_OHDR_PROTO(EIP_TR_DTLS_CAPWAP_OHDR_PROTO_V4_IN);
		tr_dtls->remove_len += sizeof(struct eip_capwap_hdr);
		tr_dtls->tk_hdr |= EIP_TR_DTLS_DECAP_TOKEN_CAPWAP;
		break;

	default:	/* DTLS IPv4 tunnel */
		tr_words[68] |= EIP_TR_DTLS_OHDR_PROTO(EIP_TR_DTLS_OHDR_PROTO_V4_IN);
		break;
	}

	/*
	 * Enable redirection for dtls
	 */
	if (tr->svc == EIP_SVC_HYBRID_DTLS) {
		struct eip_ctx *ctx = tr->ctx;
		tr_words[65] |= EIP_TR_REDIR_EN;
		tr_words[65] |= EIP_TR_REDIR_IFACE(ctx->dma[1].ring_id);
		pr_debug("%px: Redirection enable to ring(%u) for decap record\n", tr, ctx->dma[1].ring_id);
	}

	tr_words[66] = 0;
	tr_words[67] = 0; /* NPH context reference */
	tr_words[68] |= EIP_TR_DTLS_ICV_SIZE(algo->auth_digest_len);
	tr_words[68] |= EIP_TR_DTLS_IV_SIZE(algo->iv_len);
	tr_words[69] |= (dtls->version);
	tr_words[70] = EIP_TR_DTLS_DECAP_TOKEN_VERIFY(algo->auth_digest_len);
	tr_words[71] = EIP_TR_DTLS_DECAP_ESN_TOKEN_INST(seq_offset);
}

/*
 * eip_tr_dtls_dec()
 *	Decapsulation support
 */
int eip_tr_dtls_dec(struct eip_tr *tr, struct sk_buff *skb)
{
	pr_warn_once("%px: DTLS decap via lookaside path not yet implemented\n", tr);
	return -ENOTSUPP;
}
EXPORT_SYMBOL(eip_tr_dtls_dec);
