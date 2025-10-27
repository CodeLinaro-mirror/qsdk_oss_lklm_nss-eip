/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/crypto.h>
#include <crypto/aead.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <crypto/md5.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/sha3.h>
#include <crypto/aes.h>
#include <crypto/des.h>
#include <crypto/ghash.h>
#include <crypto/gcm.h>

#include "eip_priv.h"

/*
 * Forward declaration for tr_init functions.
 */
static bool eip_tr_dtls_aes_cbc_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo);
static bool eip_tr_dtls_des_cbc_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo);
static bool eip_tr_dtls_aes_gcm_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo);

/*
 * Global constant algorithm information.
 */
static const struct eip_svc_entry dtls_algo_list[] = {
	{
		.name = "eip-aes-cbc-sha1-hmac",
		.tr_init = eip_tr_dtls_aes_cbc_init,
		.auth_digest_len = SHA1_DIGEST_SIZE,
		.auth_block_len = SHA1_BLOCK_SIZE,
		.auth_state_len = EIP_HW_PAD_KEYSZ_SHA1,
		.ctrl_words_0 = EIP_HW_CTX_WITH_KEY | EIP_HW_CTX_ALGO_SHA1 |
			EIP_HW_CTX_AUTH_MODE_HMAC | EIP_TR_DTLS_PROTO_VER | EIP_TR_DTLS_CTX0_SEQNO,
		.ctrl_words_1 = EIP_HW_CTX_CIPHER_MODE_CBC | EIP_TR_DTLS_CTX1_PAD_TLS | EIP_TR_CTRL_SEQ_NUM_STORE,
		.iv_len = AES_BLOCK_SIZE,
		.cipher_blk_len = AES_BLOCK_SIZE
	},
	{
		.name = "eip-aes-cbc-sha256-hmac",
		.tr_init = eip_tr_dtls_aes_cbc_init,
		.auth_digest_len = SHA256_DIGEST_SIZE,
		.auth_block_len = SHA256_BLOCK_SIZE,
		.auth_state_len = EIP_HW_PAD_KEYSZ_SHA256,
		.ctrl_words_0 = EIP_HW_CTX_WITH_KEY | EIP_HW_CTX_ALGO_SHA256 |
			EIP_HW_CTX_AUTH_MODE_HMAC | EIP_TR_DTLS_PROTO_VER | EIP_TR_DTLS_CTX0_SEQNO,
		.ctrl_words_1 = EIP_HW_CTX_CIPHER_MODE_CBC | EIP_TR_DTLS_CTX1_PAD_TLS | EIP_TR_CTRL_SEQ_NUM_STORE,
		.iv_len = AES_BLOCK_SIZE,
		.cipher_blk_len = AES_BLOCK_SIZE
	},
	{
		.name = "eip-3des-cbc-sha1-hmac",
		.tr_init = eip_tr_dtls_des_cbc_init,
		.auth_digest_len = SHA1_DIGEST_SIZE,
		.auth_block_len = SHA1_BLOCK_SIZE,
		.auth_state_len = EIP_HW_PAD_KEYSZ_SHA1,
		.ctrl_words_0 = EIP_HW_CTX_WITH_KEY | EIP_HW_CTX_ALGO_SHA1 |
			EIP_HW_CTX_AUTH_MODE_HMAC | EIP_TR_DTLS_PROTO_VER | EIP_TR_DTLS_CTX0_SEQNO,
		.ctrl_words_1 = EIP_HW_CTX_CIPHER_MODE_CBC | EIP_TR_DTLS_CTX1_PAD_TLS | EIP_TR_CTRL_SEQ_NUM_STORE,
		.iv_len = DES3_EDE_BLOCK_SIZE,
		.cipher_blk_len = DES3_EDE_BLOCK_SIZE
	},
	{
		.name = "eip-3des-cbc-sha256-hmac",
		.tr_init = eip_tr_dtls_des_cbc_init,
		.auth_digest_len = SHA256_DIGEST_SIZE,
		.auth_block_len = SHA256_BLOCK_SIZE,
		.auth_state_len = EIP_HW_PAD_KEYSZ_SHA256,
		.ctrl_words_0 = EIP_HW_CTX_WITH_KEY | EIP_HW_CTX_ALGO_SHA256 |
			EIP_HW_CTX_AUTH_MODE_HMAC | EIP_TR_DTLS_PROTO_VER | EIP_TR_DTLS_CTX0_SEQNO,
		.ctrl_words_1 = EIP_HW_CTX_CIPHER_MODE_CBC | EIP_TR_DTLS_CTX1_PAD_TLS | EIP_TR_CTRL_SEQ_NUM_STORE,
		.iv_len = DES3_EDE_BLOCK_SIZE,
		.cipher_blk_len = DES3_EDE_BLOCK_SIZE
	},
	{
		.name = "eip-aes-gcm",
		.tr_init = eip_tr_dtls_aes_gcm_init,
		.auth_digest_len = GHASH_DIGEST_SIZE,
		.auth_block_len = GHASH_BLOCK_SIZE,
		.auth_state_len = 0,
		.ctrl_words_0 = EIP_HW_CTX_WITH_KEY | EIP_HW_CTX_ALGO_GHASH |
			EIP_HW_CTX_AUTH_MODE_GMAC | EIP_TR_DTLS_PROTO_VER | EIP_TR_DTLS_CTX0_SEQNO,
		.ctrl_words_1 = EIP_HW_CTX_CIPHER_MODE_GCM | EIP_TR_CTRL_SEQ_NUM_STORE |
			EIP_TR_DTLS_CONTROL_IV(1) | EIP_TR_DTLS_IV_FORMAT(1),	/* GCM uses nonce and CTR mode */
		.iv_len = 8,
		.cipher_blk_len = 1 /* GCM doesn't require block alignment */
	}
};

/*
 * eip_tr_dtls_cmn_init()
 *	Initialize the transform record for DTLS.
 */
static void eip_tr_dtls_cmn_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo)
{
	struct eip_tr_info_dtls *dtls = &info->dtls;
	bool enc = !!(dtls->flags & EIP_TR_DTLS_FLAG_ENC);
	bool ipv6 = !!(dtls->flags & EIP_TR_DTLS_FLAG_IPV6);
	bool capwap = !!(dtls->flags & EIP_TR_DTLS_FLAG_CAPWAP);
	uint32_t *tr_words = tr->hw_words;
	uint32_t proto;

	/*
	 * Initialise TR and derive ohdr proto based on capwap an ipv6 values
	 */
	if (enc) {
		eip_tr_dtls_enc_cmn_init(tr, info, algo);

		proto = capwap
			? (ipv6 ? EIP_TR_DTLS_CAPWAP_OHDR_PROTO_V6_OUT
					: EIP_TR_DTLS_CAPWAP_OHDR_PROTO_V4_OUT)
			: (ipv6 ? EIP_TR_DTLS_OHDR_PROTO_V6_OUT
					: EIP_TR_DTLS_OHDR_PROTO_V4_OUT);
	} else {
		eip_tr_dtls_dec_cmn_init(tr, info, algo);

		proto = capwap
			? (ipv6 ? EIP_TR_DTLS_CAPWAP_OHDR_PROTO_V6_IN
					: EIP_TR_DTLS_CAPWAP_OHDR_PROTO_V4_IN)
			: (ipv6 ? EIP_TR_DTLS_OHDR_PROTO_V6_IN
					: EIP_TR_DTLS_OHDR_PROTO_V4_IN);
	}

	/*
	 * Set OHdr Proto (word 68 bits [23:16]) so EIP knows the outer header
	 * type and whether CAPWAP preamble is present. Without this EIP does not
	 * remove the CAPWAP header on inbound and does not insert it on outbound.
	 */
	tr_words[68] |= EIP_TR_DTLS_OHDR_PROTO(proto);

	/*
	 * For decap, set the CAPWAP bit in the static token header (tr_words[64])
	 * so the firmware processes the CAPWAP preamble on inbound packets.
	 */
	if (!enc && capwap)
		tr_words[64] |= EIP_TR_DTLS_DECAP_TOKEN_CAPWAP;

	/*
	 * We use large record for dtls.
	 */
	tr->tr_addr_type = EIP_HW_CTX_TYPE_LARGE;
	tr->tr_addr_type |= virt_to_phys(tr->hw_words);
	tr->tr_flags = dtls->flags;
	tr->ctrl_words[0] = tr_words[0];
	tr->ctrl_words[1] = tr_words[1];
	tr->nonce = info->base.nonce;
	tr->iv_len = algo->iv_len;
	tr->blk_len = algo->cipher_blk_len;
	tr->digest_len = algo->auth_digest_len;

	tr->dtls.ops.tk_fill = NULL;
	tr->dtls.ops.cb = dtls->cb;
	tr->dtls.ops.err_cb = dtls->err_cb;
	tr->dtls.app_data = dtls->app_data;

	memcpy(tr->bypass, &dtls->ppe_mdata, sizeof(tr->bypass));
}

/*
 * eip_tr_dtls_aes_cbc_init()
 *	Initialize the transform record for DTLS/AES-CBC.
 */
static bool eip_tr_dtls_aes_cbc_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo)
{
	struct eip_tr_info_dtls *dtls = &info->dtls;
	struct eip_tr_base *crypto = &info->base;
	uint32_t *tr_words = tr->hw_words;
	bool enc;

	/*
	 * We first do common initialization and then algo specific initialization.
	 */
	eip_tr_dtls_cmn_init(tr, info, algo);

	switch (crypto->cipher.key_len) {
	case AES_KEYSIZE_128:
		tr_words[0] |= EIP_HW_CTX_ALGO_AES128;
		tr->ctrl_words[0] |= EIP_HW_CTX_ALGO_AES128;
		break;
	case AES_KEYSIZE_192:
		tr_words[0] |= EIP_HW_CTX_ALGO_AES192;
		tr->ctrl_words[0] |= EIP_HW_CTX_ALGO_AES192;
		break;
	case AES_KEYSIZE_256:
		tr_words[0] |= EIP_HW_CTX_ALGO_AES256;
		tr->ctrl_words[0] |= EIP_HW_CTX_ALGO_AES256;
		break;
	default:
		pr_err("%px: Invalid key length(%u)\n", tr, crypto->cipher.key_len);
		return false;
	}

	enc = !!(dtls->flags & EIP_TR_DTLS_FLAG_ENC);
	if (enc) {
		tr_words[0] |= EIP_TK_CTRL_OP_HMAC_ENC;
		tr_words[64] = EIP_TR_DTLS_ENCAP_TOKEN_HDR;
		tr_words[66] |= EIP_TR_DTLS_WINDOW_4BYTE(dtls->replay);
		tr_words[68] |= EIP_TR_DTLS_PROTO(EIP_TR_DTLS_PROTO_OUT_CBC);
	} else {
		tr_words[0] |= EIP_TK_CTRL_OP_DEC_HMAC;
		tr_words[64] |= EIP_TR_DTLS_DECAP_TOKEN_HDR;
		tr_words[68] |= EIP_TR_DTLS_PROTO(EIP_TR_DTLS_PROTO_IN_CBC);
	}

	tr_words[66] |= EIP_TR_DTLS_PAD_2BYTE(algo->cipher_blk_len);

	/*
	 * Flush record memory.
	 * Driver must not make any update in transform records words after this.
	 */
	eip_dmac_clean_range(tr->hw_words, tr->hw_words + EIP_HW_CTX_SIZE_LARGE_WORDS);

	/*
	 * HMAC Inner and Outer Digest Precalculation
	 */
	if (!eip_tr_ahash_key2digest(tr, info, algo)) {
		pr_err("%px: Digest computation failed for algo(%s)\n", tr, algo->name);
		return false;
	}

	return true;
}

/*
 * eip_tr_dtls_des_cbc_init()
 *	Initialize the transform record for DTLS/AES-CBC.
 */
static bool eip_tr_dtls_des_cbc_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo)
{
	struct eip_tr_base *crypto = &info->base;
	uint32_t *tr_words = tr->hw_words;
	bool enc;

	/*
	 * We first do common initialization and then algo specific initialization.
	 */
	eip_tr_dtls_cmn_init(tr, info, algo);

	switch (crypto->cipher.key_len) {
	case DES3_EDE_KEY_SIZE:
		tr_words[0] |= EIP_HW_CTX_ALGO_3DES;
		tr->ctrl_words[0] |= EIP_HW_CTX_ALGO_3DES;
		break;
	default:
		pr_err("%px: Invalid key length(%u)\n", tr, crypto->cipher.key_len);
		return false;
	}

	enc = !!(info->dtls.flags & EIP_TR_DTLS_FLAG_ENC);
	if (enc) {
		tr_words[0] |= EIP_TK_CTRL_OP_HMAC_ENC;
		tr_words[64] = EIP_TR_DTLS_ENCAP_TOKEN_HDR;
		tr_words[66] |= EIP_TR_DTLS_WINDOW_4BYTE(info->dtls.replay);
		tr_words[68] |= EIP_TR_DTLS_PROTO(EIP_TR_DTLS_PROTO_OUT_CBC);
	} else {
		tr_words[0] |= EIP_TK_CTRL_OP_DEC_HMAC;
		tr_words[64] |= EIP_TR_DTLS_DECAP_TOKEN_HDR;
		tr_words[68] |= EIP_TR_DTLS_PROTO(EIP_TR_DTLS_PROTO_IN_CBC);
	}

	tr_words[66] |= EIP_TR_DTLS_PAD_2BYTE(algo->cipher_blk_len);

	/*
	 * Flush record memory.
	 * Driver must not make any update in transform records words after this.
	 */
	eip_dmac_clean_range(tr->hw_words, tr->hw_words + EIP_HW_CTX_SIZE_LARGE_WORDS);

	/*
	 * HMAC Inner and Outer Digest Precalculation
	 */
	if (!eip_tr_ahash_key2digest(tr, info, algo)) {
		pr_err("%px: Digest computation failed for algo(%s)\n", tr, algo->name);
		return false;
	}

	return true;
}

/*
 * eip_tr_dtls_aes_gcm_init()
 *	Initialize the transform record for DTLS/AES-GCM.
 */
static bool eip_tr_dtls_aes_gcm_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo)
{
	struct eip_tr_info_dtls *dtls = &info->dtls;
	struct eip_tr_base *crypto = &info->base;
	uint8_t authkey[AES_BLOCK_SIZE] = {0};
	uint32_t *tr_words = tr->hw_words;
	uint32_t *doffset = NULL;
	uint32_t *key = NULL;
	uint8_t auth_key_idx;
	int err;
	bool enc;

	/*
	 * We first do common initialization and then algo specific initialization.
	 */
	eip_tr_dtls_cmn_init(tr, info, algo);

	switch (crypto->cipher.key_len) {
	case AES_KEYSIZE_128:
		tr_words[0] |= EIP_HW_CTX_ALGO_AES128;
		tr->ctrl_words[0] |= EIP_HW_CTX_ALGO_AES128;
		break;
	case AES_KEYSIZE_192:
		tr_words[0] |= EIP_HW_CTX_ALGO_AES192;
		tr->ctrl_words[0] |= EIP_HW_CTX_ALGO_AES192;
		break;
	case AES_KEYSIZE_256:
		tr_words[0] |= EIP_HW_CTX_ALGO_AES256;
		tr->ctrl_words[0] |= EIP_HW_CTX_ALGO_AES256;
		break;
	default:
		pr_err("%px: Invalid key length(%u)\n", tr, crypto->cipher.key_len);
		return false;
	}

	enc = !!(dtls->flags & EIP_TR_DTLS_FLAG_ENC);
	if (enc) {
		tr_words[0] |= EIP_TK_CTRL_OP_ENC_HMAC;
		tr_words[64] |= EIP_TR_DTLS_ENCAP_TOKEN_HDR_GCM;
		tr_words[68] |= EIP_TR_DTLS_PROTO(EIP_TR_DTLS_PROTO_OUT_GCM);
	} else {
		tr_words[0] |= EIP_TK_CTRL_OP_HMAC_DEC;
		tr_words[1] &= ~EIP_TR_DTLS_CTX1_PRE_CRYPTO_DECAP;
		tr_words[64] |= EIP_TR_DTLS_DECAP_TOKEN_HDR_GCM;
		tr_words[65] |= EIP_TR_DTLS_PAD_2BYTE(algo->cipher_blk_len);
		tr_words[68] |= EIP_TR_DTLS_PROTO(EIP_TR_DTLS_PROTO_IN_GCM);
	}

	/*
	 * Generate and fill ghash key.
	 * Here we are using software for generation of the keys
	 */
	err = eip_tr_genkey(tr, info, (uint8_t *)authkey, algo->auth_block_len);
	if (err) {
		pr_warn("Failed to generate authentication key for GCM with err <%x>\n", err);
		return false;
	}

	auth_key_idx = EIP_HW_CTRL_WORDS + (crypto->cipher.key_len / sizeof(uint32_t));
	doffset = &tr_words[auth_key_idx];

	key = (uint32_t *)authkey;
	doffset[0] = ntohl(key[0]);
	doffset[1] = ntohl(key[1]);
	doffset[2] = ntohl(key[2]);
	doffset[3] = ntohl(key[3]);

	/*
	 * Flush record memory.
	 * Driver must not make any update in transform records words after this.
	 */
	eip_dmac_clean_range(tr->hw_words, tr->hw_words + EIP_HW_CTX_SIZE_LARGE_WORDS);

	return true;
}

/*
 * eip_tr_dtls_tx_done()
 *	Hardware tx completion callback API for Encapsulation/Decapsulation.
 */
void eip_tr_dtls_tx_done(struct eip_tr *tr, struct eip_hw_desc *hw, struct eip_sw_desc *sw)
{
	struct sk_buff *skb = eip_req2skb(sw->req);
	struct eip_ctx *ctx = tr->ctx;

	/*
	 * Free the SKB.
	 */
	consume_skb(skb);
	kmem_cache_free(ctx->sw_cache, sw);

	/*
	 * Dereference: eip_tr_dtls_enc/dec()
	 */
	eip_tr_deref(tr);
}

/*
 * eip_tr_dtls_get_svc()
 *	Get algo database for DTLS.
 */
const struct eip_svc_entry *eip_tr_dtls_get_svc(void)
{
	return dtls_algo_list;
}

/*
 * eip_tr_dtls_get_svc_len()
 *	Get algo database length for dtls.
 */
size_t eip_tr_dtls_get_svc_len(void)
{
	return ARRAY_SIZE(dtls_algo_list);
}
