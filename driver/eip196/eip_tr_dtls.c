/*
 * Copyright (c) 2023, Qualcomm Innovation Center, Inc. All rights reserved.
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

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/crypto.h>
#include <crypto/aead.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <asm/cacheflush.h>

#include <crypto/md5.h>
#include <crypto/sha.h>
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

/*
 * Global constant algorithm information.
 */
static const struct eip_svc_entry dtls_algo_list[] = {
	{
		.name = "eip-aes-cbc-sha1-hmac",
		.enc_tk_fill = &eip_tk_dtls_encauth_cbc,
		.dec_tk_fill = &eip_tk_dtls_authdec_cbc,
		.tr_init = eip_tr_dtls_aes_cbc_init,
		.auth_digest_len = SHA1_DIGEST_SIZE,
		.auth_block_len = SHA1_BLOCK_SIZE,
		.auth_state_len = EIP_HW_PAD_KEYSZ_SHA1,
		.ctrl_words_0 = EIP_HW_CTX_WITH_KEY | EIP_HW_CTX_ALGO_SHA1 |
			EIP_HW_CTX_AUTH_MODE_HMAC | EIP_TR_IPSEC_SPI | EIP_TR_DTLS_CTX0_SEQNO,
		.ctrl_words_1 = EIP_HW_CTX_CIPHER_MODE_CBC | EIP_TR_DTLS_CTX1_PAD_TLS | EIP_TR_CTRL_SEQ_NUM_STORE | EIP_TR_DTLS_CTX1_HASH_STORE,
		.iv_len = AES_BLOCK_SIZE,
		.cipher_blk_len = AES_BLOCK_SIZE
	}
};

/*
 * eip_tr_dtls_aes_cbc_init()
 *	Initialize the transform record for DTLS/AES-CBC.
 */
static bool eip_tr_dtls_aes_cbc_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo)
{
	/*
	 * TODO: Initialize Transform record.
	 */
	BUG_ON(1);

	return false;
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
