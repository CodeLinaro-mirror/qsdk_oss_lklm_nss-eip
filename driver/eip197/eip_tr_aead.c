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

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <asm/cacheflush.h>

#include <crypto/md5.h>
#include <crypto/sha.h>
#include <crypto/sha3.h>
#include <crypto/aes.h>

#include "eip_priv.h"

/*
 * Global constant algorith information.
 */
static const struct eip_svc_entry aead_algo_list[] = {
	/*
	 * TODO: Fill algo database.
	 */
};

/*
 * eip_tr_aead_init()
 *	Initialize the transform record for Crypto AEAD.
 */
bool eip_tr_aead_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo)
{
	struct eip_tr_info_crypto *crypto = &info->crypto;
	struct eip_tr_base *base = &info->base;
	uint32_t *tr_words = tr->tr_ptr;
	uint32_t size;

	/*
	 * We use large record for aead.
	 */
	tr->tr_addr_type = EIP_HW_CTX_TYPE_LARGE;
	tr->tr_addr_type |= virt_to_phys(tr->tr_ptr);
	tr->digest_len = algo->auth_digest_len;
	tr->ctrl_words[0] = algo->ctrl_words_0;
	tr->ctrl_words[1] = algo->ctrl_words_1;
	tr->nonce = base->nonce;

	tr->crypto.enc.tk_fill = algo->enc_tk_fill;
	tr->crypto.enc.cb = crypto->enc_cb;
	tr->crypto.enc.err_cb = crypto->enc_err_cb;
	tr->crypto.dec.tk_fill = algo->dec_tk_fill;
	tr->crypto.dec.cb = crypto->dec_cb;
	tr->crypto.dec.err_cb = crypto->dec_err_cb;
	tr->crypto.auth.tk_fill = NULL;
	tr->crypto.auth.cb = NULL;
	tr->crypto.auth.err_cb = NULL;
	tr->crypto.app_data = crypto->app_data;

	/*
	 * For crypto, Control words are in tokens.
	 */
	*tr_words++ = 0;
	*tr_words++ = 0;

	/*
	 * Fill cipher key.
	 */
	memcpy(tr_words, base->cipher.key_data, base->cipher.key_len);
	tr_words += (base->cipher.key_len /  sizeof(uint32_t));

	/*
	 * Leave the space for inner & outer digest.
	 */
	size = algo->auth_state_len;
	tr_words += (size / sizeof(uint32_t));
	tr_words += (size / sizeof(uint32_t));

	/*
	 * Flush record memory.
	 * Driver must not make any update in transform records words after this.
	 * EIP197 will do ipad/opad update.
	 */
	dmac_clean_range(tr->tr_ptr, tr->tr_ptr + EIP_HW_CTX_SIZE_LARGE_BYTES);

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
 * eip_tr_aead_get_svc()
 *	Get algo database for aead.
 */
const struct eip_svc_entry *eip_tr_aead_get_svc(void)
{
	return aead_algo_list;
}

/*
 * eip_tr_aead_get_svc_len()
 *	Get algo database length for aead.
 */
size_t eip_tr_aead_get_svc_len(void)
{
	return ARRAY_SIZE(aead_algo_list);
}
