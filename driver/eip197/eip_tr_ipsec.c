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
static const struct eip_svc_entry ipsec_algo_list[] = {
	/*
	 * TODO: Fill algo database.
	 */
};

/*
 * eip_tr_ipsec_init()
 *	Initialize the transform record for ipsec.
 */
bool eip_tr_ipsec_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo)
{
	return false;
}

/*
 * eip_tr_ipsec_get_svc()
 *	Get algo database for ipsec.
 */
const struct eip_svc_entry *eip_tr_ipsec_get_svc(void)
{
	return ipsec_algo_list;
}

/*
 * eip_tr_ipsec_get_svc_len()
 *	Get algo database length for ipsec.
 */
size_t eip_tr_ipsec_get_svc_len(void)
{
	return ARRAY_SIZE(ipsec_algo_list);
}
