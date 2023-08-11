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
#include <linux/slab.h>
#include <linux/completion.h>
#include <asm/cacheflush.h>
#include <net/ip.h>
#include <net/dsfield.h>

#include "eip_priv.h"

/*
 * eip_tr_dtls_enc()
 *	DTLS Encapsulation.
 */
int eip_tr_dtls_enc(struct eip_tr *tr, struct sk_buff *skb)
{
	/*
	 * TODO: Perform preprocessing on packet and transmit to hardware for transformation.
	 */
	return -1;
}
EXPORT_SYMBOL(eip_tr_dtls_enc);

/*
 * eip_tr_dtls_enc_cmn_init()
 *	Initialize the transform record for DTLS encapsulation.
 */
void eip_tr_dtls_enc_cmn_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo, bool nonce_en)
{
	/*
	 * TODO: Initialize TR for common encapsulation configuration.
	 */
	BUG_ON(1);
}
