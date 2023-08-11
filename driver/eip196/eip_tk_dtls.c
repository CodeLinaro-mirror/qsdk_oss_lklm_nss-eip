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

#include "eip_priv.h"

/*
 * eip_tk_dtls_encauth_cbc()
 *      Fill tokens for dtls outbound traffic.
 */
uint8_t eip_tk_dtls_encauth_cbc(struct eip_tk *tk, struct eip_tr *tr, eip_req_t eip_req, uint32_t *cmd_tk_hdr)
{
	BUG_ON(1);

	/*
	 * Total token words.
	 */
	return (tk_word - tk->words);
}

/*
 * eip_tk_dtls_authdec_cbc()
 *      Fill tokens for dtls inbound traffic.
 */
uint8_t eip_tk_dtls_authdec_cbc(struct eip_tk *tk, struct eip_tr *tr, eip_req_t eip_req, uint32_t *cmd_tk_hdr)
{
	BUG_ON(1);

	/*
	 * Total token words.
	 */
	return (tk_word - tk->words);
}
