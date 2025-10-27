/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include "eip_priv.h"
#include "eip_tr.h"
#include "eip.h"

/*
 * eip_tr_dtls_dec_cmn_init()
 *	Common decap initialization
 */
void eip_tr_dtls_dec_cmn_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo)
{
	return;
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
