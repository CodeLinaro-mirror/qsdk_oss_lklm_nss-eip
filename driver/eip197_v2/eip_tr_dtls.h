/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#ifndef __EIP_TR_DTLS_H
#define __EIP_TR_DTLS_H

#include "eip.h"

#define EIP_TR_DTLS_TRAILER 0x1U
#define EIP_TR_DTLS_VERSION(x) ((x) << 16)
#define EIP_TR_DTLS_EPOCH(x) ((x) << 16)
#define EIP_TR_DTLS_SEQ_START 0x1U

/*
 * DTLS transformation APIs.
 */
void eip_tr_dtls_dec_cmn_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo);
void eip_tr_dtls_enc_cmn_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo);
void eip_tr_dtls_tx_done(struct eip_tr *tr, struct eip_hw_desc *hw, struct eip_sw_desc *sw);
const struct eip_svc_entry *eip_tr_dtls_get_svc(void);
size_t eip_tr_dtls_get_svc_len(void);

#endif /* __EIP_TR_DTLS_H */
