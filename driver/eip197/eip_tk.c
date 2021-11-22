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

#include "eip_priv.h"

/*
 * eip_tk_encauth_cbc()
 *	Fill tokens for AEAD outbound traffic.
 */
uint8_t eip_tk_encauth_cbc(struct eip_tk *tk, struct eip_tr *tr, eip_req_t eip_req, uint32_t *cmd_tk_hdr)
{
	struct aead_request *req = eip_req2aead_request(eip_req);
	uint16_t data_len = req->cryptlen + req->assoclen;
	uint16_t auth_digest_len = tr->digest_len;
	uint32_t *iv_word = (uint32_t *)req->iv;
	uint16_t auth_len = req->assoclen;
	uint32_t *tk_word = tk->words;

	/*
	 * Fill token control info.
	 */
	*tk_word++ = tr->ctrl_words[0] | EIP_TK_CTRL_OP_ENC_HMAC;
	*tk_word++ = tr->ctrl_words[1];

	/*
	 * We construct IV here.
	 */
	*tk_word++ = iv_word[0];
	*tk_word++ = iv_word[1];
	*tk_word++ = iv_word[2];
	*tk_word++ = iv_word[3];

	/*
	 * Fill the instructions.
	 */
	*tk_word++ = EIP_TK_INST_HMAC | auth_len;			/* Pure hash. */
	*tk_word++ = EIP_TK_INST_ENC_HMAC | (data_len - auth_len);	/* Encryption + Hash. */
	*tk_word++ = EIP_TK_INST_NOPAD_ENC_HMAC;			/* Don't pad before enc + hash.*/
	*tk_word++ = EIP_TK_INST_HMAC_ADD | auth_digest_len;		/* Insert generated hash.*/

	/*
	 * Fill token header.
	 */
	*cmd_tk_hdr |= EIP_HW_TOKEN_HDR_CRYPTO_IV16;
	*cmd_tk_hdr |= (EIP_HW_TOKEN_HDR_OUTBOUND | data_len);

	/*
	 * Total token words.
	 */
	return (tk_word - tk->words);
}
EXPORT_SYMBOL(eip_tk_encauth_cbc);

/*
 * eip_tk_authdec_cbc()
 *	Fill tokens for AEAD inbound traffic.
 */
uint8_t eip_tk_authdec_cbc(struct eip_tk *tk, struct eip_tr *tr, eip_req_t eip_req, uint32_t *cmd_tk_hdr)
{
	struct aead_request *req = eip_req2aead_request(eip_req);
	uint16_t data_len = req->cryptlen + req->assoclen;
	uint16_t auth_digest_len = tr->digest_len;
	uint32_t *iv_word = (uint32_t *)req->iv;
	uint16_t auth_len = req->assoclen;
	uint32_t *tk_word = tk->words;

	/*
	 * Fill token control info.
	 */
	*tk_word++ = tr->ctrl_words[0] | EIP_TK_CTRL_OP_HMAC_DEC;
	*tk_word++ = tr->ctrl_words[1];

	/*
	 * We construct IV here.
	 */
	*tk_word++ = iv_word[0];
	*tk_word++ = iv_word[1];
	*tk_word++ = iv_word[2];
	*tk_word++ = iv_word[3];

	/*
	 * Fill instructions.
	 */
	*tk_word++ = EIP_TK_INST_HMAC | auth_len;					/* Pure hash */
	*tk_word++ = EIP_TK_INST_HMAC_DEC | (data_len - auth_len - auth_digest_len);	/* Perform hash before decryption. */
	*tk_word++ = EIP_TK_INST_HMAC_GET | auth_digest_len;				/* Fetch hash/pad */
	*tk_word++ = EIP_TK_INST_HMAC_CHK | auth_digest_len;				/* Verify hash */

	/*
	 * Fill token control data.
	 */
	*cmd_tk_hdr |= EIP_HW_TOKEN_HDR_CRYPTO_IV16;
	*cmd_tk_hdr |= (EIP_HW_TOKEN_HDR_INBOUND | data_len);

	/*
	 * Total token words.
	 */
	return (tk_word - tk->words);
}
EXPORT_SYMBOL(eip_tk_authdec_cbc);

/*
 * eip_tk_encauth_ctr_rfc()
 *	Fill tokens for AEAD outbound traffic.
 */
uint8_t eip_tk_encauth_ctr_rfc(struct eip_tk *tk, struct eip_tr *tr, eip_req_t eip_req, uint32_t *cmd_tk_hdr)
{
	struct aead_request *req = eip_req2aead_request(eip_req);
	uint16_t data_len = req->cryptlen + req->assoclen;
	uint16_t auth_digest_len = tr->digest_len;
	uint32_t *iv_word = (uint32_t *)req->iv;
	uint16_t auth_len = req->assoclen;
	uint32_t *tk_word = tk->words;

	/*
	 * Fill token control info.
	 */
	*tk_word++ = tr->ctrl_words[0] | EIP_TK_CTRL_OP_ENC_HMAC;
	*tk_word++ = tr->ctrl_words[1];

	/*
	 * We construct IV here from cached nonce during setkey.
	 * Byte[0]: nonce from key.
	 * Byte[1]: IV[0] from request.
	 * Byte[2]: IV[1] from request.
	 * Byte[3]: Counter set to 1.
	 */
	*tk_word++ = tr->nonce;
	*tk_word++ = iv_word[0];
	*tk_word++ = iv_word[1];
	*tk_word++ = ntohl(0x1);

	/*
	 * Fill the encryption and hmac instructions.
	 */
	*tk_word++ = EIP_TK_INST_HMAC | auth_len;			/* Pure hash */
	*tk_word++ = EIP_TK_INST_ENC_HMAC | (data_len - auth_len);	/* Encryption + Hash */
	*tk_word++ = EIP_TK_INST_NOPAD_ENC_HMAC;			/* Don't do padding */
	*tk_word++ = EIP_TK_INST_HMAC_ADD | auth_digest_len;		/* Insert hash */

	/*
	 * Fill token header.
	 */
	*cmd_tk_hdr |= EIP_HW_TOKEN_HDR_CRYPTO_IV16;
	*cmd_tk_hdr |= (EIP_HW_TOKEN_HDR_OUTBOUND | data_len);

	/*
	 * Total token words.
	 */
	return (tk_word - tk->words);
}
EXPORT_SYMBOL(eip_tk_encauth_ctr_rfc);

/*
 * eip_tk_authdec_ctr_rfc()
 *	Fill tokens for AEAD inbound traffic.
 */
uint8_t eip_tk_authdec_ctr_rfc(struct eip_tk *tk, struct eip_tr *tr, eip_req_t eip_req, uint32_t *cmd_tk_hdr)
{
	struct aead_request *req = eip_req2aead_request(eip_req);
	uint16_t data_len = req->cryptlen + req->assoclen;
	uint16_t auth_digest_len = tr->digest_len;
	uint32_t *iv_word = (uint32_t *)req->iv;
	uint16_t auth_len = req->assoclen;
	uint32_t *tk_word = tk->words;

	/*
	 * Fill token control info.
	 */
	*tk_word++ = tr->ctrl_words[0] | EIP_TK_CTRL_OP_HMAC_DEC;
	*tk_word++ = tr->ctrl_words[1];

	/*
	 * We construct IV here from cached nonce during setkey.
	 * Byte[0]: nonce from key.
	 * Byte[1]: IV[0] from request.
	 * Byte[2]: IV[1] from request.
	 * Byte[3]: Counter set to 1.
	 */
	*tk_word++ = tr->nonce;
	*tk_word++ = iv_word[0];
	*tk_word++ = iv_word[1];
	*tk_word++ = ntohl(0x1);

	/*
	 * Fill instructions.
	 */
	*tk_word++ = EIP_TK_INST_HMAC | auth_len;					/* Pure hash */
	*tk_word++ = EIP_TK_INST_HMAC_DEC | (data_len - auth_len - auth_digest_len);	/* Encryption + Hash */
	*tk_word++ = EIP_TK_INST_HMAC_GET | auth_digest_len;				/* Fetch hash/pad */
	*tk_word++ = EIP_TK_INST_HMAC_CHK | auth_digest_len;				/* Verify hash */

	/*
	 * Fill control header.
	 */
	*cmd_tk_hdr |= EIP_HW_TOKEN_HDR_CRYPTO_IV16;
	*cmd_tk_hdr |= (EIP_HW_TOKEN_HDR_INBOUND | data_len);

	/*
	 * Total token words.
	 */
	return (tk_word - tk->words);
}
EXPORT_SYMBOL(eip_tk_authdec_ctr_rfc);
