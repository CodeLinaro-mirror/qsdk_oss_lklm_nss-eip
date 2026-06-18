/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <net/ip.h>
#include <net/dsfield.h>

#include "eip_priv.h"

/*
 * eip_tr_dtls_enc_udp()
 *	Encapsulate UDP header.
 */
static inline void eip_tr_dtls_enc_udp(struct eip_tr *tr, struct sk_buff *skb)
{
	struct eip_tr_dtls *dtls = &tr->dtls;
	struct udphdr *udph;
	bool is_udplite;
	__be16 len;

	/*
	 * insert UDP header.
	 */
	udph = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);
	len = skb->len;

	/*
	 * UDPlite checksum will be calculated by EDMA.
	 */
	is_udplite = (dtls->protocol != IPPROTO_UDP);
	if (is_udplite) {
		len = (tr->tr_flags & EIP_TR_DTLS_FLAG_UDPLITE_CSUM) ? sizeof(struct udphdr) : 0;
	}

	udph->source = dtls->src_port;
	udph->dest = dtls->dst_port;
	udph->len = htons(len);
	udph->check = 0;
	skb->ip_summed = CHECKSUM_NONE;
}

/*
 * eip_tr_dtls_enc_v4()
 *	Outer IPv4 header addition before encapsulation.
 */
static void eip_tr_dtls_enc_v4(struct eip_tr *tr, struct sk_buff *skb)
{
	struct eip_tr_dtls *dtls = &tr->dtls;
	struct iphdr *iph;
	uint8_t tos;

	/*
	 * Calculate payload length including encrypted data length and fixed encapsulation header length.
	 * Pad length is updated in SKB CB for later use.
	 */
	tos = (tr->tr_flags & EIP_TR_DTLS_FLAG_CP_TOS) ? skb->priority : dtls->tos;

	/*
	 * insert UDP header.
	 */
	eip_tr_dtls_enc_udp(tr, skb);

	/*
	 * Insert IPv4 header.
	 */
	iph = (struct iphdr *)skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	skb->protocol = htons(ETH_P_IP);

	iph->version = IPVERSION;
	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->tos = tos;
	iph->tot_len = htons(skb->len);
	iph->id = htons(atomic_fetch_add(1, &dtls->ip_id) & 0xFFFF);
	iph->frag_off = dtls->ip_df;
	iph->ttl = dtls->ttl;
	iph->protocol = dtls->protocol;
	iph->saddr = dtls->src_ip[0];
	iph->daddr = dtls->dst_ip[0];

	/*
	 * Update the header checksum
	 */
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

/*
 * eip_tr_dtls_enc_v6()
 *	Outer IPv6 header addition before encapsulation.
 */
static void eip_tr_dtls_enc_v6(struct eip_tr *tr, struct sk_buff *skb)
{
	struct eip_tr_dtls *dtls = &tr->dtls;
	struct ipv6hdr *ip6h;
	uint16_t udp_len;
	uint8_t tos;

	/*
	 * Calculate payload length including encrypted data length and fixed encapsulation header length.
	 * Pad length is update in SKB CB for later use.
	 */
	tos = (tr->tr_flags & EIP_TR_DTLS_FLAG_CP_TOS) ? skb->priority : dtls->tos;

	/*
	 * Insert UDP header.
	 */
	eip_tr_dtls_enc_udp(tr, skb);
	udp_len = skb->len;

	/*
	 * Insert IPv6 header.
	 */
	ip6h = (struct ipv6hdr *)skb_push(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	skb->protocol = htons(ETH_P_IPV6);

	ip6_flow_hdr(ip6h, tos, 0);
	ip6h->payload_len = htons(udp_len);
	ip6h->nexthdr = dtls->protocol;
	ip6h->hop_limit = dtls->ttl;

	memcpy(ip6h->saddr.s6_addr32, dtls->src_ip, sizeof(ip6h->saddr.s6_addr32));
	memcpy(ip6h->daddr.s6_addr32, dtls->dst_ip, sizeof(ip6h->daddr.s6_addr32));
}

/*
 * eip_tr_dtls_enc()
 *	DTLS Encapsulation.
 */
int eip_tr_dtls_enc(struct eip_tr *tr, struct sk_buff *skb)
{
	int (*dma_tx)(struct eip_dma *dma, struct eip_sw_desc *sw, struct sk_buff *skb);
	struct eip_tr_stats *tr_stats = this_cpu_ptr(tr->stats_pcpu);
	uint8_t headroom = tr->dtls.headroom;
	struct eip_ctx *ctx = tr->ctx;
	struct eip_sw_desc *sw;
	struct eip_dma *dma;
	int status = 0;

	dma_tx = skb_is_nonlinear(skb) ? eip_dma_hy_tx_nonlinear_skb : eip_dma_hy_tx_linear_skb;
	dma = &ctx->dma[smp_processor_id()];

	/*
	 * check whether the packet length is within
	 * max jumbo size limit supported by the HW.
	 */
	if (unlikely(skb->len > EIP_MAX_PKT_LEN)) {
		pr_err_ratelimited("%px: packet size(%d) exceeds max supported limit (%d)\n", skb, skb->len, EIP_MAX_PKT_LEN);
		tr_stats->tx_error_len++;
		return -EINVAL;
	}

	/*
	 * Check if we have enough headroom for outer IP/UDP headers and the fake mac header.
	 */
	if (unlikely(skb_headroom(skb) < headroom)) {
		pr_err_ratelimited("%px: Insufficient headroom, available(%d) needed(%d)\n", skb, skb_headroom(skb), headroom);
		tr_stats->tx_error_len++;
		return -EINVAL;
	}

	/*
	 * Allocate SW descriptor.
	 */
	sw = kmem_cache_alloc(ctx->sw_cache, GFP_NOWAIT | __GFP_NOWARN);
	if (!sw) {
		pr_debug_ratelimited("%px: Failed to allocate SW descriptor.\n", tr);
		return -ENOMEM;
	}

	EIP_TR_PRE_PROCESS(tr, &tr->dtls.ops, skb);

	/*
	 * Fill software descriptor.
	 * Dereference: eip_tr_dtls_enc_done() / eip_tr_dtls_enc_err()
	 */
	sw->tr = eip_tr_ref(tr);
	sw->tk = NULL;
	sw->tk_hdr = EIP_HW_TOKEN_HDR_BASIC;
	sw->tk_hdr |= tr->dtls.tk_hdr;
	sw->tk_addr = 0;
	sw->tr_addr_type = tr->tr_addr_type;
	sw->tk_words = 0;
	sw->hw_svc = EIP_HW_CMD_HWSERVICE_IDT;
	sw->cmd_l4_csum = EIP_HW_CMD_W5_L4CHKSUM;
	sw->req = skb;

	/*
	 * Push the fake mac header for inline.
	 * Set handler to trasmit completion as packet will be redirected to inline.
	 */
	skb_push(skb, sizeof(struct ethhdr));
	sw->tk_hdr |= skb->len;
	sw->comp = &eip_tr_dtls_tx_done;
	sw->err_comp = NULL; /* There is no error in Transmit completion */

	status = dma_tx(dma, sw, skb);
	if (status < 0) {
		dma->stats.tx_error++;

		/*
		 * Undo the outer IP/UDP headers (EIP_TR_PRE_PROCESS) and fake mac header
		 */
		skb_pull(skb, headroom);
		goto fail_tx;
	}

	return 0;

fail_tx:
	eip_tr_deref(tr);
	kmem_cache_free(ctx->sw_cache, sw);
	return status;
}
EXPORT_SYMBOL(eip_tr_dtls_enc);

/*
 * eip_tr_dtls_enc_cmn_init()
 *	Initialize the transform record for DTLS encapsulation.
 */
void eip_tr_dtls_enc_cmn_init(struct eip_tr *tr, struct eip_tr_info *info, const struct eip_svc_entry *algo)
{
	struct eip_tr_info_dtls *dtls = &info->dtls;
	struct eip_tr_dtls *tr_dtls = &tr->dtls;
	struct eip_tr_base *crypto = &info->base;
	uint32_t *crypt_words = tr->hw_words;
	uint8_t addr_len = sizeof(uint32_t);
	uint32_t *tr_words = tr->hw_words;
	uint8_t seq_offset;
	uint32_t size;
	uint32_t mode;

	/*
	 * First two words are Control words.
	 */
	tr_words[0] = algo->ctrl_words_0;
	tr_words[1] = algo->ctrl_words_1;

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
	 * Leave the space for inner & outer digest / GHASH key
	 * For GCM we store only GHASH key of size auth_block_len
	 * and for other algo we store inner & outer digest each
	 * of size auth_state_len
	 */
	size = algo->auth_state_len ? (algo->auth_state_len * 2) : algo->auth_block_len;
	crypt_words += (size / sizeof(uint32_t));

	/*
	 * DTLS specific fields for EIP96.
	 * - Version in Host order (1 word)
	 * - Sequence number start (2 words/48bit sequence)
	 */
	*crypt_words++ = EIP_TR_DTLS_VERSION(dtls->version);
	*crypt_words++ = EIP_TR_DTLS_SEQ_START;
	*crypt_words++ = EIP_TR_DTLS_EPOCH(ntohs(dtls->epoch));
	seq_offset = crypt_words - tr_words - 2;

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
	tr_words[1] |= EIP_TR_CTRL_SEQ_NUM_OFFSET_EN;
	tr_words[1] |= EIP_TR_CTRL_SEQ_NUM_OFFSET(seq_offset);
	tr_words[1] |= EIP_TR_CTRL_SEQ_NUM_STORE;

	/*
	 * Store the cipher block length to be used during encap hdrs
	 */
	tr->iv_len = algo->iv_len;
	tr->blk_len = algo->cipher_blk_len;
	tr->digest_len = algo->auth_digest_len;

	/*
	 * Configure DTLS encapsulation specific details in TR
	 */
	tr_dtls->ip_version = dtls->ip_ver;
	tr_dtls->tos = dtls->ip_dscp;
	tr_dtls->ip_df = dtls->ip_df ? htons(IP_DF) : 0;
	tr_dtls->ttl = dtls->ip_ttl;
	tr_dtls->src_port = dtls->src_port;
	tr_dtls->dst_port = dtls->dst_port;
	tr_dtls->headroom = dtls->ip_ver ? (sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct ipv6hdr))
					: (sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct iphdr));
	atomic_set(&tr_dtls->ip_id, 1);

	tr_words[65] = 0;

	/*
	 * Configure mode specific details in TR
	 * We bypass the pre-filled outer header (IP/IP+UDP)
	 * There is no post processing for encap
	 */
	tr_dtls->ops.post = NULL;
	tr_dtls->tk_hdr |= EIP_TR_DTLS_ENCAP_TOKEN_DATA;
	mode = dtls->flags & (EIP_TR_DTLS_FLAG_UDPLITE | EIP_TR_DTLS_FLAG_CAPWAP | EIP_TR_DTLS_FLAG_IPV6);

	switch (mode) {
	case (EIP_TR_DTLS_FLAG_UDPLITE | EIP_TR_DTLS_FLAG_IPV6):
	case (EIP_TR_DTLS_FLAG_IPV6):
	case (EIP_TR_DTLS_FLAG_UDPLITE):
		WARN_ON(1);
		break;

	case (EIP_TR_DTLS_FLAG_CAPWAP | EIP_TR_DTLS_FLAG_IPV6 | EIP_TR_DTLS_FLAG_UDPLITE):
		tr_words[65] |= EIP_TR_DTLS_IPV6_EN;
		tr_words[68] |= EIP_TR_DTLS_OHDR_PROTO(EIP_TR_DTLS_CAPWAP_OHDR_PROTO_V6_OUT);
		tr_dtls->ops.pre = eip_tr_dtls_enc_v6;
		tr_dtls->protocol = IPPROTO_UDPLITE;
		addr_len = sizeof(struct in6_addr);
		break;

	case (EIP_TR_DTLS_FLAG_CAPWAP | EIP_TR_DTLS_FLAG_IPV6):
		tr_words[65] |= EIP_TR_DTLS_IPV6_EN;
		tr_words[68] |= EIP_TR_DTLS_OHDR_PROTO(EIP_TR_DTLS_CAPWAP_OHDR_PROTO_V6_OUT);
		tr_dtls->ops.pre = eip_tr_dtls_enc_v6;
		tr_dtls->protocol = IPPROTO_UDP;
		addr_len = sizeof(struct in6_addr);
		break;

	case (EIP_TR_DTLS_FLAG_CAPWAP | EIP_TR_DTLS_FLAG_UDPLITE):
		tr_words[68] |= EIP_TR_DTLS_OHDR_PROTO(EIP_TR_DTLS_CAPWAP_OHDR_PROTO_V4_OUT);
		tr_dtls->ops.pre = eip_tr_dtls_enc_v4;
		tr_dtls->protocol = IPPROTO_UDPLITE;
		addr_len = sizeof(uint32_t);
		break;

	case (EIP_TR_DTLS_FLAG_CAPWAP):	/* DTLS + CAPWAP IPv4 tunnel */
		tr_words[68] |= EIP_TR_DTLS_OHDR_PROTO(EIP_TR_DTLS_CAPWAP_OHDR_PROTO_V4_OUT);
		tr_dtls->ops.pre = eip_tr_dtls_enc_v4;
		tr_dtls->protocol = IPPROTO_UDP;
		addr_len = sizeof(uint32_t);
		break;

	default:	/* DTLS IPv4 tunnel */
		tr_words[68] |= EIP_TR_DTLS_OHDR_PROTO(EIP_TR_DTLS_OHDR_PROTO_V4_OUT);
		tr_dtls->ops.pre = eip_tr_dtls_enc_v4;
		tr_dtls->protocol = IPPROTO_UDP;
		addr_len = sizeof(uint32_t);
		break;
	}

	/*
	 * Enable redirection for dtls
	 */
	if (tr->svc == EIP_SVC_HYBRID_DTLS) {
		tr_words[65] |= EIP_TR_REDIR_EN;
		tr_words[65] |= EIP_TR_REDIR_IFACE(EIP_HW_INLINE_RING);
	}

	tr_words[66] = 0;
	tr_words[67] = 0; /* NPH context reference */
	tr_words[68] |= EIP_TR_DTLS_ICV_SIZE(algo->auth_digest_len);
	tr_words[68] |= EIP_TR_DTLS_IV_SIZE(algo->iv_len);
	tr_words[69] = 0;
	tr_words[70] = EIP_TR_DTLS_ENCAP_TOKEN_VERIFY;
	tr_words[71] = EIP_TR_DTLS_ENCAP_ESN_TOKEN_INST(seq_offset);

	memcpy(tr_dtls->src_ip, dtls->src_ip, addr_len);
	memcpy(tr_dtls->dst_ip, dtls->dst_ip, addr_len);
}
