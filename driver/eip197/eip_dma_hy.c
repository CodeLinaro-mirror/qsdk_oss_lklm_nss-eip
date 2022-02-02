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
#include <linux/atomic.h>
#include <linux/dma-mapping.h>
#include <linux/cache.h>
#include <linux/interrupt.h>
#include <linux/debugfs.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <asm/cacheflush.h>

#include "eip_priv.h"

/*
 * eip_dma_hy_notify()
 *	Notify HW for new descriptor.
 */
static inline void eip_dma_hy_notify(struct eip_hw_ring *ring, uint8_t desc, uint32_t prod_idx)
{
	/*
	 * Update producer.
	 */
	atomic_set(&ring->prod_idx, prod_idx);

	/*
	 * Add Data barrier to insure all descriptor write operation is done.
	 */
	dsb(st);
	iowrite32(EIP_HW_PREP_CNT_DESC_SZ(EIP_HW_DESC_WORDS * desc), ring->prep_cnt);
}

/*
 * eip_dma_hy_tx_res()
 *	Schedule single command for transformation. The function must be called with prempt disabled.
 */
static inline void eip_dma_hy_tx_res(struct eip_dma *dma, struct sk_buff *skb, struct eip_frag *frag)
{
	struct eip_hw_desc *res;

	/*
	 * Invalidate the all cache line associated with output data to avoid any corruption due to cache eviction.
	 * We are performing clean as we may be sharing the cache line with others.
	 */
	dmac_clean_range_no_dsb(frag->data, frag->data + frag->len);

	/*
	 * Fill result descriptor for single buffer.
	 */
	res = &dma->out.desc[frag->idx];


	res->frag[0] = frag->flag;
	res->frag[0] |= EIP_HW_RES_FRAG_LEN(frag->len);
	res->frag[1] = 0;
	res->frag[2] = virt_to_phys(frag->data);
	res->frag[3] = 0;

	res->token[0] = res->token[1] = res->token[2] = res->token[3] = 0;
	res->token[4] = res->token[5] = res->token[6] = res->token[7] = 0;
	res->bypass[0] = res->bypass[1] = res->bypass[2] = res->bypass[3] = 0;

	dma->out.meta[frag->idx] = (uintptr_t)skb;
	dmac_clean_range_no_dsb(res, res + 1);
}

/*
 * eip_dma_hy_tx_cmd()
 *	Schedule single command for transformation. The function must be called with prempt disabled.
 */
static inline void eip_dma_hy_tx_cmd(struct eip_dma *dma, struct eip_sw_desc *sw, struct eip_frag *frag)
{
	struct eip_hw_desc *cmd;

	/*
	 * Flush all the data to be read by hardware.
	 */
	dmac_clean_range_no_dsb(frag->data, frag->data + frag->len);

	/*
	 * Fill command descriptor for single buffer.
	 */
	cmd = &dma->in.desc[frag->idx];

	cmd->frag[0] = frag->flag;
	cmd->frag[0] |= EIP_HW_CMD_FRAG_LEN(frag->len);
	cmd->frag[1] = 0;
	cmd->frag[2] = virt_to_phys(frag->data);
	cmd->frag[3] = 0;

	if (frag->flag & EIP_HW_CMD_FLAGS_FIRST) {
		struct eip_tr *tr = sw->tr;

		cmd->frag[0] |= EIP_HW_CMD_TOKEN_WORDS(sw->tk_words);

		cmd->token[0] = sw->tk_addr;
		cmd->token[1] = 0;
		cmd->token[2] = sw->cmd_token_hdr;
		cmd->token[3] = 0;
		cmd->token[4] = sw->tr_addr_type;
		cmd->token[5] = 0;
		cmd->token[6] = sw->hw_svc;
		cmd->token[7] = EIP_HW_CMD_OFFSET(sizeof(struct ethhdr));

		/*
		 * TODO: Copy with uint64_t?
		 */
		cmd->bypass[0] = tr->bypass[0];
		cmd->bypass[1] = tr->bypass[1];
		cmd->bypass[2] = tr->bypass[2];
		cmd->bypass[3] = tr->bypass[3];

		dma->in.meta[frag->idx] = (uintptr_t)sw;
	} else {
		cmd->token[0] = cmd->token[1] = cmd->token[2] = cmd->token[3] = 0;
		cmd->token[4] = cmd->token[5] = cmd->token[6] = cmd->token[7] = 0;
		cmd->bypass[0] = cmd->bypass[1] = cmd->bypass[2] = cmd->bypass[3] = 0;

		dma->in.meta[frag->idx] = (uintptr_t)0;
	}

	dmac_clean_range_no_dsb(cmd, cmd + 1);
}

/*
 * eip_dma_hy_refill()
 *	Refill new SKB(s) in DMA output ring.
 */
static void eip_dma_hy_refill(struct eip_dma *dma)
{
	uint32_t count, processed;
	struct eip_frag frag;
	struct sk_buff *skb;
	uint32_t pidx;

	count = eip_dma_avail_idx_and_count(&dma->out, &pidx);
	if (!count)
		return;


	/*
	 * Refill start index.
	 * TODO: How do we support jumbo size? Do we just increase EIP_RX_BUFFER_SIZE?
	 */
	frag.idx = pidx;
	processed = count;

	while (count) {
		skb = dev_alloc_skb(EIP_RX_BUFFER_SIZE);
		if (unlikely(!skb))
			break;

		/*
		 * Put the data to largest possible value. In rx, we will trim the data with actual size.
		 */
		skb_reserve(skb, EIP_RX_BUFFER_HEADROOM);
		skb_put(skb, EIP_RX_BUFFER_DATA_LEN);

		frag.data = skb->data;
		frag.len = skb->len;
		frag.flag = EIP_HW_RES_FLAGS(1, 1);

		eip_dma_hy_tx_res(dma, skb, &frag);
		frag.idx = EIP_DMA_IDX_INC(frag.idx);
		count -= 1;
	}

	eip_dma_hy_notify(&dma->out, processed - count, frag.idx);
}

/*
 * eip_dma_hy_append_frag()
 */
static inline void eip_dma_hy_append_frag(struct sk_buff *skb, struct sk_buff **tail_frag, struct sk_buff *new_frag)
{
	/*
	 * Updated frag_list pointer for first fragment append.
	 */
	if (!skb_has_frag_list(skb)) {
		skb_shinfo(skb)->frag_list = new_frag;
		*tail_frag = skb;
	}

	new_frag->next = NULL;

	(*tail_frag)->next = new_frag;
	*tail_frag = new_frag;

	skb->len += new_frag->len;
	skb->data_len += new_frag->len;
	skb->truesize += new_frag->truesize;
}

/*
 * eip_dma_hy_get_tr()
 *	Get the TR object using physical address.
 */
static inline struct eip_tr *eip_dma_hy_get_tr(struct eip_hw_desc *res)
{
	uint32_t tr_hw_addr = EIP_HW_RES_TR_ADDR(res->token[4]);

	/*
	 * TR address is invalid when there is a CLE error.
	 */
	if (unlikely(EIP_HW_RES_ERROR_CLE(res->token[1]))) {
		return NULL;
	}

	/*
	 * higher 32bit must be zero as we use only 32bit bus address.
	 */
	if (unlikely(!tr_hw_addr || res->token[5] == 0xffffffff)) {
		return NULL;
	}

	/*
	 * TR reference does not work for packet received from inline channel.
	 * Instead we make sure TR invalidation & free is scheduled only after all the packet
	 * is read from queue to make sure memory is valid.
	 */
	return container_of(phys_to_virt(tr_hw_addr), struct eip_tr, hw_words);
}

/*
 * eip_dma_hy_tr_deliver()
 *	Send SKB to registered client's handler.
 */
static inline void eip_dma_hy_tr_deliver(struct eip_tr *tr, struct sk_buff *skb, uint8_t nsegs)
{
	struct eip_tr_stats *tr_stats = this_cpu_ptr(tr->stats_pcpu);

	BUG_ON(tr->svc != EIP_SVC_HYBRID_IPSEC);

	tr_stats->rx_frags += nsegs;
	tr_stats->rx_pkts++;
	tr_stats->rx_bytes += skb->len;

	/*
	 * Call completion callback.
	 */
	tr->ipsec.op.cb(tr->ipsec.app_data, skb);
}

/*
 * eip_dma_hy_tr_deliver_err()
 *	Send SKB to registered client's error handler.
 */
static inline void eip_dma_hy_tr_deliver_err(struct eip_tr *tr, struct sk_buff *skb, uint8_t nsegs, uint16_t tr_err)
{
	struct eip_tr_stats *tr_stats = this_cpu_ptr(tr->stats_pcpu);

	BUG_ON(tr->svc != EIP_SVC_HYBRID_IPSEC);

	tr_stats->rx_frags += nsegs;
	tr_stats->rx_pkts++;
	tr_stats->rx_bytes += skb->len;
	tr_stats->rx_error ++;

	/*
	 * Call completion callback.
	 */
	tr->ipsec.op.err_cb(tr->ipsec.app_data, skb, -EBADE);
}

/*
 * eip_dma_hy_rx()
 *	Process all recieved packet on DMA.
 */
int eip_dma_hy_rx(struct eip_dma *dma, int budget)
{
	struct sk_buff *head_skb = dma->head_skb;
	struct sk_buff *tail_skb = dma->tail_skb;
	uint8_t nsegs = dma->nsegs;

	uint32_t hw_pidx, out_cidx;
	uint32_t avail, processed;
	uint32_t prod_words;

	/*
	 * Calculate Descriptor produced by HW.
	 */
	prod_words = EIP_HW_PROC_DESC_SZ(ioread32(dma->out.proc));
	hw_pidx = prod_words / EIP_HW_DESC_WORDS;
	out_cidx = atomic_read(&dma->out.cons_idx);

	avail = EIP_DMA_AVAIL_COUNT(hw_pidx, out_cidx);
	if (!avail) {
		return 0;
	}

	avail = avail > budget ? budget : avail;
	processed = avail;

	/*
	 * Invalidate the descriptor we are going to read.
	 * We need to invalidate cache line from head and tail when hw index is behind sw index.
	 */
	if (hw_pidx > out_cidx) {
		dmac_inv_range(dma->out.desc + out_cidx, dma->out.desc + hw_pidx);
	} else {
		dmac_inv_range_no_dsb(dma->out.desc + out_cidx, dma->out.desc + EIP_DMA_DESC_MAX);
		dmac_inv_range(dma->out.desc, dma->out.desc + hw_pidx);
	}

	while (avail--) {
		uint16_t cle_err, tr_err;
		struct eip_hw_desc *res;
		struct sk_buff *skb;
		struct eip_tr *tr;
		uint16_t frag_len;
		uint16_t data_len;
		void *data;
		bool err;

		res = &dma->out.desc[out_cidx];
		skb = (struct sk_buff *)dma->out.meta[out_cidx];
		out_cidx = EIP_DMA_IDX_INC(out_cidx);

		/*
		 * Fragment data needs to be invalidated for non zero fragment.
		 * This is needed as there may be speculative prefetch before completion.
		 */
		frag_len = EIP_HW_RES_FRAG_LEN(res->frag[0]);
		BUG_ON(!frag_len);
		data = phys_to_virt(res->frag[2]);
		dmac_inv_range(data, data + frag_len);

		/*
		 * Trim the linear SKB frag to length produced by hardware.
		 */
		skb_trim(skb, frag_len);

		/*
		 * Linear data. Both First & Last flags are set.
		 */
		if ((EIP_HW_RES_FLAGS_MASK & res->frag[0]) == EIP_HW_RES_FLAGS_LINEAR) {
			head_skb = skb;
			nsegs = 1;
			goto deliver;
		}

		/*
		 * Non-linear data. Set our head to descriptor with first flag.
		 */
		if (EIP_HW_RES_FLAGS_FIRST & res->frag[0]) {
			head_skb = skb;
			nsegs = 1;
			continue;
		}

		/*
		 * Append SKB to head SKB frag list.
		 */
		eip_dma_hy_append_frag(head_skb, &tail_skb, skb);
		nsegs++;
		skb = NULL;

		/*
		 * Continue to next descriptor if not last.
		 */
		if (!(EIP_HW_RES_FLAGS_LAST & res->frag[0])) {
			continue;
		}

deliver:
		/*
		 * Fetch error from result descriptor.
		 */
		tr_err = EIP_HW_RES_ERROR(res->token[0]);
		cle_err = EIP_HW_RES_ERROR_CLE(res->token[1]);
		err = cle_err || tr_err;
		data_len = EIP_HW_RES_DATA_LEN(res->token[0]);

		/*
		 * Update DMA Rx stats.
		 * We have not used atomic operation as there is no write contention for stats.
		 */
		dma->stats.rx_frags += nsegs;
		dma->stats.rx_pkts++;
		dma->stats.rx_bytes += data_len;

		tr = eip_dma_hy_get_tr(res);
		if (unlikely(!tr)) {
			dma->stats.rx_dropped++;
			dma->stats.rx_error ++;
			dma->stats.rx_err_code[tr_err]++;

			consume_skb(head_skb);
			head_skb = NULL;
			tail_skb = NULL;
			nsegs = 0;
			continue;
		}

		/*
		 * Pull the fake mac added by PPE.
		 */
		skb_pull(head_skb, sizeof(struct ethhdr));

		/*
		 * Send packet to the client's handler.
		 */
		if (err) {
			dma->stats.rx_error ++;
			dma->stats.rx_err_code[tr_err]++;

			eip_dma_hy_tr_deliver_err(tr, head_skb, nsegs, tr_err);
			head_skb = NULL;
			tail_skb = NULL;
			nsegs = 0;
			continue;
		}

		eip_dma_hy_tr_deliver(tr, head_skb, nsegs);
		head_skb = NULL;
		tail_skb = NULL;
		nsegs = 0;
	}

	/*
	 * Acknowledge HW for result descriptor.
	 */
	iowrite32(EIP_HW_PROC_CNT_DESC_SZ(EIP_HW_DESC_WORDS * processed), dma->out.proc_cnt);

	/*
	 * Update output consumer indexes in dma object.
	 * Save any in-progress SG state in DMA.
	 */
	atomic_set(&dma->out.cons_idx, out_cidx);
	dma->head_skb = head_skb;
	dma->tail_skb = tail_skb;
	dma->nsegs = nsegs;

	return processed;
}

/*
 * eip_dma_hy_tx_comp()
 *	Free transmitted buffer.
 */
int eip_dma_hy_tx_comp(struct eip_dma *dma, int budget)
{
	uint32_t hw_cidx, in_cidx;
	uint32_t cons_words;
	uint32_t processed;
	uint32_t avail;

	/*
	 * Calculate Descriptor produced by HW.
	 */
	cons_words = EIP_HW_PROC_DESC_SZ(ioread32(dma->in.proc));
	hw_cidx = cons_words / EIP_HW_DESC_WORDS;
	in_cidx = atomic_read(&dma->in.cons_idx);

	avail = EIP_DMA_AVAIL_COUNT(hw_cidx, in_cidx);
	if (!avail) {
		return 0;
	}

	avail = avail > budget ? budget : avail;
	processed = avail;

	while (avail--) {
		struct eip_sw_desc *sw;

		sw = (struct eip_sw_desc *)dma->in.meta[in_cidx];
		in_cidx = EIP_DMA_IDX_INC(in_cidx);

		if (!sw)
			continue;

		sw->comp(sw->tr, NULL, sw);
	}

	/*
	 * Acknowledge HW for command descriptor.
	 */
	iowrite32(EIP_HW_PROC_CNT_DESC_SZ(EIP_HW_DESC_WORDS * processed), dma->in.proc_cnt);

	/*
	 * Update input consumer index.
	 */
	atomic_set(&dma->in.cons_idx, in_cidx);
	return processed;
}

/*
 * eip_dma_hy_handle_irq()
 *	Interrupt handler for DMA Rx.
 */
static irqreturn_t eip_dma_hy_handle_irq(int irq, void *ctx)
{
	struct eip_dma *dma = ctx;

	/*
	 * Acknowledge interrupt. HW interrupt remain in disabled state
	 * until our bottom half re-enables it.
	 */
	if (ioread32(dma->in.proc_status) & EIP_HW_CDR_PROC_IRQ_STATUS) {
		iowrite32(EIP_HW_CDR_PROC_IRQ_STATUS, dma->in.proc_status);
		napi_schedule(&dma->in.napi);
	}

	if (ioread32(dma->out.proc_status) & EIP_HW_RDR_PROC_IRQ_STATUS) {
		iowrite32(EIP_HW_RDR_PROC_IRQ_STATUS, dma->out.proc_status);
		napi_schedule(&dma->out.napi);
	}

	return IRQ_HANDLED;
}

/*
 * eip_dma_hy_napi_tx_poll()
 *	NAPI poll callback to handle EIP197 interrupt.
 */
static int eip_dma_hy_napi_tx_poll(struct napi_struct *napi, int budget)
{
	struct eip_dma *dma = container_of(napi, struct eip_dma, in.napi);
	int processed;

	processed = eip_dma_hy_tx_comp(dma, budget);
	if (processed < budget) {
		napi_complete(napi);
		iowrite32(EIP_HW_CDR_HIA_THR_VAL, dma->in.proc_thresh);
	}

	return processed;
}

/*
 * eip_dma_hy_napi_rx_poll()
 *	NAPI poll callback to handle EIP197 interrupt.
 */
static int eip_dma_hy_napi_rx_poll(struct napi_struct *napi, int budget)
{
	struct eip_dma *dma = container_of(napi, struct eip_dma, out.napi);
	int processed;

	/*
	 * Reap Rx ring. If we have processed all packet in queue
	 * then disable napi and re-enable irq in EIP.
	 */
	processed = eip_dma_hy_rx(dma, budget);
	if (processed < budget) {
		napi_complete(napi);
		iowrite32(EIP_HW_RDR_HIA_THR_VAL, dma->out.proc_thresh);
	}

	/*
	 * Refill new SKB.
	 */
	eip_dma_hy_refill(dma);

	return processed;
}

/*
 * eip_dma_hy_free_skb()
 *	Refill new SKB(s) in DMA output ring.
 */
static void eip_dma_hy_free_skb(struct eip_dma *dma)
{
	/*
	 * TODO: Fix
	 */
	BUG_ON(1);
}

/*
 * eip_dma_hy_tx_linear_skb()
 *	Schedule linear SKB for transformation. The function must be called with prempt disabled.
 */
int eip_dma_hy_tx_linear_skb(struct eip_dma *dma, struct eip_sw_desc *sw, struct sk_buff *skb)
{
	struct eip_tr_stats *tr_stats = this_cpu_ptr(sw->tr->stats_pcpu);
	struct eip_frag src;
	uint32_t in_count;

	BUG_ON(skb_is_nonlinear(skb));

	in_count = eip_dma_avail_idx_and_count(&dma->in, &src.idx);
	if (!in_count)
		return -EBUSY;

	/*
	 * Fill Source fragment for Command ring.
	 */
	src.data = skb->data;
	src.len = skb->len;
	src.flag = EIP_HW_CMD_FLAGS(1, 1);
	sw->src_nsegs = 1;
	eip_dma_hy_tx_cmd(dma, sw, &src);

	/*
	 * Increament Tx statistics.
	 */
	tr_stats->tx_frags += 1;
	tr_stats->tx_pkts++;
	tr_stats->tx_bytes += src.len;
	dma->stats.tx_frags += 1;
	dma->stats.tx_pkts++;
	dma->stats.tx_bytes += src.len;


	eip_dma_hy_notify(&dma->in, 1, EIP_DMA_IDX_INC(src.idx));
	return 0;
}

/*
 * eip_dma_hy_tx_nonlinear_skb()
 *	Schedule non-linear SKB for transformation. The function must be called with prempt disabled.
 */
int eip_dma_hy_tx_nonlinear_skb(struct eip_dma *dma, struct eip_sw_desc *sw, struct sk_buff *skb)
{
	/*
	 * TODO: Add support.
	 */
	return -EINVAL;
}

/*
 * eip_dma_hy_deinit()
 *	De-Initialize the DMA HW ring.
 */
void eip_dma_hy_deinit(struct eip_dma *dma)
{
	if (!dma->active) {
		return;
	}

	debugfs_remove_recursive(dma->dentry);
	free_irq(dma->irq, dma);
	napi_disable(&dma->in.napi);
	napi_disable(&dma->out.napi);
	netif_napi_del(&dma->in.napi);
	netif_napi_del(&dma->out.napi);
	eip_dma_hy_free_skb(dma);
	kfree(dma->out.desc);
	kfree(dma->in.desc);

	memset(dma, 0, sizeof(*dma));
}

/*
 * eip_dma_hy_init()
 *	initialize the EIP197 DMA.
 */
int eip_dma_hy_init(struct eip_dma *dma, struct platform_device *pdev, uint8_t tx_cpu,
		uint8_t rx_cpu,	uint32_t ring_id, void __iomem *base_addr)
{
	struct eip_pdev *ep = platform_get_drvdata(pdev);
	int status;

	if (dma->active) {
		pr_err("%px: DMA is already configured; ring_id(%u)\n", dma, ring_id);
		return -EINVAL;
	}

	dma->type = EIP_DMA_TYPE_HYBRID;
	dma->ring_id = ring_id;
	dma->irq_mask = EIP_HW_RDR_PROC_IRQ_STATUS;
	dma->irq_status = base_addr + EIP_HW_HIA_RDR_STAT(ring_id);

	/*
	 * TODO: should we rename rx_cpu to irq_num?
	 */
	dma->irq = platform_get_irq(ep->pdev, rx_cpu);
	if (!dma->irq) {
		pr_err("%px: irq_of_parse_and_map() fail for irq, ring_id(%u)\n", dma, ring_id);
		return -EINVAL;
	}

	/*
	 * Initialize and allocate ring.
	 */
	status = eip_dma_cmd_init(dma, base_addr, true, rx_cpu);
	if (status < 0) {
		pr_err("%px: Failed to initialize cmd ring(%u)\n", dma, ring_id);
		return status;

	}

	status = eip_dma_res_init(dma, base_addr, true, rx_cpu);
	if (status < 0) {
		pr_err("%px: Failed to initialize res ring(%u)\n", dma, ring_id);
		goto fail_res;
	}

	/*
	 * Initialize the interrupt.
	 */
	status = request_irq(dma->irq, eip_dma_hy_handle_irq, IRQF_SHARED, irq_name[ring_id], dma);
	if (status < 0) {
		pr_err("%px: IRQ %u request failed\n", dma, dma->irq);
		goto fail_irq;
	}

	/*
	 * Initialize NAPI for transmit completion for input ring.
	 */
	init_dummy_netdev(&dma->in.ndev);
	netif_napi_add(&dma->in.ndev, &dma->in.napi, eip_dma_hy_napi_tx_poll, EIP_DMA_TX_COMPL_NAPI_WEIGHT);
	napi_enable(&dma->in.napi);

	/*
	 * Initialize NAPI for receiving packet for output ring.
	 */
	init_dummy_netdev(&dma->out.ndev);
	netif_napi_add(&dma->out.ndev, &dma->out.napi, eip_dma_hy_napi_rx_poll, EIP_DMA_RX_HY_NAPI_WEIGHT);
	napi_enable(&dma->out.napi);
	eip_dma_hy_refill(dma);

	/*
	 * Interrupt can only be handled by the specified CPU.
	 */
	irq_set_affinity_hint(dma->irq, cpumask_of(rx_cpu));

	dma->dentry = debugfs_create_file(dma_name[ring_id], S_IRUGO, ep->dentry, dma, &dma_stats_ops);
	dma->active = 1;
	pr_info("%px: DMA ring(%u) configured and Rx mapped to cpu(%u)\n", dma, ring_id, rx_cpu);
	return 0;

fail_irq:
	kfree(dma->out.kaddr);
fail_res:
	kfree(dma->in.kaddr);
	return status;
}
