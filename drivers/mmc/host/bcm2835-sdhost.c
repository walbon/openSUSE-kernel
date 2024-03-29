/*
 * BCM2835 SD host driver.
 *
 * Author:      Phil Elwell <phil@xxxxxxxxxxxxxxx>
 *              Copyright (C) 2015-2016 Raspberry Pi (Trading) Ltd.
 *
 * Based on
 *  mmc-bcm2835.c by Gellert Weisz
 * which is, in turn, based on
 *  sdhci-bcm2708.c by Broadcom
 *  sdhci-bcm2835.c by Stephen Warren and Oleksandr Tymoshenko
 *  sdhci.c and sdhci-pci.c by Pierre Ossman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/host.h>
#include <linux/mmc/sd.h>
#include <linux/scatterlist.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/clk.h>
#include <linux/platform_device.h>
#include <linux/err.h>
#include <linux/blkdev.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/of_dma.h>
#include <linux/time.h>
#include <linux/workqueue.h>

#define SDCMD  0x00 /* Command to SD card              - 16 R/W */
#define SDARG  0x04 /* Argument to SD card             - 32 R/W */
#define SDTOUT 0x08 /* Start value for timeout counter - 32 R/W */
#define SDCDIV 0x0c /* Start value for clock divider   - 11 R/W */
#define SDRSP0 0x10 /* SD card response (31:0)         - 32 R   */
#define SDRSP1 0x14 /* SD card response (63:32)        - 32 R   */
#define SDRSP2 0x18 /* SD card response (95:64)        - 32 R   */
#define SDRSP3 0x1c /* SD card response (127:96)       - 32 R   */
#define SDHSTS 0x20 /* SD host status                  - 11 R   */
#define SDVDD  0x30 /* SD card power control           -  1 R/W */
#define SDEDM  0x34 /* Emergency Debug Mode            - 13 R/W */
#define SDHCFG 0x38 /* Host configuration              -  2 R/W */
#define SDHBCT 0x3c /* Host byte count (debug)         - 32 R/W */
#define SDDATA 0x40 /* Data to/from SD card            - 32 R/W */
#define SDHBLC 0x50 /* Host block count (SDIO/SDHC)    -  9 R/W */

#define SDCMD_NEW_FLAG                  0x8000
#define SDCMD_FAIL_FLAG                 0x4000
#define SDCMD_BUSYWAIT                  0x800
#define SDCMD_NO_RESPONSE               0x400
#define SDCMD_LONG_RESPONSE             0x200
#define SDCMD_WRITE_CMD                 0x80
#define SDCMD_READ_CMD                  0x40
#define SDCMD_CMD_MASK                  0x3f

#define SDCDIV_MAX_CDIV                 0x7ff

#define SDHSTS_BUSY_IRPT                0x400
#define SDHSTS_BLOCK_IRPT               0x200
#define SDHSTS_SDIO_IRPT                0x100
#define SDHSTS_REW_TIME_OUT             0x80
#define SDHSTS_CMD_TIME_OUT             0x40
#define SDHSTS_CRC16_ERROR              0x20
#define SDHSTS_CRC7_ERROR               0x10
#define SDHSTS_FIFO_ERROR               0x08
/* Reserved */
/* Reserved */
#define SDHSTS_DATA_FLAG                0x01

#define SDHSTS_TRANSFER_ERROR_MASK      (SDHSTS_CRC7_ERROR | \
					 SDHSTS_CRC16_ERROR | \
					 SDHSTS_REW_TIME_OUT | \
					 SDHSTS_FIFO_ERROR)

#define SDHSTS_ERROR_MASK               (SDHSTS_CMD_TIME_OUT | \
					 SDHSTS_TRANSFER_ERROR_MASK)

#define SDHCFG_BUSY_IRPT_EN     BIT(10)
#define SDHCFG_BLOCK_IRPT_EN    BIT(8)
#define SDHCFG_SDIO_IRPT_EN     BIT(5)
#define SDHCFG_DATA_IRPT_EN     BIT(4)
#define SDHCFG_SLOW_CARD        BIT(3)
#define SDHCFG_WIDE_EXT_BUS     BIT(2)
#define SDHCFG_WIDE_INT_BUS     BIT(1)
#define SDHCFG_REL_CMD_LINE     BIT(0)

#define SDEDM_FORCE_DATA_MODE   BIT(19)
#define SDEDM_CLOCK_PULSE       BIT(20)
#define SDEDM_BYPASS            BIT(21)

#define SDEDM_WRITE_THRESHOLD_SHIFT 9
#define SDEDM_READ_THRESHOLD_SHIFT 14
#define SDEDM_THRESHOLD_MASK     0x1f

#define SDEDM_FSM_MASK           0xf
#define SDEDM_FSM_IDENTMODE      0x0
#define SDEDM_FSM_DATAMODE       0x1
#define SDEDM_FSM_READDATA       0x2
#define SDEDM_FSM_WRITEDATA      0x3
#define SDEDM_FSM_READWAIT       0x4
#define SDEDM_FSM_READCRC        0x5
#define SDEDM_FSM_WRITECRC       0x6
#define SDEDM_FSM_WRITEWAIT1     0x7
#define SDEDM_FSM_POWERDOWN      0x8
#define SDEDM_FSM_POWERUP        0x9
#define SDEDM_FSM_WRITESTART1    0xa
#define SDEDM_FSM_WRITESTART2    0xb
#define SDEDM_FSM_GENPULSES      0xc
#define SDEDM_FSM_WRITEWAIT2     0xd
#define SDEDM_FSM_STARTPOWDOWN   0xf

#define SDDATA_FIFO_WORDS        16

#define FIFO_READ_THRESHOLD     4
#define FIFO_WRITE_THRESHOLD    4
#define SDDATA_FIFO_PIO_BURST   8
#define CMD_DALLY_US            1

struct bcm2835_host {
	spinlock_t		lock;

	void __iomem		*ioaddr;
	u32			phys_addr;

	struct mmc_host		*mmc;

	u32			pio_timeout;	/* In jiffies */

	int			clock;		/* Current clock speed */

	unsigned int		max_clk;	/* Max possible freq */

	struct tasklet_struct	finish_tasklet;	/* Tasklet structures */

	struct work_struct	cmd_wait_wq;	/* Workqueue function */

	struct timer_list	timer;		/* Timer for timeouts */

	struct sg_mapping_iter	sg_miter;	/* SG state for PIO */
	unsigned int		blocks;		/* remaining PIO blocks */

	int			irq;		/* Device IRQ */

	u32			cmd_quick_poll_retries;
	u32			ns_per_fifo_word;

	/* cached registers */
	u32			hcfg;
	u32			cdiv;

	/* Current request */
	struct mmc_request		*mrq;
	/* Current command */
	struct mmc_command		*cmd;
	/* Current data request */
	struct mmc_data			*data;
	/* Data finished before cmd */
	bool				data_complete:1;
	/* Drain the fifo when finishing */
	bool				flush_fifo:1;
	/* Wait for busy interrupt */
	bool				use_busy:1;
	/* Send CMD23 */
	bool				use_sbc:1;

	/*DMA part*/
	struct dma_chan			*dma_chan_rx;
	struct dma_chan			*dma_chan_tx;
	/* Channel in use */
	struct dma_chan			*dma_chan;
	struct dma_async_tx_descriptor	*dma_desc;
	u32				dma_dir;
	u32				drain_words;
	struct page			*drain_page;
	u32				drain_offset;

	bool				use_dma;
	/*end of DMA part*/
	/* maximum length of time spent waiting */
	int				max_delay;
	/* Maximum block count for PIO (0 = always DMA) */
	u32				pio_limit;
};

static inline void bcm2835_sdhost_write(struct bcm2835_host *host,
					u32 val, int reg)
{
	writel(val, host->ioaddr + reg);
}

static inline u32 bcm2835_sdhost_read(struct bcm2835_host *host, int reg)
{
	return readl(host->ioaddr + reg);
}

static inline u32 bcm2835_sdhost_read_relaxed(struct bcm2835_host *host,
					      int reg)
{
	return readl_relaxed(host->ioaddr + reg);
}

static void bcm2835_sdhost_dumpcmd(struct bcm2835_host *host,
				   struct mmc_command *cmd,
				   const char *label)
{
	if (!cmd)
		return;

	pr_err("%s:%c%s op %d arg 0x%x flags 0x%x - resp %08x %08x %08x %08x, err %d\n",
	       mmc_hostname(host->mmc),
	       (cmd == host->cmd) ? '>' : ' ',
	       label, cmd->opcode, cmd->arg, cmd->flags,
	       cmd->resp[0], cmd->resp[1], cmd->resp[2], cmd->resp[3],
	       cmd->error);
}

static void bcm2835_sdhost_dumpregs(struct bcm2835_host *host)
{
	if (host->mrq) {
		bcm2835_sdhost_dumpcmd(host, host->mrq->sbc, "sbc");
		bcm2835_sdhost_dumpcmd(host, host->mrq->cmd, "cmd");
		if (host->mrq->data) {
			pr_err("%s: data blocks %x blksz %x - err %d\n",
			       mmc_hostname(host->mmc),
			       host->mrq->data->blocks,
			       host->mrq->data->blksz,
			       host->mrq->data->error);
		}
		bcm2835_sdhost_dumpcmd(host, host->mrq->stop, "stop");
	}

	pr_err("%s: =========== REGISTER DUMP ===========\n",
	       mmc_hostname(host->mmc));

	pr_err("%s: SDCMD  0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDCMD));
	pr_err("%s: SDARG  0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDARG));
	pr_err("%s: SDTOUT 0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDTOUT));
	pr_err("%s: SDCDIV 0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDCDIV));
	pr_err("%s: SDRSP0 0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDRSP0));
	pr_err("%s: SDRSP1 0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDRSP1));
	pr_err("%s: SDRSP2 0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDRSP2));
	pr_err("%s: SDRSP3 0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDRSP3));
	pr_err("%s: SDHSTS 0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDHSTS));
	pr_err("%s: SDVDD  0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDVDD));
	pr_err("%s: SDEDM  0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDEDM));
	pr_err("%s: SDHCFG 0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDHCFG));
	pr_err("%s: SDHBCT 0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDHBCT));
	pr_err("%s: SDHBLC 0x%08x\n",
	       mmc_hostname(host->mmc),
	       bcm2835_sdhost_read(host, SDHBLC));

	pr_err("%s: ===========================================\n",
	       mmc_hostname(host->mmc));
}

static void bcm2835_sdhost_set_power(struct bcm2835_host *host, bool on)
{
	bcm2835_sdhost_write(host, on ? 1 : 0, SDVDD);
}

static void bcm2835_sdhost_reset_internal(struct bcm2835_host *host)
{
	u32 temp;

	bcm2835_sdhost_set_power(host, false);

	bcm2835_sdhost_write(host, 0, SDCMD);
	bcm2835_sdhost_write(host, 0, SDARG);
	bcm2835_sdhost_write(host, 0xf00000, SDTOUT);
	bcm2835_sdhost_write(host, 0, SDCDIV);
	bcm2835_sdhost_write(host, 0x7f8, SDHSTS); /* Write 1s to clear */
	bcm2835_sdhost_write(host, 0, SDHCFG);
	bcm2835_sdhost_write(host, 0, SDHBCT);
	bcm2835_sdhost_write(host, 0, SDHBLC);

	/* Limit fifo usage due to silicon bug */
	temp = bcm2835_sdhost_read(host, SDEDM);
	temp &= ~((SDEDM_THRESHOLD_MASK << SDEDM_READ_THRESHOLD_SHIFT) |
		  (SDEDM_THRESHOLD_MASK << SDEDM_WRITE_THRESHOLD_SHIFT));
	temp |= (FIFO_READ_THRESHOLD << SDEDM_READ_THRESHOLD_SHIFT) |
		(FIFO_WRITE_THRESHOLD << SDEDM_WRITE_THRESHOLD_SHIFT);
	bcm2835_sdhost_write(host, temp, SDEDM);
	msleep(20);
	bcm2835_sdhost_set_power(host, true);
	msleep(20);
	host->clock = 0;
	bcm2835_sdhost_write(host, host->hcfg, SDHCFG);
	bcm2835_sdhost_write(host, host->cdiv, SDCDIV);
}

static void bcm2835_sdhost_reset(struct mmc_host *mmc)
{
	struct bcm2835_host *host = mmc_priv(mmc);
	unsigned long flags;

	if (host->dma_chan)
		dmaengine_terminate_all(host->dma_chan);
	tasklet_kill(&host->finish_tasklet);
	bcm2835_sdhost_reset_internal(host);
}

static void bcm2835_sdhost_set_ios(struct mmc_host *mmc, struct mmc_ios *ios);

static void bcm2835_sdhost_init(struct bcm2835_host *host, int soft)
{
	pr_debug("bcm2835_sdhost_init(%d)\n", soft);

	/* Set interrupt enables */
	host->hcfg = SDHCFG_BUSY_IRPT_EN;

	bcm2835_sdhost_reset_internal(host);

	if (soft) {
		/* force clock reconfiguration */
		host->clock = 0;
		bcm2835_sdhost_set_ios(host->mmc, &host->mmc->ios);
	}
}

static void bcm2835_sdhost_wait_transfer_complete(struct bcm2835_host *host)
{
	int timediff;
	u32 alternate_idle;
	u32 edm;

	alternate_idle = (host->mrq->data->flags & MMC_DATA_READ) ?
		SDEDM_FSM_READWAIT : SDEDM_FSM_WRITESTART1;

	edm = bcm2835_sdhost_read(host, SDEDM);

	timediff = 0;

	while (1) {
		u32 fsm = edm & SDEDM_FSM_MASK;

		if ((fsm == SDEDM_FSM_IDENTMODE) ||
		    (fsm == SDEDM_FSM_DATAMODE))
			break;
		if (fsm == alternate_idle) {
			bcm2835_sdhost_write(host,
					     edm | SDEDM_FORCE_DATA_MODE,
					     SDEDM);
			break;
		}

		timediff++;
		if (timediff == 100000) {
			pr_err("%s: wait_transfer_complete - still waiting after %d retries\n",
			       mmc_hostname(host->mmc),
			       timediff);
			bcm2835_sdhost_dumpregs(host);
			host->mrq->data->error = -ETIMEDOUT;
			return;
		}
		cpu_relax();
		edm = bcm2835_sdhost_read(host, SDEDM);
	}
}

static void bcm2835_sdhost_finish_data(struct bcm2835_host *host);

static void bcm2835_sdhost_dma_complete(void *param)
{
	struct bcm2835_host *host = param;
	struct mmc_data *data = host->data;
	unsigned long flags;

	spin_lock_irqsave(&host->lock, flags);

	if (host->dma_chan) {
		dma_unmap_sg(host->dma_chan->device->dev,
			     data->sg, data->sg_len,
			     host->dma_dir);

		host->dma_chan = NULL;
	}

	if (host->drain_words) {
		void *page;
		u32 *buf;

		page = kmap_atomic(host->drain_page);
		buf = page + host->drain_offset;

		while (host->drain_words) {
			u32 edm = bcm2835_sdhost_read(host, SDEDM);

			if ((edm >> 4) & 0x1f)
				*(buf++) = bcm2835_sdhost_read(host,
							       SDDATA);
			host->drain_words--;
		}

		kunmap_atomic(page);
	}

	bcm2835_sdhost_finish_data(host);

	spin_unlock_irqrestore(&host->lock, flags);
}

static void bcm2835_sdhost_transfer_block_pio(struct bcm2835_host *host,
					      bool is_read)
{
	unsigned long flags;
	size_t blksize, len;
	u32 *buf;
	unsigned long wait_max;

	blksize = host->data->blksz;

	wait_max = jiffies + msecs_to_jiffies(host->pio_timeout);

	local_irq_save(flags);

	while (blksize) {
		int copy_words;
		u32 hsts = 0;

		if (!sg_miter_next(&host->sg_miter)) {
			host->data->error = -EINVAL;
			break;
		}

		len = min(host->sg_miter.length, blksize);
		if (len % 4) {
			host->data->error = -EINVAL;
			break;
		}

		blksize -= len;
		host->sg_miter.consumed = len;

		buf = (u32 *)host->sg_miter.addr;

		copy_words = len / 4;

		while (copy_words) {
			int burst_words, words;
			u32 edm;

			burst_words = SDDATA_FIFO_PIO_BURST;
			if (burst_words > copy_words)
				burst_words = copy_words;
			edm = bcm2835_sdhost_read(host, SDEDM);
			if (is_read)
				words = ((edm >> 4) & 0x1f);
			else
				words = SDDATA_FIFO_WORDS - ((edm >> 4) & 0x1f);

			if (words < burst_words) {
				int fsm_state = (edm & SDEDM_FSM_MASK);

				if ((is_read &&
				     (fsm_state != SDEDM_FSM_READDATA &&
				      fsm_state != SDEDM_FSM_READWAIT &&
				      fsm_state != SDEDM_FSM_READCRC)) ||
				    (!is_read &&
				     (fsm_state != SDEDM_FSM_WRITEDATA &&
				      fsm_state != SDEDM_FSM_WRITESTART1 &&
				      fsm_state != SDEDM_FSM_WRITESTART2))) {
					hsts = bcm2835_sdhost_read(host,
								   SDHSTS);
					pr_err("%s: fsm %x, hsts %x\n",
					       mmc_hostname(host->mmc),
					       fsm_state, hsts);
					if (hsts & SDHSTS_ERROR_MASK)
						break;
				}

				if (time_after(jiffies, wait_max)) {
					pr_err("%s: PIO %s timeout - EDM %x\n",
					       is_read ? "read" : "write",
					       mmc_hostname(host->mmc),
					       edm);
					hsts = SDHSTS_REW_TIME_OUT;
					break;
				}
				ndelay((burst_words - words) *
				       host->ns_per_fifo_word);
				continue;
			} else if (words > copy_words) {
				words = copy_words;
			}

			copy_words -= words;

			while (words) {
				if (is_read) {
					*(buf++) = bcm2835_sdhost_read(host,
								       SDDATA);
				} else {
					bcm2835_sdhost_write(host, *(buf++),
							     SDDATA);
				}
				words--;
			}
		}

		if (hsts & SDHSTS_ERROR_MASK)
			break;
	}

	sg_miter_stop(&host->sg_miter);

	local_irq_restore(flags);
}

static void bcm2835_sdhost_transfer_pio(struct bcm2835_host *host)
{
	u32 sdhsts;
	bool is_read;

	is_read = (host->data->flags & MMC_DATA_READ) != 0;
	bcm2835_sdhost_transfer_block_pio(host, is_read);

	sdhsts = bcm2835_sdhost_read(host, SDHSTS);
	if (sdhsts & (SDHSTS_CRC16_ERROR |
		      SDHSTS_CRC7_ERROR |
		      SDHSTS_FIFO_ERROR)) {
		pr_err("%s: %s transfer error - HSTS %x\n",
		       mmc_hostname(host->mmc),
		       is_read ? "read" : "write",
		       sdhsts);
		host->data->error = -EILSEQ;
	} else if ((sdhsts & (SDHSTS_CMD_TIME_OUT |
			      SDHSTS_REW_TIME_OUT))) {
		pr_err("%s: %s timeout error - HSTS %x\n",
		       mmc_hostname(host->mmc),
		       is_read ? "read" : "write",
		       sdhsts);
		host->data->error = -ETIMEDOUT;
	}
}

static void bcm2835_sdhost_prepare_dma(struct bcm2835_host *host,
				       struct mmc_data *data)
{
	int len, dir_data, dir_slave;
	struct dma_async_tx_descriptor *desc = NULL;
	struct dma_chan *dma_chan;

	pr_debug("bcm2835_sdhost_prepare_dma()\n");

	if (data->flags & MMC_DATA_READ) {
		dma_chan = host->dma_chan_rx;
		dir_data = DMA_FROM_DEVICE;
		dir_slave = DMA_DEV_TO_MEM;
	} else {
		dma_chan = host->dma_chan_tx;
		dir_data = DMA_TO_DEVICE;
		dir_slave = DMA_MEM_TO_DEV;
	}

	/* The block doesn't manage the FIFO DREQs properly for
	 * multi-block transfers, so don't attempt to DMA the final
	 * few words.  Unfortunately this requires the final sg entry
	 * to be trimmed.  N.B. This code demands that the overspill
	 * is contained in a single sg entry.
	 */

	host->drain_words = 0;
	if ((data->blocks > 1) && (dir_data == DMA_FROM_DEVICE)) {
		struct scatterlist *sg;
		u32 len;
		int i;

		len = min((u32)(FIFO_READ_THRESHOLD - 1) * 4,
			  (u32)data->blocks * data->blksz);

		for_each_sg(data->sg, sg, data->sg_len, i) {
			if (sg_is_last(sg)) {
				WARN_ON(sg->length < len);
				sg->length -= len;
				host->drain_page = (struct page *)sg->page_link;
				host->drain_offset = sg->offset + sg->length;
			}
		}
		host->drain_words = len / 4;
	}

	len = dma_map_sg(dma_chan->device->dev, data->sg, data->sg_len,
			 dir_data);

	if (len > 0) {
		desc = dmaengine_prep_slave_sg(dma_chan, data->sg,
					       len, dir_slave,
					       DMA_PREP_INTERRUPT |
					       DMA_CTRL_ACK);
	}

	if (desc) {
		desc->callback = bcm2835_sdhost_dma_complete;
		desc->callback_param = host;
		host->dma_desc = desc;
		host->dma_chan = dma_chan;
		host->dma_dir = dir_data;
	}
}

static void bcm2835_sdhost_start_dma(struct bcm2835_host *host)
{
	dmaengine_submit(host->dma_desc);
	dma_async_issue_pending(host->dma_chan);
}

static void bcm2835_sdhost_set_transfer_irqs(struct bcm2835_host *host)
{
	u32 all_irqs = SDHCFG_DATA_IRPT_EN | SDHCFG_BLOCK_IRPT_EN |
		SDHCFG_BUSY_IRPT_EN;

	if (host->dma_desc) {
		host->hcfg = (host->hcfg & ~all_irqs) |
			SDHCFG_BUSY_IRPT_EN;
	} else {
		host->hcfg = (host->hcfg & ~all_irqs) |
			SDHCFG_DATA_IRPT_EN |
			SDHCFG_BUSY_IRPT_EN;
	}

	bcm2835_sdhost_write(host, host->hcfg, SDHCFG);
}

static void bcm2835_sdhost_prepare_data(struct bcm2835_host *host,
					struct mmc_command *cmd)
{
	struct mmc_data *data = cmd->data;

	WARN_ON(host->data);

	host->data = data;
	if (!data)
		return;

	/* Sanity checks */
	WARN_ON(data->blksz * data->blocks > 524288);
	WARN_ON(data->blksz > host->mmc->max_blk_size);
	WARN_ON(data->blocks > 65535);

	host->data_complete = false;
	host->flush_fifo = false;
	host->data->bytes_xfered = 0;

	if (!host->dma_desc) {
		/* Use PIO */
		int flags = SG_MITER_ATOMIC;

		if (data->flags & MMC_DATA_READ)
			flags |= SG_MITER_TO_SG;
		else
			flags |= SG_MITER_FROM_SG;
		sg_miter_start(&host->sg_miter, data->sg, data->sg_len, flags);
		host->blocks = data->blocks;
	}

	bcm2835_sdhost_set_transfer_irqs(host);

	bcm2835_sdhost_write(host, data->blksz, SDHBCT);
	bcm2835_sdhost_write(host, data->blocks, SDHBLC);
}

bool bcm2835_sdhost_send_command(struct bcm2835_host *host,
				 struct mmc_command *cmd)
{
	u32 sdcmd, sdhsts;
	unsigned long timeout;
	int delay;

	WARN_ON(host->cmd);

	if (cmd->data) {
		pr_debug("%s: send_command %d 0x%x (flags 0x%x) - %s %d*%d\n",
			 mmc_hostname(host->mmc),
			 cmd->opcode, cmd->arg, cmd->flags,
			 (cmd->data->flags & MMC_DATA_READ) ?
			 "read" : "write", cmd->data->blocks,
			 cmd->data->blksz);
	} else {
		pr_debug("%s: send_command %d 0x%x (flags 0x%x)\n",
			 mmc_hostname(host->mmc),
			 cmd->opcode, cmd->arg, cmd->flags);
	}

	/* Wait max 100 ms */
	timeout = 10000;

	while (bcm2835_sdhost_read(host, SDCMD) & SDCMD_NEW_FLAG) {
		if (timeout == 0) {
			pr_err("%s: previous command never completed.\n",
			       mmc_hostname(host->mmc));
			bcm2835_sdhost_dumpregs(host);
			cmd->error = -EILSEQ;
			tasklet_schedule(&host->finish_tasklet);
			return false;
		}
		timeout--;
		udelay(10);
	}

	delay = (10000 - timeout) / 100;
	if (delay > host->max_delay) {
		host->max_delay = delay;
		pr_warn("%s: controller hung for %d ms\n",
			mmc_hostname(host->mmc),
			host->max_delay);
	}

	timeout = jiffies;
	if (!cmd->data && cmd->busy_timeout > 9000)
		timeout += DIV_ROUND_UP(cmd->busy_timeout, 1000) * HZ + HZ;
	else
		timeout += 10 * HZ;
	mod_timer(&host->timer, timeout);

	host->cmd = cmd;

	/* Clear any error flags */
	sdhsts = bcm2835_sdhost_read(host, SDHSTS);
	if (sdhsts & SDHSTS_ERROR_MASK)
		bcm2835_sdhost_write(host, sdhsts, SDHSTS);

	if ((cmd->flags & MMC_RSP_136) && (cmd->flags & MMC_RSP_BUSY)) {
		pr_err("%s: unsupported response type!\n",
		       mmc_hostname(host->mmc));
		cmd->error = -EINVAL;
		tasklet_schedule(&host->finish_tasklet);
		return false;
	}

	bcm2835_sdhost_prepare_data(host, cmd);

	bcm2835_sdhost_write(host, cmd->arg, SDARG);

	sdcmd = cmd->opcode & SDCMD_CMD_MASK;

	host->use_busy = false;
	if (!(cmd->flags & MMC_RSP_PRESENT)) {
		sdcmd |= SDCMD_NO_RESPONSE;
	} else {
		if (cmd->flags & MMC_RSP_136)
			sdcmd |= SDCMD_LONG_RESPONSE;
		if (cmd->flags & MMC_RSP_BUSY) {
			sdcmd |= SDCMD_BUSYWAIT;
			host->use_busy = true;
		}
	}

	if (cmd->data) {
		if (cmd->data->flags & MMC_DATA_WRITE)
			sdcmd |= SDCMD_WRITE_CMD;
		if (cmd->data->flags & MMC_DATA_READ)
			sdcmd |= SDCMD_READ_CMD;
	}

	bcm2835_sdhost_write(host, sdcmd | SDCMD_NEW_FLAG, SDCMD);

	return true;
}

static void bcm2835_sdhost_finish_command(struct bcm2835_host *host,
					  unsigned long *irq_flags);

static void bcm2835_sdhost_transfer_complete(struct bcm2835_host *host)
{
	struct mmc_data *data;

	WARN_ON(!host->data_complete);

	data = host->data;
	host->data = NULL;

	pr_debug("transfer_complete(error %d, stop %d)\n",
		 data->error, data->stop ? 1 : 0);

	/* Need to send CMD12 if -
	 * a) open-ended multiblock transfer (no CMD23)
	 * b) error in multiblock transfer
	 */
	if (host->mrq->stop && (data->error || !host->use_sbc)) {
		if (bcm2835_sdhost_send_command(host, host->mrq->stop)) {
			/* No busy, so poll for completion */
			if (!host->use_busy)
				bcm2835_sdhost_finish_command(host, NULL);
		}
	} else {
		bcm2835_sdhost_wait_transfer_complete(host);
		tasklet_schedule(&host->finish_tasklet);
	}
}

static void bcm2835_sdhost_finish_data(struct bcm2835_host *host)
{
	struct mmc_data *data;

	data = host->data;

	pr_debug("finish_data(error %d, stop %d, sbc %d)\n",
		 data->error, data->stop ? 1 : 0,
		 host->mrq->sbc ? 1 : 0);

	host->hcfg &= ~(SDHCFG_DATA_IRPT_EN | SDHCFG_BLOCK_IRPT_EN);
	bcm2835_sdhost_write(host, host->hcfg, SDHCFG);

	data->bytes_xfered = data->error ? 0 : (data->blksz * data->blocks);

	host->data_complete = true;

	if (host->cmd) {
		/* Data managed to finish before the
		 * command completed. Make sure we do
		 * things in the proper order.
		 */
		pr_debug("Finished early - HSTS %x\n",
			 bcm2835_sdhost_read(host, SDHSTS));
	} else {
		bcm2835_sdhost_transfer_complete(host);
	}
}

/* If irq_flags is valid, the caller is in a thread context and is
 * allowed to sleep
 */
static void bcm2835_sdhost_finish_command(struct bcm2835_host *host,
					  unsigned long *irq_flags)
{
	u32 sdcmd;
	u32 retries;

	pr_debug("finish_command(%x)\n", bcm2835_sdhost_read(host, SDCMD));

	/* Poll quickly at first */

	retries = host->cmd_quick_poll_retries;
	if (!retries) {
		/* Work out how many polls take 1us by timing 10us */
		struct timeval start, now;
		int us_diff;

		retries = 1;
		do {
			int i;

			retries *= 2;

			do_gettimeofday(&start);

			for (i = 0; i < retries; i++) {
				cpu_relax();
				sdcmd = bcm2835_sdhost_read(host, SDCMD);
			}

			do_gettimeofday(&now);
			us_diff = (now.tv_sec - start.tv_sec) * 1000000 +
				(now.tv_usec - start.tv_usec);
		} while (us_diff < 10);

		host->cmd_quick_poll_retries =
			((retries * us_diff + 9) * CMD_DALLY_US) / 10 + 1;
		retries = 1; /* We've already waited long enough this time */
	}

	retries = host->cmd_quick_poll_retries;
	for (sdcmd = bcm2835_sdhost_read(host, SDCMD);
	     (sdcmd & SDCMD_NEW_FLAG) && !(sdcmd & SDCMD_FAIL_FLAG) && retries;
	     retries--) {
		cpu_relax();
		sdcmd = bcm2835_sdhost_read(host, SDCMD);
	}

	if (!retries) {
		unsigned long wait_max;

		if (!irq_flags) {
			/* Schedule the work */
			schedule_work(&host->cmd_wait_wq);
			return;
		}

		/* Wait max 100 ms */
		wait_max = jiffies + msecs_to_jiffies(100);
		while (time_before(jiffies, wait_max)) {
			spin_unlock_irqrestore(&host->lock, *irq_flags);
			usleep_range(1, 10);
			spin_lock_irqsave(&host->lock, *irq_flags);
			sdcmd = bcm2835_sdhost_read(host, SDCMD);
			if (!(sdcmd & SDCMD_NEW_FLAG) ||
			    (sdcmd & SDCMD_FAIL_FLAG))
				break;
		}
	}

	/* Check for errors */
	if (sdcmd & SDCMD_NEW_FLAG) {
		pr_err("%s: command never completed.\n",
		       mmc_hostname(host->mmc));
		bcm2835_sdhost_dumpregs(host);
		host->cmd->error = -EIO;
		tasklet_schedule(&host->finish_tasklet);
		return;
	} else if (sdcmd & SDCMD_FAIL_FLAG) {
		u32 sdhsts = bcm2835_sdhost_read(host, SDHSTS);

		/* Clear the errors */
		bcm2835_sdhost_write(host, SDHSTS_ERROR_MASK, SDHSTS);

		if (!(sdhsts & SDHSTS_CRC7_ERROR) ||
		    (host->cmd->opcode != 1)) {
			if (sdhsts & SDHSTS_CMD_TIME_OUT) {
				host->cmd->error = -ETIMEDOUT;
			} else {
				pr_err("%s: unexpected command %d error\n",
				       mmc_hostname(host->mmc),
				       host->cmd->opcode);
				bcm2835_sdhost_dumpregs(host);
				host->cmd->error = -EILSEQ;
			}
			tasklet_schedule(&host->finish_tasklet);
			return;
		}
	}

	if (host->cmd->flags & MMC_RSP_PRESENT) {
		if (host->cmd->flags & MMC_RSP_136) {
			int i;

			for (i = 0; i < 4; i++) {
				host->cmd->resp[3 - i] =
					bcm2835_sdhost_read(host,
							    SDRSP0 + i * 4);
			}

			pr_debug("%s: finish_command %08x %08x %08x %08x\n",
				 mmc_hostname(host->mmc),
				 host->cmd->resp[0], host->cmd->resp[1],
				 host->cmd->resp[2], host->cmd->resp[3]);
		} else {
			host->cmd->resp[0] = bcm2835_sdhost_read(host, SDRSP0);
			pr_debug("%s: finish_command %08x\n",
				 mmc_hostname(host->mmc),
				 host->cmd->resp[0]);
		}
	}

	if (host->cmd == host->mrq->sbc) {
		/* Finished CMD23, now send actual command. */
		host->cmd = NULL;
		if (bcm2835_sdhost_send_command(host, host->mrq->cmd)) {
			if (host->data && host->dma_desc)
				/* DMA transfer starts now, PIO starts
				 * after irq
				 */
				bcm2835_sdhost_start_dma(host);

			if (!host->use_busy)
				bcm2835_sdhost_finish_command(host, NULL);
		}
	} else if (host->cmd == host->mrq->stop) {
		/* Finished CMD12 */
		tasklet_schedule(&host->finish_tasklet);
	} else {
		/* Processed actual command. */
		host->cmd = NULL;
		if (!host->data)
			tasklet_schedule(&host->finish_tasklet);
		else if (host->data_complete)
			bcm2835_sdhost_transfer_complete(host);
	}
}

static void bcm2835_sdhost_timeout(unsigned long data)
{
	struct bcm2835_host *host;
	unsigned long flags;

	host = (struct bcm2835_host *)data;

	spin_lock_irqsave(&host->lock, flags);

	if (host->mrq) {
		pr_err("%s: timeout waiting for hardware interrupt.\n",
		       mmc_hostname(host->mmc));
		bcm2835_sdhost_dumpregs(host);

		if (host->data) {
			host->data->error = -ETIMEDOUT;
			bcm2835_sdhost_finish_data(host);
		} else {
			if (host->cmd)
				host->cmd->error = -ETIMEDOUT;
			else
				host->mrq->cmd->error = -ETIMEDOUT;

			pr_debug("timeout_timer tasklet_schedule\n");
			tasklet_schedule(&host->finish_tasklet);
		}
	}
	spin_unlock_irqrestore(&host->lock, flags);
}

static void bcm2835_sdhost_busy_irq(struct bcm2835_host *host, u32 intmask)
{
	if (!host->cmd) {
		pr_err("%s: got command busy interrupt 0x%08x even though no command operation was in progress.\n",
		       mmc_hostname(host->mmc), (unsigned)intmask);
		bcm2835_sdhost_dumpregs(host);
		return;
	}

	if (!host->use_busy) {
		pr_err("%s: got command busy interrupt 0x%08x even though not expecting one.\n",
		       mmc_hostname(host->mmc), (unsigned)intmask);
		bcm2835_sdhost_dumpregs(host);
		return;
	}
	host->use_busy = false;

	if (intmask & SDHSTS_ERROR_MASK) {
		pr_err("sdhost_busy_irq: intmask %x, data %p\n",
		       intmask, host->mrq->data);
		if (intmask & SDHSTS_CRC7_ERROR) {
			host->cmd->error = -EILSEQ;
		} else if (intmask & (SDHSTS_CRC16_ERROR |
				    SDHSTS_FIFO_ERROR)) {
			if (host->mrq->data)
				host->mrq->data->error = -EILSEQ;
			else
				host->cmd->error = -EILSEQ;
		} else if (intmask & SDHSTS_REW_TIME_OUT) {
			if (host->mrq->data)
				host->mrq->data->error = -ETIMEDOUT;
			else
				host->cmd->error = -ETIMEDOUT;
		} else if (intmask & SDHSTS_CMD_TIME_OUT) {
			host->cmd->error = -ETIMEDOUT;
		}

		bcm2835_sdhost_dumpregs(host);
	} else {
		bcm2835_sdhost_finish_command(host, NULL);
	}
}

static void bcm2835_sdhost_data_irq(struct bcm2835_host *host, u32 intmask)
{
	/* There are no dedicated data/space available interrupt
	 * status bits, so it is necessary to use the single shared
	 * data/space available FIFO status bits. It is therefore not
	 * an error to get here when there is no data transfer in
	 * progress.
	 */
	if (!host->data)
		return;

	if (intmask & (SDHSTS_CRC16_ERROR |
		       SDHSTS_FIFO_ERROR |
		       SDHSTS_REW_TIME_OUT)) {
		if (intmask & (SDHSTS_CRC16_ERROR |
			       SDHSTS_FIFO_ERROR))
			host->data->error = -EILSEQ;
		else
			host->data->error = -ETIMEDOUT;
	}

	if (host->data->error) {
		bcm2835_sdhost_finish_data(host);
	} else if (host->data->flags & MMC_DATA_WRITE) {
		/* Use the block interrupt for writes after the first block */
		host->hcfg &= ~(SDHCFG_DATA_IRPT_EN);
		host->hcfg |= SDHCFG_BLOCK_IRPT_EN;
		bcm2835_sdhost_write(host, host->hcfg, SDHCFG);
		bcm2835_sdhost_transfer_pio(host);
	} else {
		bcm2835_sdhost_transfer_pio(host);
		host->blocks--;
		if ((host->blocks == 0) || host->data->error)
			bcm2835_sdhost_finish_data(host);
	}
}

static void bcm2835_sdhost_block_irq(struct bcm2835_host *host, u32 intmask)
{
	if (!host->data) {
		pr_err("%s: got block interrupt 0x%08x even though no data operation was in progress.\n",
		       mmc_hostname(host->mmc), (unsigned)intmask);
		bcm2835_sdhost_dumpregs(host);
		return;
	}

	if (intmask & (SDHSTS_CRC16_ERROR |
		       SDHSTS_FIFO_ERROR |
		       SDHSTS_REW_TIME_OUT)) {
		if (intmask & (SDHSTS_CRC16_ERROR |
			       SDHSTS_FIFO_ERROR))
			host->data->error = -EILSEQ;
		else
			host->data->error = -ETIMEDOUT;
	}

	if (!host->dma_desc) {
		WARN_ON(!host->blocks);
		if (host->data->error || (--host->blocks == 0))
			bcm2835_sdhost_finish_data(host);
		else
			bcm2835_sdhost_transfer_pio(host);
	} else if (host->data->flags & MMC_DATA_WRITE) {
		bcm2835_sdhost_finish_data(host);
	}
}

static irqreturn_t bcm2835_sdhost_irq(int irq, void *dev_id)
{
	irqreturn_t result = IRQ_NONE;
	struct bcm2835_host *host = dev_id;
	u32 intmask;

	spin_lock(&host->lock);

	intmask = bcm2835_sdhost_read(host, SDHSTS);

	bcm2835_sdhost_write(host,
			     SDHSTS_BUSY_IRPT |
			     SDHSTS_BLOCK_IRPT |
			     SDHSTS_SDIO_IRPT |
			     SDHSTS_DATA_FLAG,
			     SDHSTS);

	if (intmask & SDHSTS_BLOCK_IRPT) {
		bcm2835_sdhost_block_irq(host, intmask);
		result = IRQ_HANDLED;
	}

	if (intmask & SDHSTS_BUSY_IRPT) {
		bcm2835_sdhost_busy_irq(host, intmask);
		result = IRQ_HANDLED;
	}

	/* There is no true data interrupt status bit, so it is
	 * necessary to qualify the data flag with the interrupt
	 * enable bit.
	 */
	if ((intmask & SDHSTS_DATA_FLAG) &&
	    (host->hcfg & SDHCFG_DATA_IRPT_EN)) {
		bcm2835_sdhost_data_irq(host, intmask);
		result = IRQ_HANDLED;
	}

	spin_unlock(&host->lock);

	return result;
}

void bcm2835_sdhost_set_clock(struct bcm2835_host *host, unsigned int clock)
{
	int div = 0; /* Initialized for compiler warning */

	/* The SDCDIV register has 11 bits, and holds (div - 2).  But
	 * in data mode the max is 50MHz wihout a minimum, and only
	 * the bottom 3 bits are used. Since the switch over is
	 * automatic (unless we have marked the card as slow...),
	 * chosen values have to make sense in both modes.  Ident mode
	 * must be 100-400KHz, so can range check the requested
	 * clock. CMD15 must be used to return to data mode, so this
	 * can be monitored.
	 *
	 * clock 250MHz -> 0->125MHz, 1->83.3MHz, 2->62.5MHz, 3->50.0MHz
	 *                 4->41.7MHz, 5->35.7MHz, 6->31.3MHz, 7->27.8MHz
	 *
	 *		 623->400KHz/27.8MHz
	 *		 reset value (507)->491159/50MHz
	 *
	 * BUT, the 3-bit clock divisor in data mode is too small if
	 * the core clock is higher than 250MHz, so instead use the
	 * SLOW_CARD configuration bit to force the use of the ident
	 * clock divisor at all times.
	 */

	host->mmc->actual_clock = 0;

	if (clock < 100000) {
		/* Can't stop the clock, but make it as slow as possible
		 * to show willing
		 */
		host->cdiv = SDCDIV_MAX_CDIV;
		bcm2835_sdhost_write(host, host->cdiv, SDCDIV);
		return;
	}

	div = host->max_clk / clock;
	if (div < 2)
		div = 2;
	if ((host->max_clk / div) > clock)
		div++;
	div -= 2;

	if (div > SDCDIV_MAX_CDIV)
		div = SDCDIV_MAX_CDIV;

	clock = host->max_clk / (div + 2);
	host->mmc->actual_clock = clock;

	/* Calibrate some delays */

	host->ns_per_fifo_word = (1000000000 / clock) *
		((host->mmc->caps & MMC_CAP_4_BIT_DATA) ? 8 : 32);

	host->cdiv = div;
	bcm2835_sdhost_write(host, host->cdiv, SDCDIV);

	/* Set the timeout to 500ms */
	bcm2835_sdhost_write(host, host->mmc->actual_clock / 2, SDTOUT);
}

static void bcm2835_sdhost_request(struct mmc_host *mmc,
				   struct mmc_request *mrq)
{
	struct bcm2835_host *host;
	unsigned long flags;
	u32 edm, fsm;

	host = mmc_priv(mmc);

	/* Reset the error statuses in case this is a retry */
	if (mrq->sbc)
		mrq->sbc->error = 0;
	if (mrq->cmd)
		mrq->cmd->error = 0;
	if (mrq->data)
		mrq->data->error = 0;
	if (mrq->stop)
		mrq->stop->error = 0;

	if (mrq->data && !is_power_of_2(mrq->data->blksz)) {
		pr_err("%s: unsupported block size (%d bytes)\n",
		       mmc_hostname(mmc), mrq->data->blksz);
		mrq->cmd->error = -EINVAL;
		mmc_request_done(mmc, mrq);
		return;
	}

	if (host->use_dma && mrq->data &&
	    (mrq->data->blocks > host->pio_limit))
		bcm2835_sdhost_prepare_dma(host, mrq->data);

	spin_lock_irqsave(&host->lock, flags);

	WARN_ON(host->mrq);
	host->mrq = mrq;

	edm = bcm2835_sdhost_read(host, SDEDM);
	fsm = edm & SDEDM_FSM_MASK;

	if ((fsm != SDEDM_FSM_IDENTMODE) &&
	    (fsm != SDEDM_FSM_DATAMODE)) {
		pr_err("%s: previous command (%d) not complete (EDM %x)\n",
		       mmc_hostname(host->mmc),
		       bcm2835_sdhost_read(host, SDCMD) & SDCMD_CMD_MASK,
		       edm);
		bcm2835_sdhost_dumpregs(host);
		mrq->cmd->error = -EILSEQ;
		tasklet_schedule(&host->finish_tasklet);
		spin_unlock_irqrestore(&host->lock, flags);
		return;
	}

	host->use_sbc = !!mrq->sbc && (host->mrq->data->flags & MMC_DATA_READ);
	if (host->use_sbc) {
		if (bcm2835_sdhost_send_command(host, mrq->sbc)) {
			if (!host->use_busy)
				bcm2835_sdhost_finish_command(host, &flags);
		}
	} else if (bcm2835_sdhost_send_command(host, mrq->cmd)) {
		if (host->data && host->dma_desc) {
			/* DMA transfer starts now, PIO starts after irq */
			bcm2835_sdhost_start_dma(host);
		}

		if (!host->use_busy)
			bcm2835_sdhost_finish_command(host, &flags);
	}

	spin_unlock_irqrestore(&host->lock, flags);
}

static void bcm2835_sdhost_set_ios(struct mmc_host *mmc, struct mmc_ios *ios)
{
	struct bcm2835_host *host = mmc_priv(mmc);
	unsigned long flags;

	spin_lock_irqsave(&host->lock, flags);

	if (!ios->clock || ios->clock != host->clock) {
		bcm2835_sdhost_set_clock(host, ios->clock);
		host->clock = ios->clock;
	}

	/* set bus width */
	host->hcfg &= ~SDHCFG_WIDE_EXT_BUS;
	if (ios->bus_width == MMC_BUS_WIDTH_4)
		host->hcfg |= SDHCFG_WIDE_EXT_BUS;

	host->hcfg |= SDHCFG_WIDE_INT_BUS;

	/* Disable clever clock switching, to cope with fast core clocks */
	host->hcfg |= SDHCFG_SLOW_CARD;

	bcm2835_sdhost_write(host, host->hcfg, SDHCFG);

	spin_unlock_irqrestore(&host->lock, flags);
}

static struct mmc_host_ops bcm2835_sdhost_ops = {
	.request = bcm2835_sdhost_request,
	.set_ios = bcm2835_sdhost_set_ios,
	.hw_reset = bcm2835_sdhost_reset,
};

static void bcm2835_sdhost_cmd_wait_work(struct work_struct *work)
{
	struct bcm2835_host *host;
	unsigned long flags;

	host = container_of(work, struct bcm2835_host, cmd_wait_wq);

	spin_lock_irqsave(&host->lock, flags);

	/* If this tasklet gets rescheduled while running, it will
	 * be run again afterwards but without any active request.
	 */
	if (!host->mrq) {
		spin_unlock_irqrestore(&host->lock, flags);
		return;
	}

	bcm2835_sdhost_finish_command(host, &flags);

	spin_unlock_irqrestore(&host->lock, flags);
}

static void bcm2835_sdhost_tasklet_finish(unsigned long param)
{
	struct bcm2835_host *host;
	unsigned long flags;
	struct mmc_request *mrq;
	struct dma_chan *terminate_chan = NULL;

	host = (struct bcm2835_host *)param;

	spin_lock_irqsave(&host->lock, flags);

	/* If this tasklet gets rescheduled while running, it will
	 * be run again afterwards but without any active request.
	 */
	if (!host->mrq) {
		spin_unlock_irqrestore(&host->lock, flags);
		return;
	}

	del_timer(&host->timer);

	mrq = host->mrq;

	host->mrq = NULL;
	host->cmd = NULL;
	host->data = NULL;

	host->dma_desc = NULL;
	terminate_chan = host->dma_chan;
	host->dma_chan = NULL;

	spin_unlock_irqrestore(&host->lock, flags);

	if (terminate_chan) {
		int err = dmaengine_terminate_all(terminate_chan);

		if (err)
			pr_err("%s: failed to terminate DMA (%d)\n",
			       mmc_hostname(host->mmc), err);
	}

	mmc_request_done(host->mmc, mrq);
}

int bcm2835_sdhost_add_host(struct bcm2835_host *host)
{
	struct mmc_host *mmc;
	struct dma_slave_config cfg;
	char pio_limit_string[20];
	int ret;

	mmc = host->mmc;

	bcm2835_sdhost_reset_internal(host);

	mmc->f_max = host->max_clk;
	mmc->f_min = host->max_clk / SDCDIV_MAX_CDIV;

	mmc->max_busy_timeout = ~0 / (mmc->f_max / 1000);

	pr_debug("f_max %d, f_min %d, max_busy_timeout %d\n",
		 mmc->f_max, mmc->f_min, mmc->max_busy_timeout);

	/* host controller capabilities */
	mmc->caps |=
		MMC_CAP_SD_HIGHSPEED | MMC_CAP_MMC_HIGHSPEED |
		MMC_CAP_NEEDS_POLL | MMC_CAP_HW_RESET | MMC_CAP_ERASE |
		MMC_CAP_CMD23;

	spin_lock_init(&host->lock);

	if (IS_ERR_OR_NULL(host->dma_chan_tx) ||
	    IS_ERR_OR_NULL(host->dma_chan_rx)) {
		pr_err("%s: unable to initialise DMA channels. Falling back to PIO\n",
		       mmc_hostname(mmc));
		host->use_dma = false;
	} else {
		host->use_dma = true;

		cfg.src_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
		cfg.dst_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
		cfg.slave_id = 13;		/* DREQ channel */

		cfg.direction = DMA_MEM_TO_DEV;
		cfg.src_addr = 0;
		cfg.dst_addr = host->phys_addr + SDDATA;
		ret = dmaengine_slave_config(host->dma_chan_tx, &cfg);
		if (ret)
			host->use_dma = false;

		cfg.direction = DMA_DEV_TO_MEM;
		cfg.src_addr = host->phys_addr + SDDATA;
		cfg.dst_addr = 0;
		ret = dmaengine_slave_config(host->dma_chan_rx, &cfg);
		if (ret)
			host->use_dma = false;
	}

	mmc->max_segs = 128;
	mmc->max_req_size = 524288;
	mmc->max_seg_size = mmc->max_req_size;
	mmc->max_blk_size = 512;
	mmc->max_blk_count =  65535;

	/* report supported voltage ranges */
	mmc->ocr_avail = MMC_VDD_32_33 | MMC_VDD_33_34;

	tasklet_init(&host->finish_tasklet,
		     bcm2835_sdhost_tasklet_finish, (unsigned long)host);

	INIT_WORK(&host->cmd_wait_wq, bcm2835_sdhost_cmd_wait_work);

	setup_timer(&host->timer, bcm2835_sdhost_timeout,
		    (unsigned long)host);

	bcm2835_sdhost_init(host, 0);

	ret = request_irq(host->irq, bcm2835_sdhost_irq, 0 /*IRQF_SHARED*/,
			  mmc_hostname(mmc), host);
	if (ret) {
		pr_err("%s: failed to request IRQ %d: %d\n",
		       mmc_hostname(mmc), host->irq, ret);
		goto untasklet;
	}

	mmc_add_host(mmc);

	pio_limit_string[0] = '\0';
	if (host->use_dma && (host->pio_limit > 0))
		sprintf(pio_limit_string, " (>%d)", host->pio_limit);
	pr_info("%s: loaded - DMA %s%s\n",
		mmc_hostname(mmc),
		host->use_dma ? "enabled" : "disabled",
		pio_limit_string);

	return 0;

untasklet:
	tasklet_kill(&host->finish_tasklet);

	return ret;
}

static int bcm2835_sdhost_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct clk *clk;
	struct resource *iomem;
	struct bcm2835_host *host;
	struct mmc_host *mmc;
	int ret;

	pr_debug("bcm2835_sdhost_probe\n");
	mmc = mmc_alloc_host(sizeof(*host), dev);
	if (!mmc)
		return -ENOMEM;

	mmc->ops = &bcm2835_sdhost_ops;
	host = mmc_priv(mmc);
	host->mmc = mmc;
	host->cmd_quick_poll_retries = 0;
	host->pio_timeout = msecs_to_jiffies(500);
	host->pio_limit = 1;
	host->max_delay = 1; /* Warn if over 1ms */
	spin_lock_init(&host->lock);

	iomem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	host->ioaddr = devm_ioremap_resource(dev, iomem);
	if (IS_ERR(host->ioaddr)) {
		ret = PTR_ERR(host->ioaddr);
		goto err;
	}

	/* Parse OF address directly to get the physical address for
	 * DMA to our registers.
	 */
	host->phys_addr = be32_to_cpup(of_get_address(pdev->dev.of_node, 0,
						      NULL, NULL));

	pr_debug(" - ioaddr %lx, iomem->start %lx, phys_addr %lx\n",
		 (unsigned long)host->ioaddr,
		 (unsigned long)iomem->start,
		 (unsigned long)host->phys_addr);

	host->dma_chan = NULL;
	host->dma_desc = NULL;

	host->dma_chan_tx = dma_request_slave_channel(dev, "tx");
	host->dma_chan_rx = dma_request_slave_channel(dev, "rx");

	clk = devm_clk_get(dev, NULL);
	if (IS_ERR(clk)) {
		ret = PTR_ERR(clk);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "could not get clk: %d\n", ret);
		goto err;
	}

	host->max_clk = clk_get_rate(clk);

	host->irq = platform_get_irq(pdev, 0);
	if (host->irq <= 0) {
		dev_err(dev, "get IRQ failed\n");
		ret = -EINVAL;
		goto err;
	}

	pr_debug(" - max_clk %lx, irq %d\n",
		 (unsigned long)host->max_clk,
		 (int)host->irq);

	mmc_of_parse(mmc);

	ret = bcm2835_sdhost_add_host(host);
	if (ret)
		goto err;

	platform_set_drvdata(pdev, host);

	pr_debug("bcm2835_sdhost_probe -> OK\n");

	return 0;

err:
	pr_debug("bcm2835_sdhost_probe -> err %d\n", ret);
	mmc_free_host(mmc);

	return ret;
}

static int bcm2835_sdhost_remove(struct platform_device *pdev)
{
	struct bcm2835_host *host = platform_get_drvdata(pdev);

	pr_debug("bcm2835_sdhost_remove\n");

	mmc_remove_host(host->mmc);

	bcm2835_sdhost_set_power(host, false);

	free_irq(host->irq, host);

	del_timer_sync(&host->timer);

	tasklet_kill(&host->finish_tasklet);

	mmc_free_host(host->mmc);
	platform_set_drvdata(pdev, NULL);

	pr_debug("bcm2835_sdhost_remove - OK\n");
	return 0;
}

static const struct of_device_id bcm2835_sdhost_match[] = {
	{ .compatible = "brcm,bcm2835-sdhost" },
	{ }
};
MODULE_DEVICE_TABLE(of, bcm2835_sdhost_match);

static struct platform_driver bcm2835_sdhost_driver = {
	.probe      = bcm2835_sdhost_probe,
	.remove     = bcm2835_sdhost_remove,
	.driver     = {
		.name		= "sdhost-bcm2835",
		.of_match_table	= bcm2835_sdhost_match,
	},
};
module_platform_driver(bcm2835_sdhost_driver);

MODULE_ALIAS("platform:sdhost-bcm2835");
MODULE_DESCRIPTION("BCM2835 SDHost driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Phil Elwell");
